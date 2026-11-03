#include "raucmanager.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <systemd/sd-bus.h>
#include <unistd.h>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <system_error>

#include <boost/optional.hpp>

#include "libaktualizr/packagemanagerfactory.h"

#include "http/httpinterface.h"
#include "logging/logging.h"
#include "storage/invstorage.h"
#include "uptane/fetcher.h"
#include "uptane/tuf.h"
#include "utilities/utils.h"

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
AUTO_REGISTER_PACKAGE_MANAGER(PACKAGE_MANAGER_RAUC, RaucManager);

static constexpr const char *kPath = "/";
static constexpr const char *kInterface = "de.pengutronix.rauc.Installer";
static constexpr const char *kKeyringDir = "/run/rauc/keyring.d";
// How long to wait for the Completed signal before checking that RAUC is still installing.
static constexpr uint64_t kInstallPollUsec = uint64_t{10} * 1000 * 1000;

namespace {
struct BusError {
  BusError() = default;
  BusError(const BusError &) = delete;
  BusError(BusError &&) = delete;
  BusError &operator=(const BusError &) = delete;
  BusError &operator=(BusError &&) = delete;
  ~BusError() { sd_bus_error_free(&error); }
  std::string message(int r) const {
    return error.message != nullptr ? error.message : std::system_category().message(-r);
  }

  sd_bus_error error = SD_BUS_ERROR_NULL;
};

struct MessageDeleter {
  void operator()(sd_bus_message *m) const { sd_bus_message_unref(m); }
};
struct SlotDeleter {
  void operator()(sd_bus_slot *s) const { sd_bus_slot_unref(s); }
};

// Certificates put in RAUC's keyring directory for one installation, and removed
// afterwards. RAUC reads the directory at every installation, looking
// certificates up by their subject hash.
class Keyring {
 public:
  explicit Keyring(boost::filesystem::path dir) : dir_{std::move(dir)} {}
  ~Keyring() {
    for (const auto &file : files_) {
      boost::system::error_code ec;
      boost::filesystem::remove(file, ec);
    }
  }
  Keyring(const Keyring &) = delete;
  Keyring(Keyring &&) = delete;
  Keyring &operator=(const Keyring &) = delete;
  Keyring &operator=(Keyring &&) = delete;

  void add(const std::string &pem) {
    boost::filesystem::create_directories(dir_);
    StructGuard<BIO> in(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_vfree);
    std::map<unsigned long, int> count;  // NOLINT(google-runtime-int)
    while (true) {
      StructGuard<X509> cert(PEM_read_bio_X509(in.get(), nullptr, nullptr, nullptr), X509_free);
      if (!cert) {
        break;
      }
      StructGuard<BIO> out(BIO_new(BIO_s_mem()), BIO_vfree);
      char *data = nullptr;
      if (PEM_write_bio_X509(out.get(), cert.get()) == 0) {
        throw std::runtime_error("Could not write a RAUC keyring certificate");
      }
      const auto size = static_cast<size_t>(BIO_get_mem_data(out.get(), &data));
      const auto hash = X509_subject_name_hash(cert.get());
      std::ostringstream name;
      name << std::hex << std::setw(8) << std::setfill('0') << hash << '.' << std::dec << count[hash]++;
      files_.push_back(dir_ / name.str());
      Utils::writeFile(files_.back(), data, size);
    }
    ERR_clear_error();  // the end of the PEM data
    if (count.empty()) {
      throw std::runtime_error("The RAUC keyring in the target metadata has no certificate");
    }
  }

 private:
  boost::filesystem::path dir_;
  std::vector<boost::filesystem::path> files_;
};
}  // namespace

static std::string manifestHash(const Uptane::Target &target) {
  return target.custom_data()["rauc"]["manifest-hash"].asString();
}

static int onCompleted(sd_bus_message *m, void *userdata, sd_bus_error * /* ret_error */) {
  int32_t result = -1;
  sd_bus_message_read(m, "i", &result);
  *static_cast<boost::optional<int32_t> *>(userdata) = result;
  return 0;
}

void RaucManager::BusDeleter::operator()(sd_bus *bus) const { sd_bus_flush_close_unref(bus); }

RaucManager::RaucManager(const PackageConfig &pconfig, const BootloaderConfig &bconfig,
                         const std::shared_ptr<INvStorage> &storage, const std::shared_ptr<HttpInterface> &http,
                         sd_bus *bus, const char *service)
    : PackageManagerInterface(pconfig, bconfig, storage, http),
      keyring_dir_{pconfig.extra.count("rauc_keyring_dir") != 0 ? pconfig.extra.at("rauc_keyring_dir") : kKeyringDir},
      bootloader_{new Bootloader(bconfig, *storage_)},
      service_{service},
      bus_{bus != nullptr ? sd_bus_ref(bus) : nullptr} {}

sd_bus *RaucManager::bus() const {
  if (!bus_) {
    sd_bus *system_bus = nullptr;
    const int r = sd_bus_open_system(&system_bus);
    if (r < 0) {
      throw std::runtime_error("Could not connect to the system D-Bus: " + std::system_category().message(-r));
    }
    bus_.reset(system_bus);
  }
  return bus_.get();
}

std::string RaucManager::property(const char *name) const {
  BusError error;
  char *value = nullptr;
  const int r = sd_bus_get_property_string(bus(), service_, kPath, kInterface, name, &error.error, &value);
  if (r < 0) {
    throw std::runtime_error(std::string("Could not read RAUC ") + name + ": " + error.message(r));
  }
  std::string result{value};
  free(value);  // NOLINT(cppcoreguidelines-no-malloc,hicpp-no-malloc)
  return result;
}

// The string fields of the booted slot's status. GetSlotStatus returns
// a(sa{sv}): every slot's name and status, where the booted slot has "state"
// set to "booted".
std::map<std::string, std::string> RaucManager::bootedSlot() const {
  BusError error;
  sd_bus_message *reply = nullptr;
  int r = sd_bus_call_method(bus(), service_, kPath, kInterface, "GetSlotStatus", &error.error, &reply, "");
  const std::unique_ptr<sd_bus_message, MessageDeleter> reply_guard{reply};
  std::map<std::string, std::string> booted;
  if (r >= 0) {
    r = sd_bus_message_enter_container(reply, 'a', "(sa{sv})");
  }
  while (r >= 0 && booted.empty()) {
    r = sd_bus_message_enter_container(reply, 'r', "sa{sv}");
    if (r <= 0) {
      break;
    }
    std::map<std::string, std::string> status;
    r = sd_bus_message_skip(reply, "s");
    if (r >= 0) {
      r = sd_bus_message_enter_container(reply, 'a', "{sv}");
    }
    while (r >= 0 && (r = sd_bus_message_enter_container(reply, 'e', "sv")) > 0) {
      const char *key = nullptr;
      const char *contents = nullptr;
      r = sd_bus_message_read(reply, "s", &key);
      if (r >= 0) {
        r = sd_bus_message_peek_type(reply, nullptr, &contents);
      }
      if (r >= 0 && contents != nullptr && std::strcmp(contents, "s") == 0) {
        const char *value = nullptr;
        r = sd_bus_message_read(reply, "v", "s", &value);
        if (r >= 0) {
          status[key] = value;
        }
      } else if (r >= 0) {
        r = sd_bus_message_skip(reply, "v");
      }
      if (r >= 0) {
        r = sd_bus_message_exit_container(reply);
      }
    }
    if (r >= 0) {
      r = sd_bus_message_exit_container(reply);
    }
    if (r >= 0) {
      r = sd_bus_message_exit_container(reply);
    }
    if (status["state"] == "booted") {
      booted = std::move(status);
    }
  }
  if (r < 0) {
    throw std::runtime_error("Could not get the RAUC slot status: " + error.message(r));
  }
  return booted;
}

// Manifest hash of the bundle in the booted slot, empty if unknown (e.g. a
// slot RAUC never wrote, as on a freshly flashed device).
std::string RaucManager::bootedHash() const {
  try {
    std::lock_guard<std::mutex> guard(mutex_);
    return bootedSlot()["bundle.hash"];
  } catch (const std::exception &e) {
    LOG_ERROR << e.what();
    return "";
  }
}

Json::Value RaucManager::getInstalledPackages() const {
  // Currently not implemented
  return Json::Value(Json::arrayValue);
}

Uptane::Target RaucManager::getCurrent() const {
  boost::optional<Uptane::Target> current_version;
  storage_->loadPrimaryInstalledVersions(&current_version, nullptr, nullptr);

  const std::string booted_hash = bootedHash();
  if (booted_hash.empty() || (!!current_version && manifestHash(*current_version) == booted_hash)) {
    return !!current_version ? *current_version : Uptane::Target::Unknown();
  }

  // The booted slot is not the version in storage, e.g. after a power cut
  // between the installation and aktualizr recording it. Look the booted
  // bundle up in the Image repo Targets metadata.
  LOG_WARNING << "Current version in storage does not match the booted RAUC slot";
  for (const auto &target : imageTargets()) {
    if (manifestHash(target) == booted_hash) {
      return target;
    }
  }
  return Uptane::Target::Unknown();
}

std::vector<Uptane::Target> RaucManager::imageTargets() const {
  std::string targets;
  if (!storage_->loadNonRoot(&targets, Uptane::RepositoryType::Image(), Uptane::Role::Targets())) {
    return {};
  }
  return Uptane::Targets(Utils::parseJSON(targets)).targets;
}

// The manifest hash is all that binds a streamed bundle to the Uptane metadata,
// so take it, and the keyring, from the Image repo: the Director's custom
// metadata wins when the two are merged.
Json::Value RaucManager::imageRaucMetadata(const Uptane::Target &target) const {
  for (const auto &image_target : imageTargets()) {
    if (image_target.MatchTarget(target)) {
      return image_target.custom_data()["rauc"];
    }
  }
  return Json::Value();
}

// The repository redirects to a pre-signed URL. Resolve it with aktualizr's TLS
// client certificate: the pre-signed URL needs none, so RAUC's unprivileged
// streaming helper can read it.
std::string RaucManager::bundleUrl(const Uptane::Target &target) const {
  std::string url = target.uri();
  if (url.empty()) {
    url = repo_server_ + "/targets/" + Utils::urlEncode(target.filename());
  }
  const std::string resolved = http_->getEffectiveUrl(url);
  return resolved.empty() ? url : resolved;
}

data::InstallationResult RaucManager::install(const Uptane::Target &target) const {
  // aktualizr flags a trial boot (updateNotify) before installing. RAUC arms the
  // bootloader only once the slot is written, so on failure clear the flag again.
  // Pre-signed URLs are credentials and must not reach the report.
  const auto failed = [this](const std::string &error) {
    const std::string description = Utils::redactUrlQueryStrings(error);
    LOG_ERROR << "RAUC installation failed: " << description;
    bootloader_->setBootOK();
    return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, description);
  };

  const Json::Value rauc = imageRaucMetadata(target);
  const std::string manifest_hash = rauc["manifest-hash"].asString();
  if (manifest_hash.empty()) {
    return failed("Target " + target.filename() + " has no RAUC manifest hash in the Image repo metadata");
  }

  // After a power cut between RAUC arming the new slot and aktualizr recording
  // the pending update, the device boots the target without knowing it.
  if (bootedHash() == manifest_hash) {
    LOG_INFO << target.filename() << " is already running";
    bootloader_->setBootOK();
    return data::InstallationResult(data::ResultCode::Numeric::kOk, "Target is already running");
  }

  std::string bundle;
  if (!repo_server_.empty()) {
    bundle = bundleUrl(target);
  } else if (auto file = checkTargetFile(target)) {
    bundle = file->second;
  } else {
    return failed("Bundle not found for target " + target.filename());
  }

  std::lock_guard<std::mutex> guard(mutex_);
  LOG_INFO << "Installing " << target.filename() << " with RAUC from " << Utils::redactUrlQueryStrings(bundle) << "...";
  try {
    Keyring keyring(keyring_dir_);
    if (rauc.isMember("keyring")) {
      keyring.add(rauc["keyring"].asString());
    }

    // Subscribe before starting the installation, so that the signal cannot be missed.
    boost::optional<int32_t> result;
    sd_bus_slot *slot = nullptr;
    int r = sd_bus_match_signal(bus(), &slot, service_, kPath, kInterface, "Completed", onCompleted, &result);
    const std::unique_ptr<sd_bus_slot, SlotDeleter> slot_guard{slot};
    if (r < 0) {
      throw std::runtime_error("Could not subscribe to RAUC signals: " + std::system_category().message(-r));
    }

    // RAUC refuses a bundle whose manifest is not the one the target describes.
    BusError error;
    r = sd_bus_call_method(bus(), service_, kPath, kInterface, "InstallBundle", &error.error, nullptr, "sa{sv}",
                           bundle.c_str(), 1, "require-manifest-hash", "s", manifest_hash.c_str());
    if (r < 0) {
      throw std::runtime_error("RAUC did not start the installation: " + error.message(r));
    }

    while (!result) {
      r = sd_bus_process(bus(), nullptr);
      if (r > 0) {
        continue;
      }
      if (r == 0) {
        r = sd_bus_wait(bus(), kInstallPollUsec);
      }
      if (r < 0) {
        throw std::runtime_error("Lost the connection to RAUC: " + std::system_category().message(-r));
      }
      // If RAUC stopped or restarted, Completed never comes.
      if (r == 0 && property("Operation") != "installing") {
        while (sd_bus_process(bus(), nullptr) > 0) {
        }
        if (!result) {
          throw std::runtime_error("RAUC stopped installing without reporting a result");
        }
      }
    }

    if (*result != 0) {
      return failed(property("LastError"));
    }
  } catch (const std::exception &e) {
    return failed(e.what());
  }

  bootloader_->rebootFlagSet();
  sync();
  return data::InstallationResult(data::ResultCode::Numeric::kNeedCompletion, "Application successful, need reboot");
}

void RaucManager::completeInstall() const {
  LOG_INFO << "About to reboot the system in order to apply pending updates...";
  bootloader_->reboot();
}

data::InstallationResult RaucManager::finalizeInstall(const Uptane::Target &target) {
  if (!bootloader_->rebootDetected()) {
    return data::InstallationResult(data::ResultCode::Numeric::kNeedCompletion,
                                    "Reboot is required for the pending update application");
  }

  const std::string expected = manifestHash(target);
  const std::string booted = bootedHash();

  data::InstallationResult install_result =
      data::InstallationResult(data::ResultCode::Numeric::kOk, "Successfully booted on new version");

  if (expected.empty() || booted != expected) {
    LOG_ERROR << "Expected to boot a bundle with manifest hash " << expected << " but found " << booted
              << ". The system may have been rolled back.";
    install_result = data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Wrong version booted");
  }

  bootloader_->setBootOK();
  bootloader_->rebootFlagClear();
  return install_result;
}

PackageManagerInterface::FetchResult RaucManager::fetchTarget(const Uptane::Target &target, Uptane::Fetcher &fetcher,
                                                              const KeyManager & /* keys */,
                                                              const FetcherProgressCb & /* progress_cb */,
                                                              const api::FlowControlToken * /* token */) {
  if (target.IsOstree()) {
    const std::string error = "Cannot download OSTree target " + target.filename() + " with the RAUC package manager!";
    LOG_ERROR << error;
    return {false, error};
  }

  // Nothing to download: RAUC streams the bundle while installing it.
  repo_server_ = fetcher.getRepoServer();
  return {true, ""};
}

#ifdef BUILD_OFFLINE_UPDATES
PackageManagerInterface::FetchResult RaucManager::fetchTargetOffUpd(const Uptane::Target &target,
                                                                    const Uptane::OfflineUpdateFetcher &fetcher,
                                                                    const KeyManager &keys,
                                                                    const FetcherProgressCb &progress_cb,
                                                                    const api::FlowControlToken *token) {
  repo_server_.clear();
  return PackageManagerInterface::fetchTargetOffUpd(target, fetcher, keys, progress_cb, token);
}
#endif

// RAUC checks a streamed bundle against its manifest hash.
TargetStatus RaucManager::verifyTarget(const Uptane::Target &target) const {
  if (!repo_server_.empty()) {
    return TargetStatus::kGood;
  }
  return PackageManagerInterface::verifyTarget(target);
}
