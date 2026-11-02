#include "raucmanager.h"

#include <systemd/sd-bus.h>
#include <unistd.h>
#include <cstring>
#include <system_error>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include "libaktualizr/packagemanagerfactory.h"

#include "logging/logging.h"
#include "storage/invstorage.h"
#include "utilities/utils.h"

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
AUTO_REGISTER_PACKAGE_MANAGER(PACKAGE_MANAGER_RAUC, RaucManager);

static constexpr const char *kPath = "/";
static constexpr const char *kInterface = "de.pengutronix.rauc.Installer";
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
}  // namespace

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

std::string RaucManager::primarySlot() const {
  BusError error;
  sd_bus_message *reply = nullptr;
  int r = sd_bus_call_method(bus(), service_, kPath, kInterface, "GetPrimary", &error.error, &reply, "");
  const std::unique_ptr<sd_bus_message, MessageDeleter> reply_guard{reply};
  const char *slot = nullptr;
  if (r >= 0) {
    r = sd_bus_message_read(reply, "s", &slot);
  }
  if (r < 0) {
    throw std::runtime_error("Could not get the RAUC primary slot: " + error.message(r));
  }
  return slot;
}

// GetSlotStatus returns a(sa{sv}): the slot names with their status. The
// booted slot has "state" set to "booted".
std::string RaucManager::bootedSlot() const {
  BusError error;
  sd_bus_message *reply = nullptr;
  int r = sd_bus_call_method(bus(), service_, kPath, kInterface, "GetSlotStatus", &error.error, &reply, "");
  const std::unique_ptr<sd_bus_message, MessageDeleter> reply_guard{reply};
  std::string booted;
  if (r >= 0) {
    r = sd_bus_message_enter_container(reply, 'a', "(sa{sv})");
  }
  while (r >= 0 && booted.empty()) {
    r = sd_bus_message_enter_container(reply, 'r', "sa{sv}");
    if (r <= 0) {
      break;
    }
    const char *slot = nullptr;
    r = sd_bus_message_read(reply, "s", &slot);
    if (r >= 0) {
      r = sd_bus_message_enter_container(reply, 'a', "{sv}");
    }
    while (r >= 0 && (r = sd_bus_message_enter_container(reply, 'e', "sv")) > 0) {
      const char *key = nullptr;
      r = sd_bus_message_read(reply, "s", &key);
      if (r >= 0 && std::strcmp(key, "state") == 0) {
        const char *state = nullptr;
        r = sd_bus_message_read(reply, "v", "s", &state);
        if (r >= 0 && std::strcmp(state, "booted") == 0) {
          booted = slot;
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
  }
  if (r < 0) {
    throw std::runtime_error("Could not get the RAUC slot status: " + error.message(r));
  }
  return booted;
}

Json::Value RaucManager::getInstalledPackages() const {
  // Currently not implemented
  return Json::Value(Json::arrayValue);
}

Uptane::Target RaucManager::getCurrent() const {
  boost::optional<Uptane::Target> current_version;
  storage_->loadPrimaryInstalledVersions(&current_version, nullptr, nullptr);

  if (!!current_version) {
    return *current_version;
  }

  return Uptane::Target::Unknown();
}

data::InstallationResult RaucManager::install(const Uptane::Target &target) const {
  auto bundle = checkTargetFile(target);
  if (!bundle) {
    return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed,
                                    "Bundle not found for target " + target.filename());
  }

  std::lock_guard<std::mutex> guard(mutex_);
  LOG_INFO << "Installing " << target.filename() << " with RAUC...";
  try {
    // Subscribe before starting the installation, so that the signal cannot be missed.
    boost::optional<int32_t> result;
    sd_bus_slot *slot = nullptr;
    int r = sd_bus_match_signal(bus(), &slot, service_, kPath, kInterface, "Completed", onCompleted, &result);
    const std::unique_ptr<sd_bus_slot, SlotDeleter> slot_guard{slot};
    if (r < 0) {
      throw std::runtime_error("Could not subscribe to RAUC signals: " + std::system_category().message(-r));
    }

    BusError error;
    r = sd_bus_call_method(bus(), service_, kPath, kInterface, "InstallBundle", &error.error, nullptr, "sa{sv}",
                           bundle->second.c_str(), 0);
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
      const std::string last_error = property("LastError");
      LOG_ERROR << "RAUC installation failed: " << last_error;
      return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, last_error);
    }

    // RAUC makes the slot it has just written the primary one.
    Utils::writeFile(slotFile(), primarySlot());
  } catch (const std::exception &e) {
    LOG_ERROR << e.what();
    return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, e.what());
  }

  bootloader_->rebootFlagSet();
  sync();
  return data::InstallationResult(data::ResultCode::Numeric::kNeedCompletion, "Application successful, need reboot");
}

void RaucManager::completeInstall() const {
  LOG_INFO << "About to reboot the system in order to apply pending updates...";
  bootloader_->reboot();
}

data::InstallationResult RaucManager::finalizeInstall(const Uptane::Target & /* target */) {
  if (!bootloader_->rebootDetected()) {
    return data::InstallationResult(data::ResultCode::Numeric::kNeedCompletion,
                                    "Reboot is required for the pending update application");
  }

  const std::string expected = boost::filesystem::exists(slotFile()) ? Utils::readFile(slotFile()) : "";
  std::string booted;
  try {
    std::lock_guard<std::mutex> guard(mutex_);
    booted = bootedSlot();
  } catch (const std::exception &e) {
    LOG_ERROR << e.what();
  }

  data::InstallationResult install_result =
      data::InstallationResult(data::ResultCode::Numeric::kOk, "Successfully booted on new version");

  if (expected.empty() || booted != expected) {
    LOG_ERROR << "Expected to boot slot " << expected << " but found " << booted
              << ". The system may have been rolled back.";
    install_result = data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Wrong slot booted");
  }

  bootloader_->setBootOK();
  boost::filesystem::remove(slotFile());
  bootloader_->rebootFlagClear();
  return install_result;
}

PackageManagerInterface::FetchResult RaucManager::fetchTarget(const Uptane::Target &target, Uptane::Fetcher &fetcher,
                                                              const KeyManager &keys,
                                                              const FetcherProgressCb &progress_cb,
                                                              const api::FlowControlToken *token) {
  if (target.IsOstree()) {
    const std::string error = "Cannot download OSTree target " + target.filename() + " with the RAUC package manager!";
    LOG_ERROR << error;
    return {false, error};
  }

  return PackageManagerInterface::fetchTarget(target, fetcher, keys, progress_cb, token);
}
