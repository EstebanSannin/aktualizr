#include <gtest/gtest.h>

#include <sys/socket.h>
#include <systemd/sd-bus.h>
#include <array>
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <boost/filesystem.hpp>

#include "libaktualizr/config.h"
#include "package_manager/raucmanager.h"
#include "storage/invstorage.h"
#include "utilities/utils.h"

// Fake RAUC service. It serves the Installer interface on one end of a socket
// pair, from its own thread; RaucManager talks to it through the other end, so
// no D-Bus daemon is needed.
class FakeRauc {
 public:
  FakeRauc() {
    std::array<int, 2> fds{};
    EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.data()), 0);
    sd_id128_t id;
    sd_id128_randomize(&id);
    sd_bus_new(&server_);
    sd_bus_set_fd(server_, fds[0], fds[0]);
    sd_bus_set_server(server_, 1, id);
    sd_bus_add_object_vtable(server_, nullptr, "/", "de.pengutronix.rauc.Installer", kVtable, this);
    sd_bus_start(server_);
    sd_bus_new(&client_);
    sd_bus_set_fd(client_, fds[1], fds[1]);
    sd_bus_start(client_);
    thread_ = std::thread([this] {
      while (running_) {
        if (sd_bus_process(server_, nullptr) == 0) {
          sd_bus_wait(server_, 100 * 1000);
        }
      }
    });
  }
  FakeRauc(const FakeRauc &) = delete;
  FakeRauc(FakeRauc &&) = delete;
  FakeRauc &operator=(const FakeRauc &) = delete;
  FakeRauc &operator=(FakeRauc &&) = delete;
  ~FakeRauc() {
    running_ = false;
    thread_.join();
    sd_bus_flush_close_unref(client_);
    sd_bus_flush_close_unref(server_);
  }

  sd_bus *client() { return client_; }

  // The booted slot, and the manifest hash of the bundle last written to a slot
  // (empty for a slot RAUC never wrote).
  void setSlot(const std::string &booted, const std::string &hash) {
    std::lock_guard<std::mutex> guard(mutex_);
    booted_ = booted;
    hashes_[booted] = hash;
  }
  // Manifest hash of the bundle that InstallBundle is given.
  void setBundleHash(const std::string &hash) {
    std::lock_guard<std::mutex> guard(mutex_);
    bundle_hash_ = hash;
  }
  void setBusy() {
    std::lock_guard<std::mutex> guard(mutex_);
    busy_ = true;
  }
  // The bundle and required manifest hash InstallBundle was called with.
  std::pair<std::string, std::string> installed() {
    std::lock_guard<std::mutex> guard(mutex_);
    return {bundle_, required_hash_};
  }

 private:
  static int installBundle(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
    auto *self = static_cast<FakeRauc *>(userdata);
    const char *source = nullptr;
    const char *key = nullptr;
    const char *required_hash = nullptr;
    int r = sd_bus_message_read(m, "sa{sv}", &source, 1, &key, "s", &required_hash);
    if (r < 0) {
      return r;
    }
    if (std::string(key) != "require-manifest-hash") {
      return sd_bus_error_set(ret_error, SD_BUS_ERROR_INVALID_ARGS, "Unexpected argument");
    }
    std::lock_guard<std::mutex> guard(self->mutex_);
    if (self->busy_) {
      return sd_bus_error_set(ret_error, SD_BUS_ERROR_FAILED, "Already processing a different method");
    }
    self->bundle_ = source;
    self->required_hash_ = required_hash;
    self->last_error_ = self->required_hash_ == self->bundle_hash_ ? "" : "Manifest hash mismatch";
    r = sd_bus_reply_method_return(m, nullptr);
    if (r < 0) {
      return r;
    }
    const int32_t result = self->last_error_.empty() ? 0 : 1;
    return sd_bus_emit_signal(sd_bus_message_get_bus(m), "/", "de.pengutronix.rauc.Installer", "Completed", "i",
                              result);
  }

  static int getSlotStatus(sd_bus_message *m, void *userdata, sd_bus_error * /* ret_error */) {
    auto *self = static_cast<FakeRauc *>(userdata);
    std::lock_guard<std::mutex> guard(self->mutex_);
    sd_bus_message *reply = nullptr;
    int r = sd_bus_message_new_method_return(m, &reply);
    if (r >= 0) {
      r = sd_bus_message_open_container(reply, 'a', "(sa{sv})");
    }
    for (const char *slot : {"rootfs.0", "rootfs.1"}) {
      const char *state = slot == self->booted_ ? "booted" : "inactive";
      const std::string &hash = self->hashes_[slot];
      if (r >= 0) {
        r = sd_bus_message_open_container(reply, 'r', "sa{sv}");
      }
      if (r >= 0) {
        r = sd_bus_message_append(reply, "s", slot);
      }
      if (r >= 0) {
        r = sd_bus_message_open_container(reply, 'a', "{sv}");
      }
      if (r >= 0) {
        r = sd_bus_message_append(reply, "{sv}{sv}", "installed.count", "u", 1U, "state", "s", state);
      }
      // Only a slot RAUC wrote has a bundle hash.
      if (r >= 0 && !hash.empty()) {
        r = sd_bus_message_append(reply, "{sv}", "bundle.hash", "s", hash.c_str());
      }
      if (r >= 0) {
        r = sd_bus_message_close_container(reply);
      }
      if (r >= 0) {
        r = sd_bus_message_close_container(reply);
      }
    }
    if (r >= 0) {
      r = sd_bus_message_close_container(reply);
    }
    if (r >= 0) {
      r = sd_bus_send(nullptr, reply, nullptr);
    }
    sd_bus_message_unref(reply);
    return r;
  }

  static int getString(sd_bus * /* bus */, const char * /* path */, const char * /* interface */, const char *property,
                       sd_bus_message *reply, void *userdata, sd_bus_error * /* ret_error */) {
    auto *self = static_cast<FakeRauc *>(userdata);
    std::lock_guard<std::mutex> guard(self->mutex_);
    const std::string value = std::string(property) == "LastError" ? self->last_error_ : "idle";
    return sd_bus_message_append(reply, "s", value.c_str());
  }

  // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
  static constexpr sd_bus_vtable kVtable[] = {SD_BUS_VTABLE_START(0),
                                              SD_BUS_METHOD("InstallBundle", "sa{sv}", "", installBundle, 0),
                                              SD_BUS_METHOD("GetSlotStatus", "", "a(sa{sv})", getSlotStatus, 0),
                                              SD_BUS_PROPERTY("LastError", "s", getString, 0, 0),
                                              SD_BUS_PROPERTY("Operation", "s", getString, 0, 0),
                                              SD_BUS_SIGNAL("Completed", "i", 0),
                                              SD_BUS_VTABLE_END};

  sd_bus *server_{nullptr};
  sd_bus *client_{nullptr};
  std::atomic<bool> running_{true};
  std::thread thread_;
  std::mutex mutex_;
  std::string booted_{"rootfs.0"};
  std::map<std::string, std::string> hashes_;
  std::string bundle_hash_{"new"};
  std::string last_error_;
  std::string bundle_;
  std::string required_hash_;
  bool busy_{false};
};

static Json::Value targetJson(const std::string &manifest_hash) {
  Json::Value target_json;
  target_json["hashes"]["sha256"] = "D9CD8155764C3543F10FAD8A480D743137466F8D55213C8EAEFCD12F06D43A80";
  target_json["length"] = 1;
  if (!manifest_hash.empty()) {
    target_json["custom"]["rauc"]["manifest-hash"] = manifest_hash;
  }
  return target_json;
}

static Uptane::Target makeTarget(const std::string &name, const std::string &manifest_hash) {
  return Uptane::Target(name, targetJson(manifest_hash));
}

class RaucManagerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    config_.pacman.type = PACKAGE_MANAGER_RAUC;
    config_.pacman.images_path = temp_dir_.Path() / "images";
    config_.bootloader.reboot_sentinel_dir = temp_dir_.Path();
    config_.storage.path = temp_dir_.Path();
    storage_ = INvStorage::newStorage(config_.storage);
    pacman_ =
        std::make_unique<RaucManager>(config_.pacman, config_.bootloader, storage_, nullptr, rauc_.client(), nullptr);
    rauc_.setSlot("rootfs.0", "old");
  }

  void download() { pacman_->createTargetFile(target_) << "a"; }

  void reboot() {
    boost::filesystem::remove(config_.bootloader.reboot_sentinel_dir / config_.bootloader.reboot_sentinel_name);
  }

  TemporaryDirectory temp_dir_;
  FakeRauc rauc_;
  Config config_;
  std::shared_ptr<INvStorage> storage_;
  std::unique_ptr<RaucManager> pacman_;
  Uptane::Target target_{makeTarget("new.raucb", "new")};
};

TEST_F(RaucManagerTest, InstallAndFinalize) {
  download();
  EXPECT_EQ(pacman_->install(target_).result_code, data::ResultCode::Numeric::kNeedCompletion);
  EXPECT_EQ(rauc_.installed().first, pacman_->checkTargetFile(target_)->second);
  EXPECT_EQ(rauc_.installed().second, "new");
  EXPECT_EQ(pacman_->finalizeInstall(target_).result_code, data::ResultCode::Numeric::kNeedCompletion);

  reboot();
  rauc_.setSlot("rootfs.1", "new");
  EXPECT_EQ(pacman_->finalizeInstall(target_).result_code, data::ResultCode::Numeric::kOk);
}

TEST_F(RaucManagerTest, Rollback) {
  download();
  EXPECT_EQ(pacman_->install(target_).result_code, data::ResultCode::Numeric::kNeedCompletion);

  // The new slot ran out of boot attempts and the bootloader went back to the old one.
  reboot();
  EXPECT_EQ(pacman_->finalizeInstall(target_).result_code, data::ResultCode::Numeric::kInstallFailed);
}

TEST_F(RaucManagerTest, ManifestHashMismatch) {
  download();
  rauc_.setBundleHash("other");
  const auto result = pacman_->install(target_);
  EXPECT_EQ(result.result_code, data::ResultCode::Numeric::kInstallFailed);
  EXPECT_EQ(result.description, "Manifest hash mismatch");
}

TEST_F(RaucManagerTest, NoManifestHash) {
  target_ = makeTarget("new.raucb", "");
  download();
  EXPECT_EQ(pacman_->install(target_).result_code, data::ResultCode::Numeric::kInstallFailed);
  EXPECT_TRUE(rauc_.installed().first.empty());
}

// A power cut after RAUC armed the new slot but before aktualizr recorded the
// pending update: the device runs the target without aktualizr knowing.
TEST_F(RaucManagerTest, AlreadyRunning) {
  download();
  rauc_.setSlot("rootfs.1", "new");
  EXPECT_EQ(pacman_->install(target_).result_code, data::ResultCode::Numeric::kOk);
  EXPECT_TRUE(rauc_.installed().first.empty());
}

TEST_F(RaucManagerTest, Busy) {
  download();
  rauc_.setBusy();
  const auto result = pacman_->install(target_);
  EXPECT_EQ(result.result_code, data::ResultCode::Numeric::kInstallFailed);
  EXPECT_NE(result.description.find("Already processing"), std::string::npos);
}

TEST_F(RaucManagerTest, MissingBundle) {
  EXPECT_EQ(pacman_->install(target_).result_code, data::ResultCode::Numeric::kInstallFailed);
}

TEST_F(RaucManagerTest, CurrentFromStorage) {
  const auto old_target = makeTarget("old.raucb", "old");
  storage_->savePrimaryInstalledVersion(old_target, InstalledVersionUpdateMode::kCurrent, "");
  EXPECT_EQ(pacman_->getCurrent().filename(), "old.raucb");

  // A slot RAUC never wrote, as on a freshly flashed device.
  rauc_.setSlot("rootfs.0", "");
  EXPECT_EQ(pacman_->getCurrent().filename(), "old.raucb");
}

TEST_F(RaucManagerTest, CurrentFromBootedSlot) {
  storage_->savePrimaryInstalledVersion(makeTarget("old.raucb", "old"), InstalledVersionUpdateMode::kCurrent, "");
  Json::Value targets;
  targets["signed"]["_type"] = "Targets";
  targets["signed"]["version"] = 1;
  targets["signed"]["expires"] = "2038-01-19T03:14:06Z";
  targets["signed"]["targets"]["new.raucb"] = targetJson("new");
  storage_->storeNonRoot(Utils::jsonToStr(targets), Uptane::RepositoryType::Image(), Uptane::Role::Targets());

  rauc_.setSlot("rootfs.1", "new");
  EXPECT_EQ(pacman_->getCurrent().filename(), "new.raucb");

  rauc_.setSlot("rootfs.1", "unknown");
  EXPECT_FALSE(pacman_->getCurrent().IsValid());
}

#ifndef __NO_MAIN__
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
#endif
