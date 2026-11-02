#include <gtest/gtest.h>

#include <sys/socket.h>
#include <systemd/sd-bus.h>
#include <array>
#include <atomic>
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

  void setSlots(const std::string &booted, const std::string &primary) {
    std::lock_guard<std::mutex> guard(mutex_);
    booted_ = booted;
    primary_ = primary;
  }
  void setInstallError(const std::string &error) {
    std::lock_guard<std::mutex> guard(mutex_);
    last_error_ = error;
  }
  void setBusy() {
    std::lock_guard<std::mutex> guard(mutex_);
    busy_ = true;
  }
  std::string bundle() {
    std::lock_guard<std::mutex> guard(mutex_);
    return bundle_;
  }

 private:
  static int installBundle(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
    auto *self = static_cast<FakeRauc *>(userdata);
    const char *source = nullptr;
    int r = sd_bus_message_read(m, "s", &source);
    if (r < 0) {
      return r;
    }
    std::lock_guard<std::mutex> guard(self->mutex_);
    if (self->busy_) {
      return sd_bus_error_set(ret_error, SD_BUS_ERROR_FAILED, "Already processing a different method");
    }
    self->bundle_ = source;
    r = sd_bus_reply_method_return(m, nullptr);
    if (r < 0) {
      return r;
    }
    const int32_t result = self->last_error_.empty() ? 0 : 1;
    return sd_bus_emit_signal(sd_bus_message_get_bus(m), "/", "de.pengutronix.rauc.Installer", "Completed", "i",
                              result);
  }

  static int getPrimary(sd_bus_message *m, void *userdata, sd_bus_error * /* ret_error */) {
    auto *self = static_cast<FakeRauc *>(userdata);
    std::lock_guard<std::mutex> guard(self->mutex_);
    return sd_bus_reply_method_return(m, "s", self->primary_.c_str());
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
      if (r >= 0) {
        r = sd_bus_message_append(reply, "(sa{sv})", slot, 2, "installed.count", "u", 1U, "state", "s", state);
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
                                              SD_BUS_METHOD("GetPrimary", "", "s", getPrimary, 0),
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
  std::string primary_{"rootfs.1"};
  std::string last_error_;
  std::string bundle_;
  bool busy_{false};
};

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

    Json::Value target_json;
    target_json["hashes"]["sha256"] = "D9CD8155764C3543F10FAD8A480D743137466F8D55213C8EAEFCD12F06D43A80";
    target_json["length"] = 1;
    target_ = Uptane::Target("bundle.raucb", target_json);
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
  Uptane::Target target_{Uptane::Target::Unknown()};
};

TEST_F(RaucManagerTest, InstallAndFinalize) {
  download();
  EXPECT_EQ(pacman_->install(target_).result_code, data::ResultCode::Numeric::kNeedCompletion);
  EXPECT_EQ(rauc_.bundle(), pacman_->checkTargetFile(target_)->second);
  EXPECT_EQ(pacman_->finalizeInstall(target_).result_code, data::ResultCode::Numeric::kNeedCompletion);

  reboot();
  rauc_.setSlots("rootfs.1", "rootfs.1");
  EXPECT_EQ(pacman_->finalizeInstall(target_).result_code, data::ResultCode::Numeric::kOk);
}

TEST_F(RaucManagerTest, Rollback) {
  download();
  EXPECT_EQ(pacman_->install(target_).result_code, data::ResultCode::Numeric::kNeedCompletion);

  // The new slot ran out of boot attempts and the bootloader went back to the old one.
  reboot();
  rauc_.setSlots("rootfs.0", "rootfs.0");
  EXPECT_EQ(pacman_->finalizeInstall(target_).result_code, data::ResultCode::Numeric::kInstallFailed);
}

TEST_F(RaucManagerTest, InstallFailure) {
  download();
  rauc_.setInstallError("Failed updating slot rootfs.1");
  const auto result = pacman_->install(target_);
  EXPECT_EQ(result.result_code, data::ResultCode::Numeric::kInstallFailed);
  EXPECT_EQ(result.description, "Failed updating slot rootfs.1");
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

#ifndef __NO_MAIN__
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
#endif
