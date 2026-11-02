#include <gtest/gtest.h>

#include <cstdlib>
#include <memory>
#include <string>

#include <boost/filesystem.hpp>

#include "libaktualizr/config.h"
#include "package_manager/raucmanager.h"
#include "storage/invstorage.h"
#include "utilities/utils.h"

// Puts a fake 'rauc' first in PATH: 'install' exits with the code stored in
// install_rc, 'status' prints status.json.
class RaucManagerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    bin_ = temp_dir_.Path() / "bin";
    boost::filesystem::create_directories(bin_);
    Utils::writeFile(bin_ / "rauc", std::string("#!/bin/sh\n"
                                                "dir=$(dirname \"$0\")\n"
                                                "case \"$1\" in\n"
                                                "  install) exit \"$(cat \"$dir/install_rc\")\" ;;\n"
                                                "  status) cat \"$dir/status.json\" ;;\n"
                                                "esac\n"));
    boost::filesystem::permissions(bin_ / "rauc", boost::filesystem::owner_all);
    Utils::writeFile(bin_ / "install_rc", std::string("0"));
    setStatus("rootfs.0", "rootfs.1");
    path_ = getenv("PATH");
    setenv("PATH", (bin_.string() + ":" + path_).c_str(), 1);

    config_.pacman.type = PACKAGE_MANAGER_RAUC;
    config_.pacman.images_path = temp_dir_.Path() / "images";
    config_.bootloader.reboot_sentinel_dir = temp_dir_.Path();
    config_.storage.path = temp_dir_.Path();
    storage_ = INvStorage::newStorage(config_.storage);
    pacman_ = std::make_unique<RaucManager>(config_.pacman, config_.bootloader, storage_, nullptr);

    Json::Value target_json;
    target_json["hashes"]["sha256"] = "D9CD8155764C3543F10FAD8A480D743137466F8D55213C8EAEFCD12F06D43A80";
    target_json["length"] = 1;
    target_ = Uptane::Target("bundle.raucb", target_json);
  }

  void TearDown() override { setenv("PATH", path_.c_str(), 1); }

  void setStatus(const std::string& booted, const std::string& primary) {
    Json::Value status;
    status["boot_primary"] = primary;
    for (const char* slot : {"rootfs.0", "rootfs.1"}) {
      Json::Value entry;
      entry[slot]["state"] = slot == booted ? "booted" : "inactive";
      status["slots"].append(entry);
    }
    Utils::writeFile(bin_ / "status.json", status);
  }

  void download() { pacman_->createTargetFile(target_) << "a"; }

  void reboot() {
    boost::filesystem::remove(config_.bootloader.reboot_sentinel_dir / config_.bootloader.reboot_sentinel_name);
  }

  TemporaryDirectory temp_dir_;
  boost::filesystem::path bin_;
  std::string path_;
  Config config_;
  std::shared_ptr<INvStorage> storage_;
  std::unique_ptr<RaucManager> pacman_;
  Uptane::Target target_{Uptane::Target::Unknown()};
};

TEST_F(RaucManagerTest, InstallAndFinalize) {
  download();
  EXPECT_EQ(pacman_->install(target_).result_code, data::ResultCode::Numeric::kNeedCompletion);
  EXPECT_EQ(pacman_->finalizeInstall(target_).result_code, data::ResultCode::Numeric::kNeedCompletion);

  reboot();
  setStatus("rootfs.1", "rootfs.1");
  EXPECT_EQ(pacman_->finalizeInstall(target_).result_code, data::ResultCode::Numeric::kOk);
}

TEST_F(RaucManagerTest, Rollback) {
  download();
  EXPECT_EQ(pacman_->install(target_).result_code, data::ResultCode::Numeric::kNeedCompletion);

  // The new slot ran out of boot attempts and the bootloader went back to the old one.
  reboot();
  setStatus("rootfs.0", "rootfs.0");
  EXPECT_EQ(pacman_->finalizeInstall(target_).result_code, data::ResultCode::Numeric::kInstallFailed);
}

TEST_F(RaucManagerTest, InstallFailure) {
  download();
  Utils::writeFile(bin_ / "install_rc", std::string("1"));
  EXPECT_EQ(pacman_->install(target_).result_code, data::ResultCode::Numeric::kInstallFailed);
}

TEST_F(RaucManagerTest, MissingBundle) {
  EXPECT_EQ(pacman_->install(target_).result_code, data::ResultCode::Numeric::kInstallFailed);
}

#ifndef __NO_MAIN__
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
#endif
