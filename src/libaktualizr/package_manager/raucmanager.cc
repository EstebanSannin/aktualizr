#include "raucmanager.h"

#include <unistd.h>

#include <boost/filesystem.hpp>

#include "libaktualizr/packagemanagerfactory.h"

#include "logging/logging.h"
#include "storage/invstorage.h"
#include "utilities/utils.h"

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
AUTO_REGISTER_PACKAGE_MANAGER(PACKAGE_MANAGER_RAUC, RaucManager);

static Json::Value raucStatus() {
  std::string output;
  if (Utils::shell("rauc status --output-format=json", &output) != 0) {
    LOG_ERROR << "Could not get the RAUC status: " << output;
    return Json::nullValue;
  }
  return Utils::parseJSON(output);
}

static std::string bootedSlot(const Json::Value &status) {
  // "slots" is a list of single-member objects: [{"rootfs.0": {...}}, ...]
  for (const auto &slot : status["slots"]) {
    for (const auto &name : slot.getMemberNames()) {
      if (slot[name]["state"].asString() == "booted") {
        return name;
      }
    }
  }
  return "";
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

  LOG_INFO << "Installing " << target.filename() << " with RAUC...";
  std::string output;
  if (Utils::shell("rauc install " + bundle->second, &output, true) != 0) {
    LOG_ERROR << "RAUC installation failed: " << output;
    return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, output);
  }

  // RAUC makes the slot it has just written the primary one.
  const std::string slot = raucStatus()["boot_primary"].asString();
  if (slot.empty()) {
    return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed,
                                    "Could not determine the slot RAUC installed to");
  }
  Utils::writeFile(slotFile(), slot);

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
  const std::string booted = bootedSlot(raucStatus());

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
