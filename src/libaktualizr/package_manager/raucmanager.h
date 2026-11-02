#ifndef RAUCMANAGER_H_
#define RAUCMANAGER_H_

#include <memory>
#include <string>

#include "libaktualizr/packagemanagerinterface.h"

#include "bootloader/bootloader.h"

// Installs RAUC bundles on an A/B system. RAUC writes the inactive slot and
// arms the bootloader; the new slot is confirmed once the device has rebooted
// into it.
class RaucManager : public PackageManagerInterface {
 public:
  RaucManager(const PackageConfig &pconfig, const BootloaderConfig &bconfig, const std::shared_ptr<INvStorage> &storage,
              const std::shared_ptr<HttpInterface> &http)
      : PackageManagerInterface(pconfig, bconfig, storage, http), bootloader_{new Bootloader(bconfig, *storage_)} {}
  ~RaucManager() override = default;
  RaucManager(const RaucManager &) = delete;
  RaucManager(RaucManager &&) = delete;
  RaucManager &operator=(const RaucManager &) = delete;
  RaucManager &operator=(RaucManager &&) = delete;
  std::string name() const override { return "rauc"; }
  Json::Value getInstalledPackages() const override;
  bool hasOstreeDiverged(const std::string & /* expected_hash */) const override { return false; }
  Uptane::Target getCurrent() const override;

  data::InstallationResult install(const Uptane::Target &target) const override;
  void completeInstall() const override;
  data::InstallationResult finalizeInstall(const Uptane::Target &target) override;
  void updateNotify() override { bootloader_->updateNotify(); }
  FetchResult fetchTarget(const Uptane::Target &target, Uptane::Fetcher &fetcher, const KeyManager &keys,
                          const FetcherProgressCb &progress_cb, const api::FlowControlToken *token) override;

 private:
  // Slot RAUC was asked to boot, kept until the update is finalized.
  boost::filesystem::path slotFile() const { return config.images_path / "rauc-slot"; }

  std::unique_ptr<Bootloader> bootloader_;
};

#endif  // RAUCMANAGER_H_
