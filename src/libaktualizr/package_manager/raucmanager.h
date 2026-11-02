#ifndef RAUCMANAGER_H_
#define RAUCMANAGER_H_

#include <memory>
#include <mutex>
#include <string>

#include "libaktualizr/packagemanagerinterface.h"

#include "bootloader/bootloader.h"

struct sd_bus;

// Installs RAUC bundles on an A/B system through the RAUC D-Bus API. RAUC
// writes the inactive slot and arms the bootloader; the new slot is confirmed
// once the device has rebooted into it.
class RaucManager : public PackageManagerInterface {
 public:
  // bus and service are for tests: by default the RAUC service is reached on
  // the system bus.
  RaucManager(const PackageConfig &pconfig, const BootloaderConfig &bconfig, const std::shared_ptr<INvStorage> &storage,
              const std::shared_ptr<HttpInterface> &http, sd_bus *bus = nullptr,
              const char *service = "de.pengutronix.rauc");
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
  struct BusDeleter {
    void operator()(sd_bus *bus) const;
  };

  // Slot RAUC was asked to boot, kept until the update is finalized.
  boost::filesystem::path slotFile() const { return config.images_path / "rauc-slot"; }
  sd_bus *bus() const;
  std::string property(const char *name) const;
  std::string primarySlot() const;
  std::string bootedSlot() const;

  std::unique_ptr<Bootloader> bootloader_;
  const char *service_;
  mutable std::mutex mutex_;  // sd-bus connections are not thread-safe
  mutable std::unique_ptr<sd_bus, BusDeleter> bus_;
};

#endif  // RAUCMANAGER_H_
