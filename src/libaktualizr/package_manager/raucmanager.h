#ifndef RAUCMANAGER_H_
#define RAUCMANAGER_H_

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "libaktualizr/packagemanagerinterface.h"

#include "bootloader/bootloader.h"

struct sd_bus;

// Installs RAUC bundles on an A/B system through the RAUC D-Bus API. RAUC
// writes the inactive slot and arms the bootloader; the new slot is confirmed
// once the device has rebooted into it.
//
// A target is identified by the manifest hash of its bundle, given in the
// target's custom metadata as {"rauc": {"manifest-hash": "..."}}. RAUC
// records it as the "bundle.hash" of the slot it writes.
//
// Bundles are not downloaded: RAUC streams them from the repository while
// installing. Offline updates install the bundle from the local copy.
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
#ifdef BUILD_OFFLINE_UPDATES
  FetchResult fetchTargetOffUpd(const Uptane::Target &target, const Uptane::OfflineUpdateFetcher &fetcher,
                                const KeyManager &keys, const FetcherProgressCb &progress_cb,
                                const api::FlowControlToken *token) override;
#endif
  TargetStatus verifyTarget(const Uptane::Target &target) const override;

 private:
  struct BusDeleter {
    void operator()(sd_bus *bus) const;
  };

  sd_bus *bus() const;
  std::string property(const char *name) const;
  std::map<std::string, std::string> bootedSlot() const;
  std::string bootedHash() const;
  std::vector<Uptane::Target> imageTargets() const;
  std::string imageManifestHash(const Uptane::Target &target) const;
  std::string bundleUrl(const Uptane::Target &target) const;

  // Set by an online fetch: the bundle is then streamed from this repository.
  std::string repo_server_;
  std::unique_ptr<Bootloader> bootloader_;
  const char *service_;
  mutable std::mutex mutex_;  // sd-bus connections are not thread-safe
  mutable std::unique_ptr<sd_bus, BusDeleter> bus_;
};

#endif  // RAUCMANAGER_H_
