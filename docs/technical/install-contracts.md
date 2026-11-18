# Reviewed installation contracts

Snapshot: 2026-11-04. These are download and adapter contracts, not a claim of tested router installation. No router was contacted or changed. Existing UI/watchdog repositories were read only. Release assets can be replaced upstream even under a fixed tag: the catalog pins the observed size and SHA256 and fails on drift.

## Canonical catalog

`internal/catalog` is dependency-free and offline. `Component` values are `Entware`, `XKeen`, `Mihomo`, `Xray`, `UI`, `Watchdog`. `RouterArch` values are `ARM64` (`arm64`), `MIPSel` (`mipsel`), `MIPS` (`mips`). Detection and parsing of router output belong to the later discovery layer; substring matching of unknown architectures is forbidden here. Shared/all payloads still retain the requested router architecture in the returned contract.

`Resolve(component, arch) (Artifact, error)` returns the reviewed default. `ResolveVersion(component, arch, version)` permits only the exact reviewed version; it does not invent arbitrary release URLs or follow `latest`. `Artifact` has `Component`, `Arch`, `Version`, `URL`, `Size` and `Integrity { SHA256, Source }`. `Size=0` and an empty digest mean upstream verification is unavailable, not successful. `Verify(artifact, io.Reader)` first rejects any metadata change against the canonical snapshot, then checks download size and SHA256 while streaming at most expected size + 1 bytes. Read errors are preserved. It performs no installation, extraction, HTTP requests or router mutations. Entware now verifies installer-derived offline bundle pins; see `docs/entware-byte-pins.md` for the superseding SEC-001 snapshot. A digest published by the same upstream proves consistency, not independent publisher authentication or executable architecture.

| Component | Reviewed version | ARM64 asset | MIPSel asset | MIPS asset |
| --- | --- | --- | --- | --- |
| XKeen | `2.1` | `xkeen.tar.gz` | same | same |
| Mihomo | `v1.19.33` | `mihomo-linux-arm64-v1.19.33.gz` | `mihomo-linux-mipsle-softfloat-v1.19.33.gz` | `mihomo-linux-mips-softfloat-v1.19.33.gz` |
| Xray | `v26.10.31` | `Xray-linux-arm64-v8a.zip` | `Xray-linux-mips32le.zip` | `Xray-linux-mips32.zip` |
| UI | `v1.4.2+pwa.1` | `xkeen-ui-arm64-v8a` | `xkeen-ui-mips32le` | `xkeen-ui-mips32` |
| Watchdog | `1.0.16-1` | `router-watchdog_1.0.16-1_all.ipk` | same | same |
| Entware | `offline-2026-11-16` | bundled `arm64.tar.gz` | bundled `mipsel.tar.gz` | bundled `mips.tar.gz` |

Published sizes/digests were read from the actual primary [XKeen release API](https://api.github.com/repos/jameszeroX/XKeen/releases/tags/2.1), [Mihomo release API](https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/v1.19.33), [Xray release API](https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.10.31), [UI release API](https://api.github.com/repos/Arap919/xkeen-ui-pwa-fork/releases/tags/v1.4.2%2Bpwa.1) and [watchdog feed manifest](https://arap919.github.io/router-watchdog/update.json). GitHub API rate limiting affected some anonymous requests; XKeen metadata was subsequently read through the connected GitHub tool. UI tag `+` is encoded as `%2B` in download URLs. No mirror is silently substituted.

## Entware bootstrap and manual gate

The following are original upstream inputs, not the current shipped archive bytes. The SEC-001 offline derivative, package closure, transformation and final pins are specified in `docs/entware-byte-pins.md`.

Official upstream source archives inspected directly:

- [ARM64](https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz): 3,232,671 bytes.
- [MIPSel](https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz): 3,304,180 bytes.
- [MIPS](https://bin.entware.net/mipssf-k3.4/installer/mips-installer.tar.gz): 3,503,782 bytes.

All three contain 229 members rooted at `bin`, `etc`, `lib`, `libexec`, `sbin`, `usr`, including `bin/opkg`, `bin/install`, and `etc/init.d/doinstall`. The latter clears loader environment variables and launches `/opt/bin/sh /opt/bin/install` in the background. No upstream version identifier or published digest was established. Observed sizes are research evidence only and intentionally are not presented as pinned integrity metadata. Archive files include host keys; this inspection does not establish their later regeneration behavior. Do not distribute local hashes as if they were upstream checksums.

The upstream [Keenetic community quickstart](https://forum.keenetic.com/topic/4290-entware-quickstart/) describes the `install` directory on the selected storage and the OPKG disk-selection workflow. The old [vendor guide](https://support.keenetic.ru/eaeu/hopper-se/kn-3812/en/20980-installing-the-entware-repository-on-a-usb-drive.html) now redirects to the support landing page, so its old permalink cannot establish current firmware UI behavior. The [XKeen router architecture table](https://github.com/jameszeroX/XKeen/wiki/Routers-Info) supplies the matching archive families; actual architecture must still be discovered from the router.

**Bootstrap mode in this task: manual, unverified transport.** No local SMB test resource/server was provided or established; no SMB upload/rename/permissions or firmware extraction trigger was tested. Therefore automatic SMB bootstrap is unsupported. The user manually copies the matching archive into `install` on the prepared storage root (the storage later mounted at `/opt`), and manually selects/applies that storage in KeeneticOS OPKG settings to trigger its bootstrap processing. If that storage is already selected, the wizard must ask the user to follow the firmware's documented re-selection/remount procedure; this task has not established that copying alone triggers extraction on an already-mounted disk. Do not silently change the disk, reconnect storage, reboot, format or execute an OPKG CLI command. Firmware-specific instructions must be verified before that path is automated.

After the user completes the manual action, re-read actual `/opt/bin/opkg` and a successful read-only package query over Entware SSH. A copied archive, completed SMB transfer, exit of the background `doinstall`, or user confirmation alone never means Entware is installed. The catalog deliberately has no `installed=true` field or bootstrap-success function.

## XKeen and independent core selection

Primary [autoinstall interface](https://github.com/jameszeroX/XKeen/wiki/autoinstall) supports `xkeen -i auto` and `cores=xray|mihomo|all|none`, `geo=on|off`, `geoipset=on|off`, `cron=on|off`, `autostart=on|off`, plus `xray=vX.Y.Z` and `mihomo=vX.Y.Z`. `auto` must immediately follow `-i`. Both cores means `cores=all`, not `cores=both`. Default auto mode installs both cores, geodata and cron and enables autostart; an adapter must pass explicit choices from the reviewed plan rather than rely on defaults. Version switches use `xkeen -ux vX.Y.Z` / `xkeen -um vX.Y.Z`; specifying a core not selected is rejected. Latest auto selection may include prereleases, so the installer must pin versions. `-toff` disables download timeout and is not needed by the catalog.

Example of an explicit adapter command AFTER verified staging and the approved backup/configuration steps (example choices only):

```sh
/opt/sbin/xkeen -i auto cores=all xray=v26.10.31 mihomo=v1.19.33 geo=off geoipset=off cron=off autostart=off
```

For a single core, use `cores=mihomo mihomo=v1.19.33` or `cores=xray xray=v26.10.31`, omitting the other core version argument. Geo/cron/autostart flags must reflect the reviewed user plan. This command has not been executed on any router.

Critical distinction: [pinned `install.sh`](https://github.com/jameszeroX/XKeen/blob/2.1/install.sh) supports `--stable`/`--legacy 2.1`, but ends with `exec /opt/sbin/xkeen -i` WITHOUT `auto`. Its initial version choice is noninteractive, its entire installation is not. Do not drive this wrapper using blind menu answers. The verified `xkeen.tar.gz` contains root `xkeen` plus `_xkeen` (72 members); the adapter must stage the verified archive, preserve/back up existing runtime and configuration, install the executable at `/opt/sbin/xkeen` and modules at `/opt/sbin/.xkeen`, then invoke the documented explicit auto command. Those writes are later-task work and are not implemented here. Review archive safety before extraction. Existing configs and active-core state must be read before deciding whether full `-i`, core-specific update or no operation is appropriate. Upstream best-effort digest verification may warn and continue; it is not a substitute for the host's strict catalog verifier.

## UI PWA paths and lifecycle

Primary [tagged setup](https://github.com/Arap919/xkeen-ui-pwa-fork/blob/v1.4.2%2Bpwa.1/setup.sh), [types](https://github.com/Arap919/xkeen-ui-pwa-fork/blob/v1.4.2%2Bpwa.1/backend/src/types.rs), and [watchdog push state](https://github.com/Arap919/xkeen-ui-pwa-fork/blob/v1.4.2%2Bpwa.1/backend/src/watchdog.rs); local source was also inspected.

- Executable: `/opt/sbin/xkeen-ui`; init: `/opt/etc/init.d/S99xkeen-ui` (`start|stop|restart|status`); default port 1000 is configured in init.
- Settings: `/opt/etc/xkeen/xkeen-ui.json`; XKeen settings: `/opt/etc/xkeen/xkeen.json`; private push/VAPID state: `/opt/etc/xkeen/watchdog-push.json` (0600).
- TLS paths: `/opt/etc/nginx/ssl/server.crt` and `server.key`; preserve valid existing files. The CA private key must remain on the host.
- Legacy paths checked by setup: `/opt/share/www/XKeen-UI`, `/opt/etc/lighttpd/conf.d/90-xkeenui.conf`, `/opt/etc/init.d/S80lighttpd`.

`setup.sh` detects existing files and enters its uninstall/reinstall flow. It is not a safe unattended preserving adapter. Later tasks must deploy the verified binary and controlled init changes after backups and preserve all above data. A successful binary transfer does not establish HTTPS/service readiness.

## Watchdog package, feed and cron

Primary [release](https://github.com/Arap919/router-watchdog/releases/tag/v1.0.16), [package definition](https://github.com/Arap919/router-watchdog/blob/v1.0.16/net/router-watchdog/Makefile), [README](https://github.com/Arap919/router-watchdog/blob/v1.0.16/README.md), [feed Packages](https://arap919.github.io/router-watchdog/all/Packages), and [update manifest](https://arap919.github.io/router-watchdog/update.json). Published manifest: schema 1, version `1.0.16-1`, size 19,860, SHA256 `68a5295a8e80702e54c036c7263174f74102ea5f40ef2272ec84be9d2a5535d6`. Catalog uses the matching versioned release asset; the feed itself is mutable.

Architecture `all` does not remove native dependency requirements: Python, PyYAML (`python3-yaml`), HTTPS downloader/certificates and a working Entware cron must be available via the correct Entware feed. Use opkg/IPK hooks, not manual payload copying. The package's configuration-preservation mechanism retains old state via `/opt/etc/router-watchdog.json-upgrade`, merges the new defaults at `/opt/share/router-watchdog/defaults.json`, writes `/opt/etc/router-watchdog.json` and keeps `.json-old`. A package failure can leave partial state; re-read package/config status before retry.

Cron uses `/opt/etc/crontab` system entries including `root`, plus `/opt/etc/cron.1min/router-watchdog`; commands are `/opt/bin/router-watchdog --sync-cron` and `--remove-cron`. User spool `crontab -l` is not this system file. Current documented restart assumes `/opt/etc/init.d/S10cron`; existing XKeen installations can have `S05crond`. Discover scripts and actual `crond` process rather than treating S10cron as universal. This compatibility gap can block activation and must be reported; this task does not fix upstream. With active Xray or incompatible Mihomo select/provider/BENCHMARK/listener/API configuration, watchdog activation is blocked even if IPK installation succeeded.

## Verification boundary

Unit tests cover all three architecture mappings, unsupported input, concrete-version refusal, metadata tampering, truncation, oversized payloads, SHA256 corruption, known valid SHA256, reader errors, and explicit unavailable Entware integrity. They do not claim SMB compatibility, Entware extraction on firmware, package script safety, preservation on real routers or running services. These remain integration gates requiring an authorized test router.

## Task 4 controlled execution adapter

The pinned [XKeen 2.1 dispatcher](https://github.com/jameszeroX/XKeen/blob/2.1/scripts/xkeen) unconditionally replaces/starts S05crond during `-i auto`, even with `cron=off`; it also restarts an already running proxy. Its wrapper runs implicit package self-healing for `-start` and can detach from SSH. Consequently this adapter does not call full `-i`, update wrappers, menus, or setup.sh. It copies strictly host-verified archive members into `/opt/sbin/xkeen` and `/opt/sbin/.xkeen`; deploys the already standalone [upstream init](https://github.com/jameszeroX/XKeen/blob/2.1/scripts/_xkeen/02_install/07_install_register/04_register_init.sh) to S05xkeen for a new installation, changes only its fixed `name_client` assignment to the reviewed core, and calls S05xkeen directly with `stop`, `start on`, and `status`. Existing recognizable init scripts retain all bytes except an explicitly requested core switch. Unsupported custom init layouts are blocked. No synthetic opkg status registrations or global package upgrades are performed. Only the explicitly previewed dependency names are installed with opkg.

S05xkeen owns `/opt/etc/ndm/netfilter.d/proxy.sh` and `/opt/etc/ndm/schedule.d/00-xkeen-hotspot-sync.sh`; discovery and backup now include these exact existing files, not other users' NDM hooks. Native validation is mandatory before starting the core. Both an isolated configuration copy and the installed live configuration are checked; read-only validation diagnostics are suppressed because they can include secrets. An inactive generated Xray base may be installed alongside active valid Mihomo, but remains explicitly pending user connection/routing setup and is never started or treated as ready.

Mihomo additionally needs the Mike Farah yq dialect. The pinned [XKeen downloader](https://github.com/jameszeroX/XKeen/blob/2.1/scripts/_xkeen/04_tools/07_tools_downloaders/01_downloaders_mihomo.sh) uses yq_linux_arm64/mipsle/mips and has a jameszeroX/yq workaround. Exact added contracts:

| Router | Release / runtime version | Asset | Size | Published SHA256 |
| --- | --- | --- | --- | --- |
| ARM64 | mikefarah/yq v4.54.1 / v4.54.1 | yq_linux_arm64 | 13172896 | 189088da0c6429ec5178dfaab1a114805f6cab0b61b165ab236efedf1d57a71b |
| MIPS | jameszeroX/yq 260527 / v4.53.2 | yq_linux_mips | 15139009 | 05ed5069325c2caea97e717a36aaab161f365afa4af862b38c51ef32a2608b41 |
| MIPSel | jameszeroX/yq 260527 / v4.53.2 | yq_linux_mipsle | 15139009 | 9271b89b0618a4fb5034f2688eaf6433756f5342c97b3bf9cbffdd04fcd29dd7 |

Primary metadata: [official exact release](https://api.github.com/repos/mikefarah/yq/releases/tags/v4.54.1), [fork exact release](https://api.github.com/repos/jameszeroX/yq/releases/tags/260527). The [pinned fork README](https://github.com/jameszeroX/yq/blob/260527/README.md) explicitly states GOMIPS=softfloat for mips/mipsle and runtime yq v4.53.2; release tag and runtime version are deliberately distinct. An exploratory official MIPS response did not match published size/digest and was rejected; no bytes from that response are used. All actual installer downloads must independently pass canonical catalog.Verify and ELF architecture checks. A shadowing `/opt/bin/yq` blocks execution before backup/mutation instead of silently invoking a different parser through the upstream init PATH.

Watchdog installation uses the pinned IPK through opkg, including preinst/postinst hooks. Because postinst immediately synchronizes cron, this operation runs only after compatible active Mihomo passes native validation and actual process inspection. Only an executable S10cron with a running crond is currently supported for watchdog activation; S05crond/custom variants are explicitly blocked for manual reconciliation, since upstream assumes S10cron. Reviewed exact watchdog bytes are restored and read back after package hooks, followed by explicit --sync-cron; failures are partial and require fresh inspection, never an opkg rollback claim.

New UI binaries are verified and installed with a controlled disabled rc.func init; TLS provisioning/HTTPS/PWA readiness remain Task 5. Existing recognized UI init/settings/private push state/TLS bytes are preserved, and an already configured UI is stopped during replacement then restarted/status-checked. No legacy uninstall, hidden RCI/KeeneticOS change, disk operation, reboot or automatic SMB/Entware bootstrap is performed. Real-router service/firewall/package-hook integration is untested and still requires separate authorization.
