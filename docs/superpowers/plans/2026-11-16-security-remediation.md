# Security Remediation Plan and Audit Register

**Audit date:** 2026-11-16
**Status:** Remediation in progress; SEC-001, SEC-005 and SEC-007 closed for the reviewed CI build candidates. Other findings remain open. No exploitation demonstrated.
**Goal:** Address the security findings from the source and local-artifact audit before broad installer distribution.
**Architecture:** Preserve the existing SSH transport, reviewed artifact catalog, installation approval gates, and private TLS storage. Remediate each trust boundary independently; do not redesign unrelated installation behavior.
**Tech stack:** Go, Wails v2, TypeScript, Python, Entware/opkg, GitHub Actions, Windows/macOS/Linux packaging.
**Source specification:** Security audit reported in the current project chat on 2026-11-16; its evidence and qualifications are captured below.
**Execution:** This document authorizes no implementation, commits, pushes, releases, or external issue creation. Implementation requires a separate user request. Do not create worktrees or project copies without an explicit request.

## Scope and evidence limits

The audit inspected application source, frontend rendering, SSH/SMB transports, archive handling, TLS generation/storage/trust, subscription handling, packaging, CI, bundled Entware archives, and existing local desktop binaries.

Checks performed:
- `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`: reported 20 symbol-level standard-library findings for Go 1.26.3, plus 4 package-level and 7 module-level findings without identified calls. This was a host-platform source scan with default build tags, not a complete production matrix scan.
- `npm audit --json --ignore-scripts`: reported zero known vulnerabilities across 132 dependencies.
- All three bundled Entware archive sizes and SHA-256 digests matched the catalog.
- Inspection of each bundled `etc/opkg.conf`: HTTP feeds, no enabled signature-check option in those files.
- Inspection of the ARM64 archive's `bin/install`: package downloads, SSH startup, and a message advertising default root credentials.
- Local Windows EXE: Go 1.26.3; PE certificate-table offset and size both zero.
- Local macOS app: ad-hoc code signature; no TeamIdentifier.

Local binaries were dated November 9 and are not evidence of the exact current published installers. No Windows/Linux installer execution, router exploitation, production platform-matrix scan, full upstream-binary audit, fuzzing campaign, or GitHub account/protection audit was performed. No intentional backdoor or direct desktop command execution through a subscription/router response was established. Absence of such a finding is not proof of absence.

## Global constraints

- Keep user-facing UI and documentation Russian; technical tasks, code, and comments English.
- Do not expose passwords, subscription URLs, private keys, or full router configurations in logs or reports.
- Preserve user configuration, backups, host-key checks, archive/path checks, and explicit approval gates.
- Do not infer Internet exposure from a wildcard bind; verify firewall and network reachability separately.
- Treat scanner findings as candidates requiring platform, call-path, and prerequisite analysis.
- Test security boundaries with isolated fixtures; never attack a user's router or import a test CA into their real trust store.
- Review each task independently. Record the verification result before closing it.

## Finding register

| ID | Priority | Evidence status | Affected boundary | Finding |
| --- | --- | --- | --- | --- |
| SEC-001 | P1 / release blocker | HTTP feeds and installer calls confirmed; exploitation not demonstrated | Network to router root | Entware bootstrap and dependency installation leave the reviewed hash boundary and use HTTP package feeds without signature checking enabled in the bundled configuration. |
| SEC-002 | P1 / release blocker | Unrestricted 10-year CA and retained private key confirmed; abuse requires key theft and traffic interception | Desktop trust store | A CA intended for one router receives broad root trust and leaves a reusable signing key on disk. |
| SEC-003 | P2 | PATH lookup confirmed; exploitation requires a writable earlier PATH entry | Desktop process execution | Trust installation resolves Windows/Linux utilities through PATH. |
| SEC-004 | P2 | Generated configuration exposure confirmed; actual reachability untested | LAN to router proxy | New Mihomo configuration enables unauthenticated HTTP/SOCKS/mixed proxy ports on wildcard interfaces. |
| SEC-005 | P1 / release blocker | Toolchain version and scanner output confirmed; individual exploitability mixed | Untrusted input to desktop runtime | CI and a local Windows binary use Go 1.26.3 with known standard-library advisories. |
| SEC-006 | P1 / distribution gate | Local artifact signature status and missing CI signing steps confirmed; current published artifacts unverified | Distribution to desktop execution | Installer provenance is not established by publisher signatures in the inspected release process. |
| SEC-007 | P1 / verification gate | Bootstrap behavior confirmed; effective post-install credentials unverified | Network to router SSH | New Entware bootstrap starts SSH and advertises a default root password; the wizard does not enforce changing it. |

P1 means address or explicitly resolve before broad distribution. P2 means a conditional or narrower security problem; priority does not assert a remotely exploitable desktop vulnerability. SEC-002 and SEC-006 include architectural/distribution risks, rather than a demonstrated code exploit.

## Review focus

- Fresh Entware must not fetch unauthenticated executable bytes before HTTPS/signature protection becomes available (SEC-001).
- Router CA trust must not silently extend to unrelated public sites; decline/removal must remain usable (SEC-002).
- A hostile PATH must not select executables for trust-store changes (SEC-003).
- Transparent routing must keep working while unnecessary explicit proxy access is restricted (SEC-004).
- A new SSH service must not expose reusable default credentials during the bootstrap-to-wizard handoff (SEC-007).

## Task pool

### SEC-001: Authenticate all Entware package downloads

**Status:** Closed for commit f9be0b2 CI candidates and isolated package fixtures; real firmware handoff remains unverified
**Priority:** P1
**Evidence:** `internal/bootstrap/archives/{arm64,mips,mipsel}.tar.gz`, members `etc/opkg.conf` and ARM64 `bin/install`; `internal/install/runner.go`, dependency stage; `internal/catalog/catalog.go`.
**Attack prerequisites:** An attacker can alter the router's HTTP download traffic or responses. Unauthenticated package metadata can defeat checksums delivered through the same channel.
**Impact:** Potential root code execution on the router through substituted packages/install hooks, followed by attacks on the home network. Desktop execution was not demonstrated.

- [x] Trace every initial-bootstrap and later opkg fetch, including transitive dependencies and repository metadata; document its authentication mechanism.
- [x] Select and implement authenticated bootstrap delivery that works before CA/TLS packages are installed. Merely changing the post-bootstrap feed URLs is insufficient.
- [x] Enforce certificate validation and/or independently trusted package signatures/digests for executable package content. Reject insecure feeds used by existing Entware installations before invoking opkg, with actionable Russian guidance.
- [x] If bundled bytes change, update archive size/digest pins and `docs/entware-byte-pins.md`; preserve archive safety validation.
- [x] Test tampered metadata/package bytes, HTTP downgrade, untrusted certificates, and missing trust material. Each must stop before executing untrusted package hooks; no insecure fallback.
- [x] Validate an isolated clean installation and an existing installation for ARM64, MIPS, and MIPSel.

**Acceptance:** Every executable package download has an authenticated trust path, including the earliest bootstrap fetch. Negative fixtures fail closed. Reviewed catalog bytes remain reproducible.
**Likely files:** `internal/bootstrap/archive.go`, bundled archives, `internal/catalog/catalog.go`, `internal/install/runner.go`, corresponding bootstrap/install tests, `docs/entware-byte-pins.md`.
**Reference:** https://github.com/Entware/Entware/blob/master/package/system/opkg/Makefile

### SEC-002: Reduce router certificate trust scope and key lifetime

**Status:** Open
**Priority:** P1
**Evidence:** `internal/tls/certificate.go`, CA template; `internal/tls/authority.go`, retained `ca.key`; `internal/tls/trust.go`, OS root-store import.
**Attack prerequisites:** Theft of the local CA signing key plus control of the victim's traffic; affected clients must use the modified trust store.
**Impact:** Certificates for unrelated sites may be accepted by those clients. The router does not receive the CA private key, and possession of a subscription alone does not enable this attack.

- [ ] Decide the supported trust design before changing code: avoid root-store import where feasible, or constrain trust to the intended router identity with independently verified platform behavior. Do not assume all clients enforce root name constraints identically.
- [ ] Define the minimum certificate/key retention needed for the supported renewal workflow; remove unnecessary persistent CA signing capability and reduce validity appropriately.
- [ ] Define migration for existing unrestricted roots and stored keys. Never delete keys before providing a safe replacement/recovery path, and never remove unrelated roots.
- [ ] Retain explicit user approval and clearly state the scope of the trust change in Russian.
- [ ] Test the intended router certificate and an unrelated-domain certificate against isolated trust stores on each supported OS. Unrelated-domain acceptance must not be introduced by the chosen design.
- [ ] Provide and validate precise removal instructions for previously imported roots; do not remove real user trust during automated tests.

**Acceptance:** The chosen design has documented, tested trust boundaries and key lifecycle. An unrelated site cannot gain acceptance through the new router trust mechanism. Existing installations have a safe migration/removal path.
**Likely files:** `internal/tls/certificate.go`, `internal/tls/authority.go`, `internal/tls/trust.go`, `app.go`, `frontend/src/wizard.ts`, `frontend/src/ui.ts`, corresponding TLS/frontend tests, `README.md`.

### SEC-003: Resolve trust utilities from trusted system locations

**Status:** Open
**Priority:** P2
**Evidence:** `internal/tls/trust.go`, `ExecRunner.LookPath` and Windows/Linux trust commands.
**Attack prerequisites:** A malicious executable can be placed in a directory preceding the genuine utility in the inherited PATH.
**Impact:** Code execution with the desktop application's current privileges; privileged launches increase the impact. This is not a demonstrated remote attack.

- [ ] Resolve Windows `certutil` through the OS system-directory API and Linux utilities through explicitly supported trusted absolute locations. Keep macOS absolute paths.
- [ ] Use a controlled environment for trust-store commands and their subprocesses; fail with manual instructions if no trusted utility is available.
- [ ] Add tests with a fake utility in a hostile PATH, a missing system utility, and a certificate path containing spaces/quotes. The fake utility must never execute.
- [ ] Verify that declining approval still performs no command execution and arguments remain separate argv values.

**Acceptance:** Trust operations never select an executable from caller-controlled PATH entries; missing tools fail closed.
**Likely files:** `internal/tls/trust.go`, platform-specific TLS helpers if needed, `internal/tls/authority_test.go` and/or focused trust tests.

### SEC-004: Restrict unauthenticated explicit proxy listeners

**Status:** Open
**Priority:** P2
**Evidence:** `internal/config/templates/mihomo.yaml`, ports 7890/7891/1080, `allow-lan`, wildcard bind, and absent authentication; `internal/config/templates.go`, generated API/benchmark overrides.
**Attack prerequisites:** Network access to the explicit proxy ports. WAN availability is not established.
**Impact:** Unauthorized use of the router/proxy subscription, resource consumption, and possible access-policy bypass.

- [ ] Determine which explicit proxy listeners are required by the existing product contract. Bind unnecessary external access to loopback or disable unused listeners; retain transparent redir/tproxy behavior.
- [ ] If LAN proxy access is required, specify a restricted client/interface policy and authentication instead of permitting every reachable client.
- [ ] Apply the policy in generated configuration, not only the source template. Preserve user-owned existing configurations and explain unsafe existing settings without silently rewriting them.
- [ ] Add generated-config tests distinguishing explicit proxy ports from transparent routing and the already-loopback API/benchmark listener.
- [ ] Verify reachability from an allowed and a disallowed client in an isolated network; separately record firewall behavior.

**Acceptance:** A fresh default installation does not offer an unauthenticated explicit proxy to arbitrary reachable clients, and intended transparent routing continues to work.
**Likely files:** `internal/config/templates/mihomo.yaml`, `internal/config/templates.go`, `internal/config/mihomo_base_test.go`, relevant validation tests.
**Reference:** https://wiki.metacubex.one/en/config/inbound/port/

### SEC-005: Update Go and triage production vulnerability scans

**Status:** Closed for commit 617c94d CI candidates; previously distributed binaries are not covered
**Priority:** P1
**Evidence:** `.github/workflows/build.yml` pins Go 1.26.3; local Windows EXE build metadata agrees; govulncheck reported 20 symbol-level standard-library findings.
**Impact:** Known parser, protocol, and runtime weaknesses may remain in shipped binaries. A scanner call-path match alone does not establish exploitability.

- [x] Select a currently supported Go patch release covering applicable advisories. The observed report included fixes through Go 1.26.11; confirm the actual supported release at implementation time.
- [x] Update CI/toolchain declarations and rebuild all four desktop targets; updating an installed Go compiler alone does not repair previously built binaries.
- [x] Run govulncheck for actual production tags/platforms, and inspect resulting binaries where supported. Record advisory IDs, platform relevance, prerequisites, mitigation, and disposition.
- [x] Add a CI vulnerability gate with explicit, justified handling of non-applicable findings; do not globally suppress standard-library reports.
- [x] Run existing Go/frontend checks and verify embedded Go versions in release artifacts.

**Acceptance:** Newly built artifacts use the reviewed patched toolchain. Every remaining finding has a documented applicability decision; no applicable unresolved release blocker remains.
**Likely files:** `.github/workflows/build.yml`, `go.mod` only if needed by the selected supported version, related toolchain documentation.
**Triage examples:** GO-2026-6611 affects HTTP/2 CPU consumption; GO-2026-4970 requires Unix os.Root symlink/trailing-slash conditions, not established for the current fixed certificate filenames. Do not label every reported advisory as desktop RCE.
**References:** https://pkg.go.dev/vuln/GO-2026-6611 ; https://pkg.go.dev/vuln/GO-2026-4970

### SEC-006: Establish publisher authenticity for distributed installers

**Status:** Open
**Priority:** P1
**Evidence:** Inspected local Windows EXE has no embedded Authenticode signature; macOS app has only an ad-hoc signature; `.github/workflows/build.yml` has no publisher-signing/notarization steps. Current published assets were not checked.
**Attack prerequisites:** Substitution of a download, mirror, message attachment, or distribution channel. A matching checksum obtained through the same compromised channel does not establish publisher identity.
**Impact:** Execution of a substituted desktop installer, potentially with installation privileges.

- [ ] Verify signature/provenance status of the actual published installers before applying local-artifact conclusions to them.
- [ ] Define publisher signing for Windows and Developer ID signing/notarization for macOS; define authenticated release metadata/provenance for Linux.
- [ ] Keep signing keys and credentials in an appropriate signing service or protected CI secrets. Never place secrets in chat or the repository.
- [ ] Sign final executable/package layers in the correct order, then generate checksums/provenance for the final distributed bytes. Restrict credential use to trusted release contexts.
- [ ] Validate signatures, expected publisher identity, notarization, and tamper rejection on supported systems. PR builds must not receive release signing credentials.
- [ ] Document user verification in Russian. Confirm external account/certificate prerequisites before enabling publication.

**Acceptance:** Release assets have verifiable publisher/provenance evidence; final-byte checksums agree; tampering is rejected or clearly fails documented verification.
**Likely files:** `.github/workflows/build.yml`, `build/windows/`, `build/darwin/`, `build/linux/package.sh`, `README.md`.
**Dependency:** SEC-005 for the release candidate build; external signing credentials/accounts may be required. This task does not authorize obtaining credentials or publishing a release.

### SEC-007: Close the default SSH credential window in fresh Entware

**Status:** Closed for commit 8b83e96 CI candidates and isolated first-access fixtures; real Keenetic firmware handoff remains unverified
**Priority:** P1
**Evidence:** ARM64 bundled `bin/install` starts `S51dropbear` and advertises default root credentials. `frontend/src/ui.ts` recommends a manual password change. The actual installed package contents/password state were not independently verified.
**Attack prerequisites:** A fresh installation retains reusable default credentials and another device can reach the SSH service.
**Impact:** Root access to Entware/router storage and a foothold in the local network.

- [x] Inspect the exact downloaded account/dropbear packages and reproduce a clean bootstrap in an isolated environment. Check ARM64, MIPS, and MIPSel behavior; establish whether the advertised password is effective and when SSH begins listening.
- [x] If reusable defaults are active, implement secure first-credential setup or equivalent access restriction before SSH becomes reachable. A later warning or changing port 22 to 222 is insufficient.
- [x] Keep credential entry in the application or secure local configuration; never require the user to send passwords in chat. Preserve existing installation credentials.
- [x] Test the bootstrap-to-SSH handoff: default credentials must not provide unrestricted access, interrupted setup must fail safely, and the intended user must have a documented recovery path.
- [x] If the default-credential hypothesis is disproved, close the finding with exact package/version evidence and retain only accurate user guidance.

**Acceptance:** Either the suspected exposure is disproved with reproducible evidence, or a new installation cannot be taken over using reusable default SSH credentials during or after setup.
**Likely files:** bundled bootstrap archives and pins if changes are required, `internal/bootstrap/session.go`, `app_bootstrap.go`, `frontend/src/wizard.ts`, `frontend/src/ui.ts`, bootstrap/handoff tests.
**Dependency:** Coordinate bootstrap changes with SEC-001; do not independently replace the same reviewed archive bytes.

## Suggested execution order

1. SEC-005: establish a patched build baseline and reliable production scan results.
2. SEC-001 and SEC-007: review the bootstrap trust chain and first-access lifecycle together; retain separate acceptance decisions.
3. SEC-002: resolve the trust design and migration before implementing certificate changes.
4. SEC-003 and SEC-004: close conditional local-execution and network-exposure risks.
5. SEC-006: authenticate the final patched release artifacts before broad distribution.

Order does not authorize parallel agents or external actions. Keep every task open until its acceptance evidence is recorded.

## Closure record template

For each SEC ID record: implementation commit, affected platforms, verification commands/results, isolated manual test evidence where required, residual risks, reviewer decision, and final status. Record disproved hypotheses explicitly rather than silently dropping them. Do not put secrets or private user data in this record.

## SEC-005 execution record (2026-11-16)

- Implementation commit: `617c94d4141b88d4acf03f3905e6968d22532efa`, pushed with user authorization to `feature/installer`. No release publication performed.
- Toolchain: Go 1.26.11, confirmed in the official stable downloads catalog (`https://go.dev/dl/?mode=json`). The installed default remains 1.26.3; local verification explicitly used `GOTOOLCHAIN=go1.26.11`.
- CI: pinned govulncheck v1.9.0; source checks use Wails production tags, including `desktop`, platform WebView2 strategy, and Linux `webkit2_41`. A second gate selects exactly one built application executable, verifies its embedded Go version against the configured compiler, and scans its binary. Errors stop packaging/release; no advisory suppressions.
- Advisory disposition: GO-2026-6866 and GO-2026-6860 were reported for x/net v0.60.0; upgraded to v0.62.0. GO-2026-5932 was module-only in the source scan but blocked the stripped-binary scan for x/crypto v0.58.0; upgraded to v0.59.0 rather than suppressing it. Required transitive versions are x/sys v0.50.0 and x/text v0.44.0. The binary finding alone did not establish call-path reachability.
- Verification on macOS ARM64: `GOTOOLCHAIN=go1.26.11 go test ./...` passed all eight packages; production `go vet` passed; `npm run typecheck`, `npm test` (58/58), and `npm run build` passed. Final source govulncheck with `desktop,production,wv2runtime.download` and `-show verbose`: no vulnerabilities found.
- Rebuilt the local production app with Wails v2.17.1 (`build -platform darwin/arm64 -trimpath -skipbindings -s`, using the freshly built frontend). Embedded metadata confirms go1.26.11 and production tags. Final binary govulncheck: no vulnerabilities found. Executed the CI Python gate against the local app bundle successfully; its search root was narrowed to that bundle to exclude pre-existing binaries for other platforms.
- Independent security reviewer: first review returned a Windows production-tag mismatch; corrected. Second review found no remaining actionable defect in the diff. Reviewer explicitly requires complete platform evidence before closure.
- Full native CI evidence: [run 43769000738](https://github.com/Arap919/Xkeen-installer/actions/runs/43769000738), commit `617c94d4141b88d4acf03f3905e6968d22532efa`, completed successfully. Linux AMD64 job `132980473905`, Windows AMD64 `132980473932`, macOS AMD64 `132980474021`, macOS ARM64 `132980474040`: production source and binary scans reported no vulnerabilities; executable metadata confirmed go1.26.11 and expected GOOS/GOARCH/tags; all eight Go packages, vet, frontend typecheck, 58 tests, frontend build, native desktop build, packaging and upload passed. Release job was skipped. Old local and published binaries remain outside this verification.
- Final reviewer decision: independent security specialist retrieved all four native job logs, confirmed the checked-out commit, tests, source/binary scans, embedded toolchain and target metadata, and recommended closure. No unresolved advisory remained in these scans.
- Final status: CLOSED for the new CI candidates. Broad distribution remains gated by the other open SEC findings, including SEC-006. No real-router installation or exploitation was performed.

## SEC-001 delivery design proposal (2026-11-16)

Current trust-chain trace:
- All three bundled archives authenticate their compressed bootstrap bytes through catalog SHA-256 pins, but each bin/install subsequently runs opkg update and installs 17 named base packages plus their dependency closure through two HTTP feeds. The same scripts start Dropbear; credential hardening remains SEC-007.
- The later installer runs opkg update and installs selected dependency names in internal/install/runner.go. Installing the reviewed watchdog IPK can also resolve transitive dependencies. Existing feed configuration and TLS downloader behavior are not currently validated.
- Upstream opkg packaging leaves signature-check configuration commented out. A post-bootstrap HTTPS URL edit alone cannot authenticate the earliest fetch.

Proposed design: bundle an independently reviewed, immutable offline package repository for each architecture, including the complete bootstrap and installer dependency closure. Fetch source metadata and packages over certificate-validated HTTPS during bundle preparation, verify package hashes before inclusion, record package/version/digest provenance, and pin final deterministic archive bytes. During initial bootstrap, opkg may read only that local repository. During later installation, transfer the same reviewed local repository over the authenticated SSH transport and invoke opkg with an explicit private config containing only that local source. Package hooks must be reviewed for their own downloads and tested with network access denied. Missing or modified local metadata/packages fail before installation; no network fallback. Reject insecure existing feed configurations with Russian migration guidance before opkg runs, without silently rewriting user files. Preserve existing approval, backup, and archive/path checks.

Alternative: provision a verified TLS-capable downloader and CA material into the initial archive, and strictly validate all feed URLs, redirect behavior, downloader flags/environment, and trust material before any opkg call. This is smaller on disk but makes the router downloader, runtime libraries, TLS settings, and repository changes part of the installation trust boundary.

Recommendation: offline reviewed package closure. Tradeoff: larger desktop packages and a maintainer-controlled package refresh process; authentication no longer depends on the router having working TLS before installation. Existing configurations are preserved. This does not authorize release publication or changing a real router.

Required verification: isolated package tampering, metadata tampering, missing package/trust data and no network fallback; actual opkg bootstrap/install fixtures on ARM64, MIPS and MIPSel; independent security review before closing SEC-001. The design is a proposal, not an implemented fix.

## SEC-001 implementation checklist

Approved by the user: offline reviewed package closure, as proposed above. Work remains in the existing checkout. Implement locally, then use a separate security reviewer; no release publication.

- [x] Add `scripts/entware_bundle.py` and focused Python fixtures: HTTPS-only bounded downloads with downgrade rejection; strict repository parsing and dependency closure; separately reviewed lock metadata; deterministic offline bundle generation with pinned original archives and IPK hashes. Tests must reject tampering, untrusted certificates, missing trust material and missing dependencies without a network fallback.
- [x] Generate per-architecture locked repositories, inspect all package installation hooks for network fetches and credential/service side effects, then update the three bootstrap archives, catalog pins and `docs/entware-byte-pins.md`. Initial opkg calls must use only the local repository.
- [x] Add authenticated offline-repository extraction in `internal/bootstrap`, preserving existing archive validation. Add negative fixtures for changed/missing metadata, modified IPKs and unsafe paths.
- [x] In `internal/install/runner.go`, validate existing feed configuration before package/service mutations, stage the verified local repository through the existing SSH transport, and use an explicit local-only opkg config for dependencies and watchdog hooks. Keep backups and existing configuration. Add tests that an HTTP feed or missing trust material stops before opkg and that no command uses network feeds.
- [x] Run Go/frontend checks and isolated clean/existing opkg tests on ARM64/MIPS/MIPSel with network denied. Obtain independent security review, fix findings, record remaining evidence honestly, then close SEC-001 only if its acceptance is met.

Initial environment observations (subsequently resolved for isolated verification): HTTPS requests to bin.entware.net timed out during TLS negotiation on this host; Docker client exists but its daemon socket is unavailable. These are verification blockers, not permission to use HTTP or disable certificate checks.

## SEC-001 execution record (2026-11-16)

- User approved offline delivery design and sequential implementation/security review. Implemented in the existing checkout; no worktree, real-router mutation, trust-store import or release publication.
- Acquisition: CI run 43849821304 fetched official package metadata and IPKs with validated HTTPS; current locks contain ARM64 78, MIPS 79 and MIPSel 79 packages. IPK hashes/sizes and complete version-constrained dependency closure verified; ca-certs provider is explicitly ca-bundle. Final derived catalog version is offline-2026-11-16, with bundled:// origins. Exact source/final provenance and reproduction are in docs/entware-byte-pins.md.
- Bootstrap: all package metadata/IPKs are local. Explicit opkg config, env -i, fixed PATH and OPKG_CONF_DIR prevent extra feeds. Whole-archive SHA256, archive/path/symlink/ELF safety checks and individual IPK/index checks remain fail-closed. SMB readback bound increased from 16 to 64 MiB for the approximately 23 MiB archives; decompression/member limits unchanged.
- Existing installs: reject HTTP, disabled certificate checks, unsupported quoted config, extra unknown functions.sh callbacks, incomplete status, and version changes with old unknown hooks before writes. Exact dependency closure is staged/read back over SSH with private config/lists; both dependencies and watchdog use it. State rechecked before installs. No user feed/config rewrite or automatic package repair.
- Independent review returned and resolved: version constraints ignored; cross-architecture/feed locks accepted; locales HTTP fallback; unrelated unpacked hooks/old upgrade callbacks; quoted directive parsing. Each reproduced with negative tests before its fix. Final reviewer recommends closure for the reviewed scope. A final UI-path check also found generic error hiding; four allowlisted static package-policy errors now reach the UI without wrapped/unknown private error text; app regression passed and reviewer approved this fix.
- locales transformation: exact original hook digests pinned; only HTTP fallback replaced by Russian error/exit 1. data.tar.gz and other control members unchanged. Source and derived package hashes recorded separately. Independent reviewer reproduced all final archives byte-for-byte and verified their catalog pins.
- Checks: full Go suite (eight packages), production vet, frontend typecheck/58 tests/build, Python 20 security tests including real untrusted TLS and HTTPS-to-HTTP redirect with zero HTTP-target requests, remote package readback tampering, and git diff --check passed.
- Isolated execution: real bin/install and full dependency installation succeeded on ARM64, MIPS, MIPSel with network disabled. Final TestNativeOfflinePackagePhase passed ARM64 2.58s, MIPS 31.50s, MIPSel 36.34s, including the pinned watchdog IPK, hostile env/additional configs/stale lists, blocked unfinished/old hooks, harmless reproduction of the previous unrelated-postinst path, and forced locales generation failure. proot 5.5.0/QEMU used only in Docker; older broken proot excluded from evidence.
- Evidence limits: isolated Linux userspace only; real Keenetic hardware, firmware extraction/RCI and SSH credential handoff were not validated. Existing compromise or concurrent root-level package administration is not attested by these checks. SEC-007 remains separate; no distribution approval is implied.
- Ruling: existing read-only discovery with opkg list-installed is retained; the new gates precede package update/install and hook execution. That query does not fetch packages or configure pending hooks.
- Final status: CLOSED for implementation commit 0165371e131a0824ef50470f85efe27ef763f92c plus packaging fix f9be0b242963b0cbc0b0e50c43f63ebc497322c3, subject to the evidence limits above.

### SEC-001 desktop packaging follow-up (2026-11-17)

Implementation commit 0165371e131a0824ef50470f85efe27ef763f92c was pushed; a large
HTTP push initially failed and succeeded with a command-local 128 MiB postBuffer
without disabling TLS or changing global Git settings. CI run 43947013140 passed
Linux/Windows and all macOS Intel source/binary checks, but DMG creation failed
with No space left on device while copying the larger executable into its mounted
image. The same step failed again on a fresh Intel runner. Local ARM64 automatic
DMG creation succeeded with 95 GiB host space available; the failure is not claimed
to reproduce on every OS. The packaging follow-up explicitly sizes the image from
logical regular-file bytes plus 64 MiB metadata headroom, excluding symlinks;
format, app contents, release conditions and security gates are retained. Final
native CI is still required. The first ARM64 queued job was cancelled by GitHub
when a new single-job attempt was created; it was not a passing ARM64 result.

### SEC-001 final closure (2026-11-17)

- Final native CI [run 43963707188](https://github.com/Arap919/Xkeen-installer/actions/runs/43963707188) succeeded on exact head f9be0b242963b0cbc0b0e50c43f63ebc497322c3. Jobs: macOS ARM64 133637599216, macOS AMD64 133637599264, Windows AMD64 133637599339, Linux AMD64 133637599402.
- Independent security reviewer read all four complete job logs and verified checkout SHA, embedded Go 1.26.11, expected GOOS/GOARCH and consistent production source/binary tags. Both govulncheck gates reported no vulnerabilities on each platform; Go tests/vet and frontend 58/58 tests passed.
- Both DMGs were created/uploaded (explicit capacity 145 MiB ARM64, 146 MiB Intel); Windows NSIS and Linux DEB were uploaded. All four artifact records bind to the same SHA. Release skipped; no publication.
- Reviewer confirmed closure for the reviewed candidates and isolated userspace fixtures. Real Keenetic firmware extraction/RCI/SSH handoff and previously distributed binaries remain outside this evidence.

## SEC-007 initial verification (2026-11-17)

- Read-only inspection of the exact bundled packages: opt-ndmsv2 1.0-17 on all three architectures contains identical root account data (passwd file SHA256 51f28bc4f23398131fac87e065825e7349621ea1b5d3f141bb1570b28e0f250b).
- Disposable network-denied Linux containers compared crypt(advertised default, stored hash): true for ARM64, MIPS and MIPSel. Only boolean outcomes were printed; no account hash or private host key was logged.
- Dropbear 2026.94-4 has identical S51dropbear SHA256 3a531c9a5f4aab0797ae8d40d0235966100ec13139a4bbe2078cbc76d0d1ee4e. It invokes dropbear with port and pidfile only, without disabling password authentication. Its postinst generates missing host keys but does not start the service; bin/install explicitly starts it after key regeneration.
- This establishes reusable account credentials and the configured startup path, not real-router reachability or a successful remote login. Full isolated bootstrap-to-SSH tests remain required. No SEC-007 product code changed.

## SEC-007 implementation progress (2026-11-17)

- User approved the password-first design in docs/superpowers/specs/2026-11-17-sec007-first-password-design.md and its implementation. Work remains in the same checkout; no router/trust/release changes.
- Added transient fresh-only password/repeat fields, identical frontend/backend limits, SHA-512-crypt v1.0.6 (100000 rounds, random 16-character salt), private one-shot hash state and bounded signed-SMB sidecar with exact readback before firmware trigger. No public plan/error contains the hash.
- Added positive-ready Dropbear startup guard, root account and regenerated-host-key binding, readiness revocation/service stop before package passes, and a pinned fresh account derivative that locks root until the selected hash is installed. Existing installer dependency closure refuses fresh account/SSH packages before writes.
- Independent specialist found a shared signal cleanup trap that could continue after TERM. A real ARM64 keygen fixture reproduced it; separate EXIT cleanup and terminating signal handlers now replace it. Final fixture rerun remains pending.
- Initial ARM64 real bootstrap/auth and offline package-phase checks passed. MIPS/MIPSel normal daemon processes under PRoot/QEMU accepted TCP but closed before auth; these EOF results are not recorded as password rejection. Target MIPS libcrypt independently matched the selected hash in 0.41s and root lookup matched the installed account. Exact-binary inetd fixtures are being evaluated without changing production daemon behavior.
- Full Go suite, production vet, frontend suite and source govulncheck passed at intermediate snapshots. Final snapshot, all-architecture acceptance, independent re-review and native desktop CI are still required before closure.

### SEC-007 final local acceptance (2026-11-17)

- Full network-denied fixture wrapper exited 0. ARM64 FirstAccess 20.79s / OfflinePackagePhase 2.55s; MIPS 62.69s / 29.81s; MIPSel 71.03s / 30.17s. Exact Dropbear accepted the selected password, rejected default/wrong credentials at the protocol auth step, and passed missing/stale readiness, TERM during keygen, keygen failure and safe completion checks.
- MIPS/MIPSel auth uses direct QEMU normal Dropbear and its built-in fork fallback after fexecve Exec format error; bootstrap/init/package tests use PRoot. These packages lack inetd support. Failed PRoot EOF attempts are excluded from positive evidence; native MIPS reexec and real Keenetic firmware/RCI/handoff remain outside isolated evidence.
- Final local suite: eight Go packages, production vet, 23 Python security tests, frontend typecheck/63 tests/build and git diff --check passed. New dependency is pinned github.com/sergeymakinen/go-crypt v1.0.6. Production source govulncheck clean; rebuilt macOS ARM64 binary scan pending/final CI gates authoritative for shipped candidates.
- Separate security specialist confirmed the signal finding corrected, reviewed precise failure assertions and one-shot approval lifecycle, independently reproduced all three final archive bytes/pins, and reported no unresolved concrete finding. Closure waits for native desktop CI; no release or router mutation performed.

### SEC-007 final closure (2026-11-17)

- Implementation commit 8b83e9608cf1040412f99f5df4c895475b73d623 was pushed to authorized feature/installer. [Native CI run 44097652083](https://github.com/Arap919/Xkeen-installer/actions/runs/44097652083) completed successfully on that head; release skipped.
- Native jobs succeeded: macOS AMD64 134089092569, macOS ARM64 134089092574, Linux AMD64 134089092683, Windows AMD64 134089102954. Root retrieved complete CI logs and verified source and binary govulncheck both report no vulnerabilities on each platform; embedded Go 1.26.11, expected GOOS/GOARCH and production tags; frontend 63/63 tests; successful packaging/upload. macOS DMG capacity 146 MiB Intel / 145 MiB ARM64.
- Artifact upload IDs: macOS AMD64 14335790806, macOS ARM64 14333879620, Linux AMD64 14333709919, Windows AMD64 14335550363.
- Reviewer independence: the separate security specialist independently reviewed code and test boundaries, confirmed the signal fix, and reproduced all three final archives byte-for-byte. The reviewer recommended closure with no unresolved concrete code defect. Their separate CI network retrieval did not complete; CI conclusions above are root's direct log verification, not an independent reviewer log audit.
- Final status: CLOSED for these CI candidates and the recorded isolated runtime scope. Existing installations keep credentials; legacy distributed binaries, real firmware extraction/RCI/SSH handoff, native MIPS reexec and arbitrary concurrent root-level storage/package modifications remain outside this evidence. Signed SMB does not provide confidentiality for the transferable password hash; the approved design requires a long separate password. Broad release remains gated by the other open findings. No release, real-router change or system trust import performed.
