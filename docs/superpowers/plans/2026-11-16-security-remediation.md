# Security Remediation Plan and Audit Register

**Audit date:** 2026-11-16
**Status:** Remediation in progress; SEC-005 closed for the new CI build candidates. Other findings remain open. No exploitation demonstrated.
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

**Status:** Open
**Priority:** P1
**Evidence:** `internal/bootstrap/archives/{arm64,mips,mipsel}.tar.gz`, members `etc/opkg.conf` and ARM64 `bin/install`; `internal/install/runner.go`, dependency stage; `internal/catalog/catalog.go`.
**Attack prerequisites:** An attacker can alter the router's HTTP download traffic or responses. Unauthenticated package metadata can defeat checksums delivered through the same channel.
**Impact:** Potential root code execution on the router through substituted packages/install hooks, followed by attacks on the home network. Desktop execution was not demonstrated.

- [ ] Trace every initial-bootstrap and later opkg fetch, including transitive dependencies and repository metadata; document its authentication mechanism.
- [ ] Select and implement authenticated bootstrap delivery that works before CA/TLS packages are installed. Merely changing the post-bootstrap feed URLs is insufficient.
- [ ] Enforce certificate validation and/or independently trusted package signatures/digests for executable package content. Reject insecure feeds used by existing Entware installations before invoking opkg, with actionable Russian guidance.
- [ ] If bundled bytes change, update archive size/digest pins and `docs/entware-byte-pins.md`; preserve archive safety validation.
- [ ] Test tampered metadata/package bytes, HTTP downgrade, untrusted certificates, and missing trust material. Each must stop before executing untrusted package hooks; no insecure fallback.
- [ ] Validate an isolated clean installation and an existing installation for ARM64, MIPS, and MIPSel.

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

**Status:** Open; verify effective credentials first
**Priority:** P1
**Evidence:** ARM64 bundled `bin/install` starts `S51dropbear` and advertises default root credentials. `frontend/src/ui.ts` recommends a manual password change. The actual installed package contents/password state were not independently verified.
**Attack prerequisites:** A fresh installation retains reusable default credentials and another device can reach the SSH service.
**Impact:** Root access to Entware/router storage and a foothold in the local network.

- [ ] Inspect the exact downloaded account/dropbear packages and reproduce a clean bootstrap in an isolated environment. Check ARM64, MIPS, and MIPSel behavior; establish whether the advertised password is effective and when SSH begins listening.
- [ ] If reusable defaults are active, implement secure first-credential setup or equivalent access restriction before SSH becomes reachable. A later warning or changing port 22 to 222 is insufficient.
- [ ] Keep credential entry in the application or secure local configuration; never require the user to send passwords in chat. Preserve existing installation credentials.
- [ ] Test the bootstrap-to-SSH handoff: default credentials must not provide unrestricted access, interrupted setup must fail safely, and the intended user must have a documented recovery path.
- [ ] If the default-credential hypothesis is disproved, close the finding with exact package/version evidence and retain only accurate user guidance.

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
