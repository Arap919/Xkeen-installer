# SEC-007 First Password Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Execute in the existing checkout; the user authorized implementation and a separate security review.

**Goal:** Prevent reusable default SSH credentials throughout fresh Entware bootstrap.
**Architecture:** Desktop hashes the user password; signed SMB publishes a bounded plan/volume-bound sidecar independently of canonical archives. Fresh-only Dropbear package/init requires positive readiness bound to the current root account and regenerated host keys. Existing package installation must never select this fresh-only package.
**Tech Stack:** Go, SHA-512-crypt, TypeScript, Python deterministic IPK/tar transformations, Entware ash, isolated Docker/QEMU.
**Spec:** docs/superpowers/specs/2026-11-17-sec007-first-password-design.md

## Global Constraints
- Password: at least 16 Unicode code points, at most 1024 UTF-8 bytes; no NUL/CR/LF; matching repeat; no persistence/logging/argv.
- No real-router changes, worktrees, release, or trust-store changes.
- Preserve SEC-001 source provenance, offline-only execution, archive validation, and existing credentials.
- Missing readiness fails closed, including reboot and stale account/key material.

## Review Focus
- Partial SMB publication must never permit firmware trigger.
- Fresh package transforms must not reach existing installation dependencies.
- Interrupted package/configuration passes must not leave stale readiness.
- Password changes must invalidate frontend review without retaining plaintext.
- Missing host key regeneration must prevent SSH startup.

### Task 1: Desktop credential and SMB publication
**Files:** internal/bootstrap/credential.go, credential_test.go, session.go/session_test.go, smb.go/smb_test.go, app_bootstrap.go.
**Interfaces:** Prepare(ctx, uuid, password, repeat) returns Plan; Credential stores PlanID/UUID/Hash privately, serializes a bounded newline-delimited payload; Store credential publication/check follows archive publication and precedes firmware trigger.
- [x] Write/run negative password, random salted hash, payload binding, foreign/symlink/readback and trigger-on-failure tests (RED).
- [x] Implement SHA-512-crypt using a pinned external implementation; fixed bounded rounds, random salt. Implement exclusive publication/readback and one-shot private credential lifecycle.
- [x] Run bootstrap and app suites (GREEN).

### Task 2: Fresh bootstrap service gate and reviewed archives
**Files:** scripts/entware_bundle.py, scripts/test_entware_bundle.py, fresh gate/bootstrap shell scripts, internal/catalog/catalog.go, internal/bootstrap/archives/*, internal/install/offline.go tests.
**Interfaces:** sidecar /opt/.xkeen-bootstrap-credential; fresh gate /opt/etc/xkeen-bootstrap/; readiness is checksums of current passwd and new host keys; transformed dropbear retains the upstream identity for bootstrap; the existing installer rejects dropbear/opt-ndmsv2 in its selected dependency closure before writes.
- [x] Write/run real shell gate fixtures for missing/malformed/stale readiness and credential payload (RED).
- [x] Implement pinned minimal package transformations and bootstrap order: revoke readiness, install account, hash, keys, readiness, start. Keep canonical provenance and immutable sidecar validation.
- [x] Rebuild all three deterministic archives from source locks/original archives; update exact pins.
- [x] Verify Python and Go suites (GREEN); ensure existing dependency closure rejects fresh-only service/account packages.

### Task 3: Wizard and handoff
**Files:** frontend/src/wizard.ts, ui.ts, bootstrap.test.ts, Wails App bindings, README.md.
**Interfaces:** PrepareBootstrap(uuid,password,repeat); frontend bootstrapPassword/bootstrapPasswordRepeat transient fields, cleared on prepare attempt/mode change/session end.
- [x] Write/run mismatch/length/clearing/invalidation and rendered fields tests (RED).
- [x] Add Russian fields/guidance; backend validation remains authoritative, public errors static.
- [x] Run typecheck, frontend full suite/build, app tests (GREEN).

### Task 4: Isolated acceptance, recovery, security review
**Files:** scripts/check_entware_offline.sh, focused Linux fixtures, docs/entware-byte-pins.md, existing remediation plan.
- [x] Real bootstrap and SSH password auth for all architectures with network denied except isolated loopback fixtures; default/wrong passwords rejected, intended password accepted.
- [x] Test package-pass interruption/reboot, stale ready after account/key overwrite, missing sidecar, recovery commands, unchanged existing credentials.
- [x] Full Go/frontend/Python verification, deterministic reproduction, production vet/scans; separate security review and remediate findings.
- [x] Commit/push authorized feature branch and run desktop CI; record evidence before SEC-007 closure.

## Execution evidence (2026-11-17)

- Implemented in existing feature/installer checkout. A bounded worker implemented credential hashing/UI and fixture diagnostics; a separate security specialist reviewed source, test boundaries and final archives.
- Ruling: transformed account/SSH packages retain their upstream package identities for the canonical bootstrap; normal installation rejects those names in its full selected closure before writes, instead of introducing new virtual-provider identities.
- Ruling: exact MIPS/MIPSel Dropbear packages do not support inetd. PRoot accepted connections but its child execution closed before auth. Direct QEMU normal server successfully uses the unchanged binary's documented fork fallback after fexecve Exec format error. The wrapper still tests bootstrap/init via PRoot. Native MIPS reexec and real Keenetic firmware remain unverified; no product bytes or flags were weakened for the emulator.
- SSH negatives require protocol authentication failure, never EOF. Intended password requires a successful handshake. Test wrapper preserves Dropbear multicall argv0 with exec -a for precise TERM injection.
- Final bash scripts/check_entware_offline.sh exit 0: ARM64 first access 20.79s/offline phase 2.55s; MIPS 62.69s/29.81s; MIPSel 71.03s/30.17s. Tests include missing/stale state, wrong/default passwords, TERM after passwd during keygen, keygen failure and safe completion.
- Local final checks: Go eight packages, production vet, Python 23/23, frontend typecheck/63 tests/build, diff whitespace passed. Source govulncheck found no vulnerabilities. Independent reviewer reproduced all three final archives byte-for-byte and found no remaining concrete source finding. CI remains pending.

## Closure

Implementation 8b83e9608cf1040412f99f5df4c895475b73d623; CI 44097652083
all four native targets passed, release skipped. Root verified complete logs,
source/binary scans, embedded toolchain/tags and uploads. Independent specialist
reviewed code, tests and reproducible final archives; their CI network retrieval
did not complete. No unresolved concrete code finding remains. SEC-007 closed
within the isolated runtime/CI-candidate evidence limits recorded in the parent
remediation plan; no real-router or release action performed.
