# Automatic CA trust implementation plan

Goal: installer handles local CA trust for macOS and Windows as part of UI completion, with explicit exact-CA approval and native OS authorization, followed by verified system HTTPS.

Constraints: preserve existing router TLS/configs/passwords and current private CA storage; never import CA private keys; no trust mutation during tests or builds. Reuse one-shot reviewed TrustAction boundary. Skip prompts when system-trusted HTTPS already passes. Retain manual fallback for external/unavailable CA and Linux behavior. No worktrees, commits, pushes or releases.

- [ ] Backend: macOS administrator authorization via fixed AppleScript and quoted argv to /usr/bin/security; Windows certutil CurrentUser Root; friendly exact-CA/platform description and truthful failures. Tests for argv quoting, approved/refused/tampered CA and platform commands; no real store changes.
- [ ] Completion UX: automatic verification after UI install, automatic exact-CA approval dialog only when expected TLS/API passes and system trust does not; apply then reverify; clear result on rejection/error without claiming browser readiness; retry from result screen; prevent duplicate prompts/events and preserve no-UI/bootstrap flows.
- [ ] App verification: only expose PanelURL after verified system trust, HTTPS and API success. Preserve existing API approval guard; no trust command from preview/Verify alone.
- [ ] Root verification: targeted Go/GUI tests, Windows cross-compile of TLS tests, independent review, macOS ARM64 build and ZIP integrity/template assertions. Windows runtime remains untested on this host.
