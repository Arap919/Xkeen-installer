# Cron and multiple subscriptions implementation plan

**Goal:** Install cron automatically and support up to ten Mihomo or Xray JSON subscriptions through step six, preserving existing installations.
**Architecture:** Keep Mihomo native HTTP providers. Resolve Xray JSON subscriptions before plan review and retain their URLs in a private managed file for a Python updater scheduled every twelve hours. Import only proxy outbounds into the embedded base; use the first suitable node initially. Validate updates before atomic replacement and retain the working file on failure.
**Tech stack:** Go/Wails, TypeScript, Entware cron, Python 3 for the router-side Xray updater.
**Spec:** User-approved design in this conversation (2026-11-07).

## Constraints
- Ten URLs total per core, HTTPS only, no personal URL embedded or printed.
- Mihomo names VPNProvider, VPNProvider1 through VPNProvider9; Proxy and BENCHMARK use all providers; retain requested headers, interval, health check and overrides.
- Xray inputs: one JSON configuration containing outbounds, or an array of those configurations. Preserve base DNS/routing and import proxy outbounds only.
- Existing user configurations and cron jobs remain intact; unmanaged or ambiguous cron layouts must not be silently replaced.
- No router mutation during development. Router changes appear in a concrete one-shot reviewed plan and run only after backup.
- Preserve existing uncommitted work. No worktrees, commits, pushes or publication.

## Task 1: Subscription backend and updater
- [x] Add failing tests for 1/10/11 subscriptions, invalid HTTPS/JSON, redaction, existing-config preservation, Xray proxy-only import and first-node activation.
- [x] Extend Go configuration imports and request bridge for Mihomo and Xray URL lists; bounded Xray JSON fetch before plan review.
- [x] Add managed Xray sources and updater with bounded HTTPS requests, a lock, validate-before-replace, failure preservation and restart recovery.
- [x] Integrate exact managed payloads into plan, backup, inventory and runner; add twelve-hour cron job without overwriting user jobs.
- [x] Verify targeted Go and updater tests; independent review.

## Task 2: Automatic cron
- [x] Add cron to dependencies and reviewed service steps; remove requirement that S10cron must exist before installation.
- [x] Detect existing conflicting daemon layouts; preserve existing jobs/configs; start and verify the exact cron service after dependencies.
- [x] Verify fresh-install, existing-install and failure/order regression tests; independent review.

## Task 3: GUI and packaging
- [x] Step six exposes independent per-core URL lists, add/remove buttons, maximum ten, clears secrets on end/unload and invalidates prepared plans on edits.
- [x] Verify GUI tests and typecheck; review backend/GUI integration.
- [x] Build macOS ARM64 ZIP, verify embedded Mihomo/Xray templates and archive, report device-validation boundary.

## Progress
- Design approved; backend and GUI implemented. Backend review and scoped hash re-review passed. Final integration review PASS; native macOS ARM64 build PASS.

Backend tasks 1–2 implemented. Review round 1 identified node-edit ownership overwrite; exact config SHA256 metadata fix applied by root after child approval stalled. Focused config/updater and install/cron tests passed after fix. Scoped re-review pending; GUI task pending. Race run rejected and not retried.

Task3 source complete: wizard26/26 and full frontend29/29 PASS, TypeScript PASS. Full Go suite PASS after hash fix. Final template contract corrected with RED/GREEN and shared provider prototype; config/install tests pass. Race not rerun. Native checks use macOS binary and actual pinned MIPSel ZIP geobases, not router execution.

Completion: backend task review and exact-hash re-review PASS; frontend task review PASS; final feature review P2 fresh-restart guard fixed with RED/GREEN and scoped re-review PASS. Full Go8-package suite passed after hash integration, frontend29/29 and TypeScript passed; changed config/install suites passed after final guard. Mihomo1.19.33 and Xray26.10.31 native config validation passed with local geodata. macOS ARM64 Wails build passed; embedded Mihomo/Xray/updater and new GUI markers verified. Race denied and not rerun. No physical-router, remote CI, Windows/Linux GUI runtime or publication checks.

## Subscription diagnostics follow-up

User rejected combined step6 error text. Root tracing proves Mihomo-only resolver performs URL validation, not fetch/JSON; actual failing URL unknown. Implemented safe enum diagnostics with core/stage/one-based source/reason/status; App and GUI preserve code, use fixed whitelisted Russian messages and reject unsafe/unrecognized metadata. Separate known input/configuration/state/TLS preparation stages. RED generic errors reproduced in config/App/GUI. GREEN full Go8packages, frontend37/37, TypeScript. Independent review and rebuilt ZIP pending. No real subscription or router tested.

Diagnostics follow-up complete: independent scoped review Spec PASS / Quality PASS. Full Go8packages PASS; frontend37/37 and TypeScript PASS. Native macOS ARM64 build PASS; both core templates, updater and new diagnostics markers verified in binary; old combined subscription error removed. Actual user URL failure remains unconfirmed until redacted diagnostic from updated app; no secret requested and no real subscription/router accessed.

## Mihomo URL fragment follow-up

Real user failure FRAGMENT/2 reproduced. Both subscription validation and repeated provider/watchdog validation now accept Mihomo URL fragments and preserve exact URLs; label Unicode/spaces accepted, request-path/query whitespace and controls remain rejected. Xray policy unchanged. RED full Prepare cases failed FRAGMENT and WHITESPACE before fix; config/install/app tests and native Mihomo1.19.33 fragment fixture PASS after fix. Independent scoped review PASS. Native macOS ARM64 rebuilt; core templates/updater verified embedded. No real subscription/router accessed.

## Progress and authentication follow-up

Progress events now update one row per unique stage; normal plan uses real unique completed-stage count in semantic progress bar and escaped planned descriptions. Raw progress Message is not shown. New normal/bootstrap runs reset progress; completed state resists late running; terminal events route once. Bootstrap real running-only protocol advances prior received markers without marking waiting-shell/terminal as confirmed Entware readiness. RED4initial+2protocol regressions; GREEN fullfrontend44/44, TypeScript. Independent review and scoped bootstrap re-review PASS. Native macOS ARM64 rebuilt; core templates/updater and progress markers embedded.

Password diagnosis: anonymous read-only public API at expected router UI endpoint returned HTTP200 enabled=false,has_password=false,authenticated=false. Peer certificate matched installer certificate. First strict Python TLS probe failed certificate verification; separate explicitly approved anonymous diagnostic used no credentials. Pinned UI1.4.2+pwa.1 source confirmed auth defaults disabled and failed auth fetch displays login. No router configuration/password mutation, no UI artifact/version change. Browser-specific failure not captured; reload while API is available is required to re-evaluate current auth state.
