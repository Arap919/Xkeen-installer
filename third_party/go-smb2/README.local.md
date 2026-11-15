# Local SMB no-replace delta

This directory contains the production Go sources, license and module metadata
from github.com/cloudsoda/go-smb2 at commit
7b96c35f5f4babfc9d68a60baf5e85f2303d4a4b
(version v0.0.0-20260609183447-7b96c35f5f4b).

The upstream module checksum retained by the parent module is:
h1:VE/gRw9Mahc4LRVqcCr/+boMTCD/5g97ioBKlGER8Yw=

UPSTREAM.json lists the SHA256 and size of each original file. Copy exactly those
files from the verified pinned module before applying the local client.go delta.
Upstream tests, CI, examples and the ignored status-code generator are omitted.
Their omission changes no production package. No module-cache file is modified.

The only production source delta is in client.go:

- Existing Share.Rename delegates to the shared rename implementation with
  ReplaceIfExists=1, retaining upstream behavior.
- New Share.RenameNoReplace delegates with ReplaceIfExists=0.
- The shared implementation puts that value in FileRenameInformationType2Encoder.
  All path validation, reparse-point opening, handle cleanup and response handling
  remain the existing upstream code.

The exact patched client.go SHA256 before any unrelated formatting is:
f0332dad2607e88ac63ce9d29c31c82280154436c2e563c4beb9739dc33a14df

The parent module replaces this dependency locally and calls RenameNoReplace
directly. There is no dynamic optional-method fallback. This removes the
check-then-overwrite race for installer archive publication.

The wire regression uses a net.Pipe with the production connection/session/share
chain and real CREATE, SET_INFO and CLOSE encoders. It verifies the zero replace
flag, success for an absent target, collision propagation and preservation of
foreign target bytes, plus retention of legacy Rename overwrite behavior.
Negotiation and authentication are intentionally outside this established-session
fixture. A real SMB server and Keenetic device still require separate validation.

To reproduce: download the exact pinned module with Go tooling, verify every
UPSTREAM.json original hash, copy the listed files, then apply the small client.go
delta described above. Only client.go may differ from the original manifest;
README.local.md, UPSTREAM.json and rename_noreplace_test.go are local additions.

Run the local regression explicitly because a parent go test ./... does not enter
nested modules:

    cd third_party/go-smb2
    go test -race -run TestRenameNoReplaceWirePreservesCollision .

Run parent-module Go tests separately after applying its local replace directive.

