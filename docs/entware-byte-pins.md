# Entware byte-pin provenance

## Original upstream inputs

Reviewed on 2026-11-07. These are installer-maintainer pins of the exact compressed
bytes fetched over HTTPS from the official Entware URLs. Entware did not publish
these SHA256 values in the reviewed source. They are not publisher signatures,
upstream checksum statements, release versions, or evidence of successful device
installation. A changed upstream archive intentionally requires another review.

| Architecture | URL | Compressed bytes | SHA256 |
| --- | --- | ---: | --- |
| arm64 | https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz | 3232671 | 64451a3a70ca85aaab3b0677814f6b58f7994793ed6b120eddc36a16639c15d1 |
| mipsel | https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz | 3304180 | 44d94db8b4eb0ccd950552bc71c17ae50777dcac89f8aae949d7140c55e76c9f |
| mips | https://bin.entware.net/mipssf-k3.4/installer/mips-installer.tar.gz | 3503782 | a8ca977def91f1a12ab4675e20e89a4c05700cb932ef9e41b88e5cb8388f8fe2 |

The controller downloaded the archives to /tmp/xkeen-entware-{arm64,mipsel,mips}.tar.gz
for this review without executing them. Tests must remain independent of these
temporary files and network availability. Catalog verification binds canonical
metadata, exact compressed size and SHA256; separate archive validation checks
safe paths and target ELF architecture before publication.


## Installer-derived offline snapshot: 2026-11-16

These are the current shipped bytes, not byte-identical upstream archives. Catalog
URIs use `bundled://entware/2026-11-16/<arch>.tar.gz`; initial setup performs no
Entware HTTP requests. Source archives above retain their own independent pins.

| Architecture | Packages | Compressed bytes | Final SHA256 |
| --- | ---: | ---: | --- |
| arm64 | 78 | 23925092 | 84155665caeeb509feb7c373c698d456f6cc3ce7a0c0af6b77fce9a2f1672df6 |
| mips | 79 | 23855348 | 15ac0d03f8369aedd15d62ad361f1595705be47e40693903c1a3b2d248caa06d |
| mipsel | 79 | 23554566 | 1b6037a43a6a386677e879dd779c41d23d338b93ffbf5ad7ca9ca0ef473a05ba |

Acquisition evidence: [CI run 43849821304](https://github.com/Arap919/Xkeen-installer/actions/runs/43849821304).
Package indexes and exact IPK bytes were fetched only from certificate-validated
`https://bin.entware.net/<architecture>` and its `/keenetic` feed. Each IPK size and
SHA256 is checked against that authenticated index. The reviewed input lock is
embedded as `etc/xkeen-offline-source-lock.json`; it records versions, full
stanzas, architecture-specific URLs, SHA256, dependency roots and the explicit
virtual provider `ca-certs: ca-bundle`. Metadata includes version constraints,
which the preparation tool checks using opkg version ordering. No HTTP, foreign
redirect, checksum-only HTTP metadata, insecure certificate flag or missing-CA
fallback is allowed. Retrying a TLS timeout never changes the URL or trust policy.

The complete bootstrap and optional installer dependency closure is embedded in
`.xkeen-installer-repository/` with mode 0700 on its root. Its `Packages` file,
IPKs and format-2 `reviewed-lock.json` describe the final local bytes. The original
format-1 acquisition lock cannot be confused with this derived manifest.

The locales package hook is deliberately changed: `locales` 2.27-9 postinst previously
called HTTP wget if localedef failed to create its archive. The transformation
`locales-no-network-fallback-v1` replaces only that fallback with a Russian error
and exit 1; its data.tar.gz is preserved byte-for-byte. The original postinst
hash must match cb04a9323a9995fc0dd79ae73aa7e3a711167131f8caae88eb7a948b1f80d361
(ARM64/MIPSel) or 658ed52ae794cea7ed6257b4a6aac5a3dfd7b7e863a4807bab81d5136591d775
(MIPS), otherwise preparation fails pending a new review. The final manifest
records source_url, source_size, source_sha256 and transformation beside the
new package size/digest. These modified packages are installer-maintained
derivatives, not claims about upstream-published bytes or signatures.

Bootstrap bin/install uses an explicit local-only configuration, an empty inherited
environment, a fixed PATH and OPKG_CONF_DIR pointing only to its private repository.
The normal initial opkg.conf also contains only that local source. The desktop
installer revalidates the embedded bundle, transfers and reads back its local
repository over authenticated SSH, and uses a private per-plan opkg configuration
and lists directory for dependency and watchdog IPK operations. Existing feeds
and configs are preserved; HTTP/insecure feeds and unknown external functions.sh
callbacks stop the operation before backup/package/service writes.

Reproduction (maintainer fixture directories; never execute on a real router):

1. Obtain the exact original architecture archive above; verify its original pin.
2. Extract `etc/xkeen-offline-source-lock.json` from the pinned derived archive.
3. Run `python3 -B scripts/entware_bundle.py fetch SOURCE_LOCK EMPTY_REPOSITORY`.
   Source drift or unavailable old packages fails; no new versions are substituted.
4. Run `python3 -B scripts/entware_bundle.py build SOURCE_LOCK REPOSITORY ORIGINAL_ARCHIVE NEW_ARCHIVE`.
5. Verify the final size/SHA256 above and Go archive/offline-repository validation.
   A new upstream snapshot starts with `resolve ARCH CANDIDATE_LOCK` and requires
   explicit package/hook review before replacing catalog pins.

The SMB read-back cap is 64 MiB for these approximately 23 MiB bundles. Existing
128 MiB decompression, 120 MiB member-total, 64 MiB member and 1000-entry limits,
path/symlink/ELF checks and exact size/SHA256 binding are retained. This provenance
record alone does not claim successful real-device firmware installation.

## Existing package state and isolated fixtures

`opkg install` can configure unrelated unpacked packages; this behavior was checked
against opkg commit `80503d94e356476250adaf1f669ee955ec26de76` and reproduced using a
harmless marker hook. Before writes, the installer requires a complete status
file containing fully installed packages. Residual/incomplete states are refused.
If a selected dependency's installed version differs from the pinned closure and
old preinst/postinst/prerm/postrm exist, the operation is refused for separate
review. It does not silently configure, remove or repair those packages. State is
checked again immediately before dependency and watchdog package installation.
Unsupported quoted config syntax also fails closed. Four static, allowlisted
remediation messages reach the UI; wrapped transport details remain redacted.

`bash scripts/check_entware_offline.sh arm64 mips mipsel` runs the Linux-only test
`TestNativeOfflinePackagePhase` in disposable Docker containers with no network,
an anonymous ext4 /opt volume, and read-only inputs. The fixture image must be
ARM64 Ubuntu 24.04 with QEMU user-static 8.2.2 and proot 5.5.0. Ubuntu's older proot
5.1.0 crashed even on native /bin/true and was not used as acceptance evidence.
The test requires a private fixture marker and explicit environment selection;
it skips in normal Go tests. It validates the exact private staging command,
hostile OPKG_CONF_DIR/OFFLINE_ROOT/TMPDIR, additional HTTP configs and stale lists,
the real pinned watchdog IPK, unfinished/unrelated hooks, unknown old hooks, and
the locales low-memory failure path. Real Keenetic firmware extraction, RCI,
network reachability and SSH credential handoff are outside this userspace check.

The maintainer fixture needs the watchdog 1.0.16 IPK already authenticated by its
catalog size/SHA in `.superpowers/sec001/watchdog/`. It does not download fixture
inputs or use a live router. The test image was prepared with these two builds
(no project build context or user files are sent):

```sh
docker build -t xkeen-sec001-fixture - <<'DOCKERFILE'
FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends qemu-user-static proot && rm -rf /var/lib/apt/lists/*
DOCKERFILE
docker build -t xkeen-sec001-fixture-current - <<'DOCKERFILE'
FROM xkeen-sec001-fixture
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential libtalloc-dev curl ca-certificates && curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' https://api.github.com/repos/proot-me/proot/tarball/v5.5.0 -o /tmp/proot.tar.gz && echo '19ffbbce2f60f3cf2a8d7900f61d8340049404767c9c6a5fed9a97eeb3763be8  /tmp/proot.tar.gz' | sha256sum -c - && mkdir /tmp/proot && tar -xzf /tmp/proot.tar.gz --strip-components=1 -C /tmp/proot && make -C /tmp/proot/src -j2 && install /tmp/proot/src/proot /usr/local/bin/proot
DOCKERFILE
```

No binfmt registration or host trust-store change is required. Current native
fixtures passed all three targets. The actual upstream control scripts, source
lock, derivative bytes and catalog pins remain the authority; a successful
fixture is not proof against previously compromised root-level router software.

## SEC-007 fresh access derivation

The source acquisition lock and original archives are unchanged. In addition to
the locales transformation, fresh-dropbear-positive-ready-v1 changes only the
pinned S51dropbear start entry in dropbear 2026.94-4 data.tar.gz. The original init
SHA256 is 3a531c9a5f4aab0797ae8d40d0235966100ec13139a4bbe2078cbc76d0d1ee4e
on all three architectures. Unknown init bytes fail preparation. Source and
derived package digests are separate manifest fields. The normal installer
rejects dropbear/opt-ndmsv2 in its selected dependency closure before writes;
it never applies this fresh-only policy to existing credentials/init.

The archive removes both upstream private host keys and adds the reviewed
etc/xkeen-first-access script plus an architecture marker. bin/install revokes
readiness and stops an existing fresh service before package operations, installs
the selected root hash, generates both host keys, checks current state, removes
the transferable credential, atomically publishes readiness, then starts SSH.
The gate checks current passwd and both key-file digests at every service start.
Missing or stale state denies startup; no default-credential fallback exists.

The desktop uses github.com/sergeymakinen/go-crypt v1.0.6 SHA-512-crypt with
100000 rounds and a random 16-character salt; see its primary API documentation:
https://pkg.go.dev/github.com/sergeymakinen/go-crypt/sha512.
The signed SMB sidecar is capped at 512 bytes and binds plan ID, volume UUID,
architecture and canonical archive SHA256 to the hash. It is never shell-sourced.
SMB signing supplies integrity, not confidentiality; a captured hash permits
offline guessing. The chosen UI requires a separate password of at least 16
Unicode code points and at most 1024 UTF-8 bytes, rejecting NUL/CR/LF and invalid
Unicode. Plaintext is not persisted or included in commands/events/reports.

The previous SEC-001 isolated results are historical evidence for its old
candidate; updated package and real SSH fixtures must pass before SEC-007 closes.
Real Keenetic firmware extraction and real-device SSH reachability remain outside
isolated userspace evidence.

The opt-ndmsv2 1.0-17 derivative fresh-root-locked-v1 checks the original passwd
file SHA256 51f28bc4f23398131fac87e065825e7349621ea1b5d3f141bb1570b28e0f250b
and changes only root's password field to !. No reusable default hash is installed,
including a repeated fresh package pass; the remaining account fields/users are
unchanged. Existing installation paths reject this package before writes.
The signal handler uses EXIT only for cleanup; HUP/INT/TERM exit unsuccessfully
before readiness. The real keygen-interruption fixture reproduced the previous
shared-handler bug before its correction.

Final isolated first-access and offline package wrapper exited 0 on ARM64, MIPS
and MIPSel (2026-11-17). Authentication checks use the exact packaged Dropbear:
normal native ARM64; direct QEMU normal MIPS/MIPSel with its existing fork
fallback after fexecve Exec format error. The MIPS packages do not support inetd.
Bootstrap/init/package operations still execute through PRoot. Neither an EOF
nor connection failure counts as password rejection. Native MIPS reexec, remote
commands inside that emulated SSH session and real Keenetic firmware remain
outside this evidence. Independent security review reproduced these final three
archive bytes and verified all transformed members/pins.
