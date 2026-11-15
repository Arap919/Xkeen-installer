# Entware byte-pin provenance

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

