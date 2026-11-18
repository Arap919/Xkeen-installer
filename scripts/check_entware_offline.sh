#!/usr/bin/env bash
# Execute only disposable, network-denied SEC-001 package fixtures.
set -euo pipefail
fixture_repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$fixture_repo"
docker image inspect xkeen-sec001-fixture-current >/dev/null
mkdir -p .superpowers/sec001
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOTOOLCHAIN=go1.26.11 go test -c -o .superpowers/sec001/offline-fixture.test ./internal/install
if [ "$#" -eq 0 ]; then set -- arm64 mips mipsel; fi
for fixture_arch in "$@"; do
  case "$fixture_arch" in arm64|mips|mipsel) ;; *) exit 2 ;; esac
  docker run --rm --network none \
    --mount type=volume,destination=/opt \
    --mount "type=bind,source=$fixture_repo/internal/bootstrap/archives,destination=/input,readonly" \
    --mount "type=bind,source=$fixture_repo/.superpowers/sec001/offline-fixture.test,destination=/test/offline-fixture.test,readonly" \
    --mount "type=bind,source=$fixture_repo/.superpowers/sec001/watchdog/router-watchdog_1.0.16-1_all.ipk,destination=/watchdog.ipk,readonly" \
    -e "XKEEN_OFFLINE_FIXTURE_ARCH=$fixture_arch" \
    xkeen-sec001-fixture-current /bin/sh -ec '
      tar -xzf "/input/$XKEEN_OFFLINE_FIXTURE_ARCH.tar.gz" -C /opt
      mkdir -p /fixture/proc /fixture/dev /fixture/etc /fixture/tmp
      ln -s /opt/bin /fixture/bin
      ln -s /opt/sbin /fixture/sbin
      printf "SEC001_NETWORK_NONE\n" >/fixture-isolated
      /test/offline-fixture.test -test.run "^TestNativeFirstAccess$" -test.v -test.timeout 10m
      /test/offline-fixture.test -test.run "^TestNativeOfflinePackagePhase$" -test.v -test.timeout 10m
    '
done
