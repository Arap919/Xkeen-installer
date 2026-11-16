// Package catalog resolves the reviewed 2026-11-04 upstream snapshot without network or router access.
package catalog

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

type Component string

const (
	Entware  Component = "entware"
	XKeen    Component = "xkeen"
	Mihomo   Component = "mihomo"
	Xray     Component = "xray"
	UI       Component = "ui"
	Yq       Component = "yq"
	Watchdog Component = "watchdog"
)

type RouterArch string

const (
	ARM64  RouterArch = "arm64"
	MIPSel RouterArch = "mipsel"
	MIPS   RouterArch = "mips"
)

// Integrity records a reviewed digest and its explicit provenance. Entware pins
// identify installer-reviewed bytes, not an upstream-published checksum.
type Integrity struct {
	SHA256 string
	Source string
}

// Artifact is a download contract, not evidence of installation. Size zero means unknown.
// Entware offline bundles are installer-derived snapshots with reviewed source pins.
type Artifact struct {
	Component Component
	Arch      RouterArch
	Version   string
	URL       string
	Size      int64
	Integrity Integrity
}

var ErrIntegrityUnavailable = errors.New("upstream integrity unavailable")

// Resolve returns the reviewed default artifact. It never follows a floating latest URL.
func Resolve(c Component, arch RouterArch) (Artifact, error) {
	if arch != ARM64 && arch != MIPSel && arch != MIPS {
		return Artifact{}, fmt.Errorf("unsupported router architecture %q", arch)
	}
	a := Artifact{Component: c, Arch: arch}
	if c == Entware {
		a.Version = "offline-2026-11-16"
		switch arch {
		case ARM64:
			a.URL = "bundled://entware/2026-11-16/arm64.tar.gz"
			a.Size = 23923438
			a.Integrity.SHA256 = "3fbdd2dddf39e97cafd63fc1a7d9df1ef81edaad423f298518d493cae1163a7d"
		case MIPSel:
			a.URL = "bundled://entware/2026-11-16/mipsel.tar.gz"
			a.Size = 23552819
			a.Integrity.SHA256 = "fc4eb8bb49fac1fd722f589e63b6189e2296cbe52e6d47e8a8761a5a6f2caf7d"
		case MIPS:
			a.URL = "bundled://entware/2026-11-16/mips.tar.gz"
			a.Size = 23854528
			a.Integrity.SHA256 = "ac5e4a80adb76965bc704ef4e08d20e82556bf9cc87f51af11d183ffd2bc7058"
		}
		a.Integrity.Source = "installer-offline-bundle:2026-11-16:" + a.URL
		return a, nil
	}
	if c == Watchdog {
		a.Version = "1.0.16-1"
		// Use the versioned release asset rather than the mutable Pages feed path.
		a.URL = "https://github.com/Arap919/router-watchdog/releases/download/v1.0.16/router-watchdog_1.0.16-1_all.ipk"
		a.Size = 19860
		a.Integrity = Integrity{"68a5295a8e80702e54c036c7263174f74102ea5f40ef2272ec84be9d2a5535d6", "https://arap919.github.io/router-watchdog/update.json"}
		return a, nil
	}
	var repo, name string
	switch c {
	case XKeen:
		repo = "jameszeroX/XKeen"
		a.Version = "2.1"
		name = "xkeen.tar.gz"
		a.Size = 129691
		a.Integrity.SHA256 = "4b9350b11fab7fd3e4973db609db0fb780994f4b5ab0096f0549bc52acac8c73"
	case Yq:
		repo = "mikefarah/yq"
		a.Version = "v4.54.1"
		switch arch {
		case ARM64:
			name = "yq_linux_arm64"
			a.Size = 13172896
			a.Integrity.SHA256 = "189088da0c6429ec5178dfaab1a114805f6cab0b61b165ab236efedf1d57a71b"
		case MIPS, MIPSel:
			repo = "jameszeroX/yq"
			a.Version = "260527"
			a.Size = 15139009
			if arch == MIPS {
				name = "yq_linux_mips"
				a.Integrity.SHA256 = "05ed5069325c2caea97e717a36aaab161f365afa4af862b38c51ef32a2608b41"
			} else {
				name = "yq_linux_mipsle"
				a.Integrity.SHA256 = "9271b89b0618a4fb5034f2688eaf6433756f5342c97b3bf9cbffdd04fcd29dd7"
			}
		}
	case Mihomo:
		repo = "MetaCubeX/mihomo"
		a.Version = "v1.19.33"
		switch arch {
		case ARM64:
			name = "mihomo-linux-arm64-v1.19.33.gz"
			a.Size = 20824326
			a.Integrity.SHA256 = "ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187"
		case MIPSel:
			name = "mihomo-linux-mipsle-softfloat-v1.19.33.gz"
			a.Size = 20397891
			a.Integrity.SHA256 = "ad6b3837db8dff2a6853a3c1604b82ee2f7e4019f626a5ab61f46b7c565871c4"
		case MIPS:
			name = "mihomo-linux-mips-softfloat-v1.19.33.gz"
			a.Size = 20744343
			a.Integrity.SHA256 = "d57934651a36af34c4a45539a946d1c8a35ce6381f93a79ca417b5e78a6170a7"
		}
	case Xray:
		repo = "XTLS/Xray-core"
		a.Version = "v26.10.31"
		switch arch {
		case ARM64:
			name = "Xray-linux-arm64-v8a.zip"
			a.Size = 15175093
			a.Integrity.SHA256 = "1811c8f1da0c3b6dc707ebaf1c8390e987ba39859a8f0a7aadd8526157f2ec8d"
		case MIPSel:
			name = "Xray-linux-mips32le.zip"
			a.Size = 24590618
			a.Integrity.SHA256 = "7f3e56ea73f2e2ce12556ba3720e8894abd89c17aec5c70ea70ae6f48552cfb5"
		case MIPS:
			name = "Xray-linux-mips32.zip"
			a.Size = 24733919
			a.Integrity.SHA256 = "45a84c48da48e7f7663c4c0030977ba0d56ba24a5c855de6a1d898be904e16db"
		}
	case UI:
		repo = "Arap919/xkeen-ui-pwa-fork"
		a.Version = "v1.4.2+pwa.1"
		switch arch {
		case ARM64:
			name = "xkeen-ui-arm64-v8a"
			a.Size = 8132448
			a.Integrity.SHA256 = "c4f059e2b9b9d8b459300750f87e69ddd1da767ee1bcfb7ba1227bc24dc5f894"
		case MIPSel:
			name = "xkeen-ui-mips32le"
			a.Size = 10184864
			a.Integrity.SHA256 = "5e03803290d56269c69e793ebf02d009cf848e887f99e8550495e8f8f3a156a8"
		case MIPS:
			name = "xkeen-ui-mips32"
			a.Size = 10201248
			a.Integrity.SHA256 = "f2237a30c40437156e7a4fcf250501895b2773b98a92ade070f4fe64b0c8f134"
		}
	default:
		return Artifact{}, fmt.Errorf("unsupported component %q", c)
	}
	tag := a.Version
	if c == UI {
		tag = "v1.4.2%2Bpwa.1"
	}
	a.URL = "https://github.com/" + repo + "/releases/download/" + tag + "/" + name
	a.Integrity.Source = "https://api.github.com/repos/" + repo + "/releases/tags/" + tag
	return a, nil
}

// ResolveVersion accepts only a concrete version present in the reviewed snapshot.
// Adding another version requires reviewing its assets, sizes and digest provenance.
func ResolveVersion(c Component, arch RouterArch, version string) (Artifact, error) {
	a, err := Resolve(c, arch)
	if err != nil {
		return Artifact{}, err
	}
	if version != a.Version {
		return Artifact{}, fmt.Errorf("unreviewed %s version %q", c, version)
	}
	return a, nil
}

// Verify rejects altered metadata before reading and checks compressed/downloaded bytes.
// A nil error proves the reviewed size and SHA256, not publisher authentication,
// archive safety, executable architecture, successful installation or service readiness.
func Verify(a Artifact, r io.Reader) error {
	canonical, err := ResolveVersion(a.Component, a.Arch, a.Version)
	if err != nil || canonical != a {
		return fmt.Errorf("artifact metadata mismatch")
	}
	if a.Integrity.SHA256 == "" {
		return ErrIntegrityUnavailable
	}
	return verifyBytes(r, a.Size, a.Integrity.SHA256)
}

func verifyBytes(r io.Reader, size int64, digest string) error {
	if r == nil {
		return errors.New("nil artifact reader")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, size+1))
	if err != nil {
		return fmt.Errorf("read artifact: %w", err)
	}
	if n != size {
		return fmt.Errorf("artifact size mismatch: got %d, want %d", n, size)
	}
	if fmt.Sprintf("%x", h.Sum(nil)) != digest {
		return errors.New("artifact SHA256 mismatch")
	}
	return nil
}
