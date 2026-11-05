package catalog

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestResolveArchitectureAssets(t *testing.T) {
	cases := []struct {
		arch                      RouterArch
		ui, mihomo, xray, entware string
	}{
		{ARM64, "xkeen-ui-arm64-v8a", "mihomo-linux-arm64-v1.19.33.gz", "Xray-linux-arm64-v8a.zip", "aarch64-k3.10/installer/aarch64-installer.tar.gz"},
		{MIPSel, "xkeen-ui-mips32le", "mihomo-linux-mipsle-softfloat-v1.19.33.gz", "Xray-linux-mips32le.zip", "mipselsf-k3.4/installer/mipsel-installer.tar.gz"},
		{MIPS, "xkeen-ui-mips32", "mihomo-linux-mips-softfloat-v1.19.33.gz", "Xray-linux-mips32.zip", "mipssf-k3.4/installer/mips-installer.tar.gz"},
	}
	for _, tc := range cases {
		for _, want := range []struct {
			c      Component
			suffix string
		}{{UI, tc.ui}, {Mihomo, tc.mihomo}, {Xray, tc.xray}, {Entware, tc.entware}, {XKeen, "2.1/xkeen.tar.gz"}, {Watchdog, "router-watchdog_1.0.16-1_all.ipk"}} {
			t.Run(string(want.c)+"/"+string(tc.arch), func(t *testing.T) {
				a, err := Resolve(want.c, tc.arch)
				if err != nil {
					t.Fatal(err)
				}
				if a.Component != want.c || a.Arch != tc.arch || !strings.HasSuffix(a.URL, want.suffix) || a.Version == "" {
					t.Fatalf("wrong artifact: %+v", a)
				}
				if want.c != Entware && (len(a.Integrity.SHA256) != 64 || a.Size <= 0 || a.Integrity.Source == "") {
					t.Fatalf("missing published integrity: %+v", a)
				}
				if want.c == UI && !strings.Contains(a.URL, "v1.4.2%2Bpwa.1/") {
					t.Fatalf("tag not pinned/encoded: %s", a.URL)
				}
			})
		}
	}
}
func TestResolveRejectsUnknownInputs(t *testing.T) {
	for _, a := range []RouterArch{"", "amd64", "mips64"} {
		if _, err := Resolve(UI, a); err == nil {
			t.Errorf("accepted arch %q", a)
		}
	}
	if _, err := Resolve(Component("unknown"), ARM64); err == nil {
		t.Fatal("accepted component")
	}
}
func TestConcreteVersionCannotFloat(t *testing.T) {
	a, err := ResolveVersion(UI, MIPS, "v1.4.2+pwa.1")
	if err != nil || a.Version != "v1.4.2+pwa.1" {
		t.Fatalf("%+v %v", a, err)
	}
	for _, v := range []string{"", "latest", "v1.4.2+pwa.99", "../main"} {
		if _, err := ResolveVersion(UI, MIPS, v); err == nil {
			t.Errorf("accepted unverified version %q", v)
		}
	}
}
func TestVerifyRejectsMetadataMismatch(t *testing.T) {
	a, err := Resolve(UI, ARM64)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"url", "version", "arch", "size", "digest", "source", "component"} {
		t.Run(field, func(t *testing.T) {
			b := a
			switch field {
			case "url":
				b.URL = "https://evil.example/file"
			case "version":
				b.Version = "latest"
			case "arch":
				b.Arch = MIPS
			case "size":
				b.Size = 1
			case "digest":
				b.Integrity.SHA256 = strings.Repeat("0", 64)
			case "source":
				b.Integrity.Source = "local"
			case "component":
				b.Component = XKeen
			}
			if err := Verify(b, strings.NewReader("")); err == nil || !strings.Contains(err.Error(), "metadata") {
				t.Fatalf("expected metadata rejection, got %v", err)
			}
		})
	}
}
func TestVerifyRejectsInvalidWatchdogPayloads(t *testing.T) {
	// Offline zero-filled, truncated and oversized fixtures exercise canonical
	// metadata rejection; this test does not fetch or verify a published payload.
	a, err := Resolve(Watchdog, MIPS)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(a, bytes.NewReader(make([]byte, a.Size))); err == nil || !strings.Contains(err.Error(), "SHA256") {
		t.Fatalf("wrong digest accepted: %v", err)
	}
	if err := Verify(a, strings.NewReader("short")); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("truncation accepted: %v", err)
	}
	if err := Verify(a, io.MultiReader(bytes.NewReader(make([]byte, a.Size)), strings.NewReader("extra"))); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("oversize accepted: %v", err)
	}
}
func TestEntwareCannotClaimVerified(t *testing.T) {
	a, err := Resolve(Entware, ARM64)
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != "unversioned" || a.Integrity.SHA256 != "" {
		t.Fatalf("invented upstream version/digest: %+v", a)
	}
	if err := Verify(a, strings.NewReader("archive")); !errors.Is(err, ErrIntegrityUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyBytesKnownDigestAndReadFailure(t *testing.T) {
	if err := verifyBytes(strings.NewReader("abc"), 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"); err != nil {
		t.Fatal(err)
	}
	if err := verifyBytes(failingReader{}, 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read error lost: %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestPinnedYqDependency(t *testing.T) {
	a, err := Resolve(Yq, ARM64)
	if err != nil || a.Version != "v4.54.1" || a.Size != 13172896 || a.Integrity.SHA256 != "189088da0c6429ec5178dfaab1a114805f6cab0b61b165ab236efedf1d57a71b" {
		t.Fatal(a, err)
	}
	for _, arch := range []RouterArch{MIPS, MIPSel} {
		a, err := Resolve(Yq, arch)
		if err != nil || a.Version != "260527" || a.Size != 15139009 || !strings.Contains(a.URL, "jameszeroX/yq/releases/download/260527/") {
			t.Fatal(a, err)
		}
	}
}
