package bootstrap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"net/http"
	"testing"
)

func testArchive(name string, data []byte) []byte {
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	w := tar.NewWriter(g)
	_ = w.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(data))})
	_, _ = w.Write(data)
	_ = w.Close()
	_ = g.Close()
	return b.Bytes()
}
func TestArchiveRejectsTraversalAndWrongEndian(t *testing.T) {
	elf := make([]byte, 64)
	copy(elf, []byte{0x7f, 'E', 'L', 'F', 1, 2, 1})
	elf[17] = 2
	elf[19] = 8
	if err := ValidateArchive(catalog.MIPS, testArchive("bin/opkg", elf)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateArchive(catalog.MIPSel, testArchive("bin/opkg", elf)); err == nil {
		t.Fatal("accepted wrong ELF endian")
	}
	if err := ValidateArchive(catalog.MIPS, testArchive("../bin/opkg", elf)); err == nil {
		t.Fatal("accepted traversal")
	}
	if err := ValidateArchive(catalog.MIPS, []byte("broken")); err == nil {
		t.Fatal("accepted malformed gzip")
	}
	corrupted := testArchive("bin/opkg", elf)
	corrupted[len(corrupted)-8] ^= 1
	if err := ValidateArchive(catalog.MIPS, corrupted); err == nil {
		t.Fatal("accepted gzip checksum corruption")
	}
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	w := tar.NewWriter(g)
	_ = w.WriteHeader(&tar.Header{Name: "bin/opkg", Typeflag: tar.TypeSymlink, Linkname: "../../escape"})
	_ = w.Close()
	_ = g.Close()
	if err := ValidateArchive(catalog.MIPS, b.Bytes()); err == nil {
		t.Fatal("accepted escaping symlink")
	}
}

type rejectArchiveNetwork struct{ calls int }

func (r *rejectArchiveNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return nil, errors.New("network disabled for bundled archive test")
}
func TestBundledEntwareArchivesWithoutNetwork(t *testing.T) {
	transport := &rejectArchiveNetwork{}
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = previous }()
	for _, arch := range []catalog.RouterArch{catalog.ARM64, catalog.MIPSel, catalog.MIPS} {
		t.Run(string(arch), func(t *testing.T) {
			a, e := catalog.Resolve(catalog.Entware, arch)
			if e != nil {
				t.Fatal(e)
			}
			b, e := Download(context.Background(), a)
			if e != nil {
				t.Fatal(e)
			}
			if e = catalog.Verify(a, bytes.NewReader(b)); e != nil {
				t.Fatal(e)
			}
			if e = ValidateArchive(arch, b); e != nil {
				t.Fatal(e)
			}
		})
	}
	if transport.calls != 0 {
		t.Fatalf("bundled archives used network: %d", transport.calls)
	}
}
func TestBundledEntwareRejectsChangedMetadataAndCancellation(t *testing.T) {
	a, _ := catalog.Resolve(catalog.Entware, catalog.MIPS)
	a.URL = "https://example.invalid/foreign"
	if _, e := Download(context.Background(), a); e == nil {
		t.Fatal("foreign metadata accepted")
	}
	a, _ = catalog.Resolve(catalog.Entware, catalog.MIPS)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Download(ctx, a); !errors.Is(e, context.Canceled) {
		t.Fatalf("cancellation lost: %v", e)
	}
}
