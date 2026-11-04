package install

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io/fs"
	"testing"

	"github.com/Arap919/xkeen-installer/internal/catalog"
)

func elfBytes(arch catalog.RouterArch) []byte {
	b := make([]byte, 64)
	copy(b, []byte{127, 'E', 'L', 'F'})
	b[4] = 2
	b[5] = 1
	b[6] = 1
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[18:], 183)
	binary.LittleEndian.PutUint16(b[52:], 64)
	if arch != catalog.ARM64 {
		b[4] = 1
		binary.LittleEndian.PutUint16(b[18:], 8)
		binary.LittleEndian.PutUint16(b[40:], 52)
	}
	if arch == catalog.MIPS {
		b[5] = 2
		binary.BigEndian.PutUint32(b[20:], 1)
		binary.BigEndian.PutUint16(b[18:], 8)
		binary.BigEndian.PutUint16(b[40:], 52)
	}
	return b
}
func tarBytes(name string, kind byte) []byte {
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	w := tar.NewWriter(g)
	data := []byte("#!/bin/sh\n")
	h := &tar.Header{Name: name, Typeflag: kind, Mode: 0755, Size: int64(len(data))}
	if kind != tar.TypeReg {
		h.Size = 0
		h.Linkname = "/opt/etc/private"
	}
	_ = w.WriteHeader(h)
	if kind == tar.TypeReg {
		_, _ = w.Write(data)
	}
	_ = w.Close()
	_ = g.Close()
	return b.Bytes()
}
func TestSafeArchiveAndELFArchitecture(t *testing.T) {
	for _, arch := range []catalog.RouterArch{catalog.ARM64, catalog.MIPSel, catalog.MIPS} {
		a, _ := catalog.Resolve(catalog.UI, arch)
		if _, e := decodeArtifact(a, elfBytes(arch)); e != nil {
			t.Fatal(arch, e)
		}
		if arch != catalog.ARM64 {
			if _, e := decodeArtifact(a, elfBytes(catalog.ARM64)); e == nil {
				t.Fatal("wrong ELF arch")
			}
		}
	}
	a, _ := catalog.Resolve(catalog.XKeen, catalog.ARM64)
	for _, tc := range []struct {
		name string
		kind byte
	}{{"../xkeen", tar.TypeReg}, {"/xkeen", tar.TypeReg}, {"_xkeen/link", tar.TypeSymlink}, {"_xkeen/hard", tar.TypeLink}, {"_xkeen/../xkeen", tar.TypeReg}} {
		if _, e := decodeArtifact(a, tarBytes(tc.name, tc.kind)); e == nil {
			t.Fatal("unsafe tar accepted", tc)
		}
	}
	if _, e := decodeArtifact(a, tarBytes("xkeen", tar.TypeReg)); e != nil {
		t.Fatal(e)
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	h := &zip.FileHeader{Name: "xray"}
	h.SetMode(fs.ModeSymlink | 0777)
	w, _ := z.CreateHeader(h)
	_, _ = w.Write([]byte("/opt/etc/private"))
	_ = z.Close()
	a, _ = catalog.Resolve(catalog.Xray, catalog.ARM64)
	if _, e := decodeArtifact(a, b.Bytes()); e == nil {
		t.Fatal("zip link accepted")
	}
	if _, e := decodeArtifact(a, []byte("broken")); e == nil {
		t.Fatal("invalid zip")
	}
}
func TestQuoteCannotInjectShell(t *testing.T) {
	if got := quote("x'; touch /tmp/pwn; '"); got != "'x'\"'\"'; touch /tmp/pwn; '\"'\"''" {
		t.Fatal(got)
	}
}
