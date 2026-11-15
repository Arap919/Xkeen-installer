package bootstrap

import (
	"bytes"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"os"
	"path/filepath"
	"testing"
)

// This opt-in developer check never downloads data or becomes a CI dependency.
func TestReviewedDownloadedArchives(t *testing.T) {
	dir := os.Getenv("XKEEN_BOOTSTRAP_ARCHIVE_DIR")
	if dir == "" {
		t.Skip("set XKEEN_BOOTSTRAP_ARCHIVE_DIR to inspect independently downloaded official archives")
	}
	for _, arch := range []catalog.RouterArch{catalog.ARM64, catalog.MIPSel, catalog.MIPS} {
		t.Run(string(arch), func(t *testing.T) {
			b, e := os.ReadFile(filepath.Join(dir, "xkeen-entware-"+string(arch)+".tar.gz"))
			if e != nil {
				t.Fatal(e)
			}
			a, e := catalog.Resolve(catalog.Entware, arch)
			if e != nil {
				t.Fatal(e)
			}
			if e = catalog.Verify(a, bytes.NewReader(b)); e != nil {
				t.Fatal(e)
			}
			if e = ValidateArchive(arch, b); e != nil {
				t.Fatal(e)
			}
			b[0] ^= 1
			if e = catalog.Verify(a, bytes.NewReader(b)); e == nil {
				t.Fatal("altered downloaded archive accepted")
			}
		})
	}
}
