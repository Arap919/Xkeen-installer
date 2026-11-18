package bootstrap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Arap919/xkeen-installer/internal/catalog"
)

func offlineFixture(t *testing.T, change func(map[string][]byte)) []byte {
	t.Helper()
	data := []byte("authenticated fixture package")
	stanza := "Package: app\nVersion: 1\n\n"
	manifest, err := json.Marshal(map[string]any{"format": 2, "arch": "arm64", "packages": []map[string]any{{"name": "app", "version": "1", "filename": "app.ipk", "size": len(data), "sha256": fmt.Sprintf("%x", sha256.Sum256(data)), "stanza": stanza}}})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"etc/opkg-offline.conf":                          []byte("src xkeen file:///opt/.xkeen-installer-repository\ndest root /\nlists_dir ext /opt/var/opkg-lists-offline\narch all 100\narch aarch64-3.10 150\n"),
		".xkeen-installer-repository/Packages":           []byte(stanza),
		".xkeen-installer-repository/reviewed-lock.json": manifest,
		".xkeen-installer-repository/app.ipk":            data,
	}
	if change != nil {
		change(files)
	}
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestOfflineRepositoryRejectsTamperingMissingMaterialAndWrongArch(t *testing.T) {
	good := offlineFixture(t, nil)
	repo, err := decodeOfflineRepository(catalog.ARM64, good)
	if err != nil || string(repo.Files["app.ipk"]) != "authenticated fixture package" {
		t.Fatalf("valid repository rejected: %v", err)
	}
	if _, err := decodeOfflineRepository(catalog.MIPS, good); err == nil {
		t.Fatal("wrong architecture accepted")
	}
	for _, change := range []func(map[string][]byte){
		func(files map[string][]byte) { files[".xkeen-installer-repository/app.ipk"][0] ^= 1 },
		func(files map[string][]byte) { delete(files, ".xkeen-installer-repository/app.ipk") },
		func(files map[string][]byte) { delete(files, ".xkeen-installer-repository/reviewed-lock.json") },
		func(files map[string][]byte) {
			files[".xkeen-installer-repository/Packages"] = []byte("tampered metadata")
		},
		func(files map[string][]byte) {
			files[".xkeen-installer-repository/../escape.ipk"] = []byte("unexpected")
		},
		func(files map[string][]byte) {
			files["etc/opkg-offline.conf"] = []byte("src xkeen http://evil.invalid\n")
		},
	} {
		if _, err := decodeOfflineRepository(catalog.ARM64, offlineFixture(t, change)); err == nil {
			t.Fatal("unsafe or incomplete repository accepted")
		}
	}
}

// This opt-in check validates candidates before replacing the production pins.
func TestOfflineCandidateArchives(t *testing.T) {
	dir := os.Getenv("XKEEN_OFFLINE_CANDIDATE_DIR")
	if dir == "" {
		t.Skip("set XKEEN_OFFLINE_CANDIDATE_DIR for isolated offline bundle candidates")
	}
	for _, arch := range []catalog.RouterArch{catalog.ARM64, catalog.MIPS, catalog.MIPSel} {
		t.Run(string(arch), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, string(arch)+".tar.gz"))
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateArchive(arch, data); err != nil {
				t.Fatal("runtime archive safety check", err)
			}
			repo, err := decodeOfflineRepository(arch, data)
			if err != nil {
				t.Fatal("offline package validation", err)
			}
			if len(repo.Files) < 70 {
				t.Fatal("incomplete repository")
			}
		})
	}
}

func TestBundledOfflineRepositoriesAuthenticated(t *testing.T) {
	for _, arch := range []catalog.RouterArch{catalog.ARM64, catalog.MIPS, catalog.MIPSel} {
		t.Run(string(arch), func(t *testing.T) {
			repo, err := OfflineRepository(context.Background(), arch)
			if err != nil {
				t.Fatal("bundled bootstrap lacks authenticated offline packages", err)
			}
			if len(repo.Files) < 70 || !validOfflineConfig(repo.Config) {
				t.Fatal("incomplete local repository")
			}
		})
	}
}
