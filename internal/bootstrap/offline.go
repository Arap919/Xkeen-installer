package bootstrap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Arap919/xkeen-installer/internal/catalog"
)

const OfflineRoot = "/opt/.xkeen-installer-repository"
const offlinePrefix = ".xkeen-installer-repository/"

var offlineFilename = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.~-]*\.ipk$`)
var offlineName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.-]*$`)

type OfflinePackage struct {
	Version string
	Depends string
}

type OfflineRepo struct {
	Files     map[string][]byte
	Config    []byte
	Packages  map[string]OfflinePackage
	Providers map[string]string
}

type offlineManifest struct {
	Format    int                `json:"format"`
	Arch      catalog.RouterArch `json:"arch"`
	Providers map[string]string  `json:"providers"`
	Packages  []struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Depends  string `json:"depends"`
		Filename string `json:"filename"`
		Size     int64  `json:"size"`
		SHA256   string `json:"sha256"`
		Stanza   string `json:"stanza"`
	} `json:"packages"`
}

// OfflineRepository authenticates the complete archive against the embedded catalog
// before exposing local package bytes. It never fetches or refreshes metadata.
func OfflineRepository(ctx context.Context, arch catalog.RouterArch) (OfflineRepo, error) {
	artifact, err := catalog.Resolve(catalog.Entware, arch)
	if err != nil {
		return OfflineRepo{}, ErrUnsafe
	}
	data, err := Download(ctx, artifact)
	if err != nil {
		return OfflineRepo{}, err
	}
	return decodeOfflineRepository(arch, data)
}

func decodeOfflineRepository(arch catalog.RouterArch, data []byte) (OfflineRepo, error) {
	fail := func() (OfflineRepo, error) { return OfflineRepo{}, ErrUnsafe }
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fail()
	}
	defer gz.Close()
	limited := io.LimitReader(gz, (128<<20)+1)
	reader := tar.NewReader(limited)
	repo := OfflineRepo{Files: map[string][]byte{}, Packages: map[string]OfflinePackage{}}
	seen := map[string]bool{}
	var total int64
	for count := 0; ; count++ {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || count >= 1000 || header.Size < 0 || header.Size > 64<<20 {
			return fail()
		}
		total += header.Size
		if total > 120<<20 {
			return fail()
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name != path.Clean(name) || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\x00\r\n") || seen[name] {
			return fail()
		}
		seen[name] = true
		if name != "etc/opkg-offline.conf" && !strings.HasPrefix(name, offlinePrefix) {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return fail()
		}
		content, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(content)) != header.Size {
			return fail()
		}
		if name == "etc/opkg-offline.conf" {
			repo.Config = content
			continue
		}
		relative := strings.TrimPrefix(name, offlinePrefix)
		if relative != "Packages" && relative != "reviewed-lock.json" && !offlineFilename.MatchString(relative) {
			return fail()
		}
		repo.Files[relative] = content
	}
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return fail()
	}
	var manifest offlineManifest
	if len(repo.Files["reviewed-lock.json"]) > 1<<20 || json.Unmarshal(repo.Files["reviewed-lock.json"], &manifest) != nil || manifest.Format != 2 || manifest.Arch != arch || len(manifest.Packages) == 0 || len(manifest.Packages) > 256 {
		return fail()
	}
	if len(repo.Files) != len(manifest.Packages)+2 {
		return fail()
	}
	var index strings.Builder
	names := map[string]bool{}
	filenames := map[string]bool{}
	repo.Providers = manifest.Providers
	for _, item := range manifest.Packages {
		if item.Version == "" || len(item.Version) > 128 || strings.ContainsAny(item.Version, "\x00\r\n") {
			return fail()
		}
		repo.Packages[item.Name] = OfflinePackage{item.Version, item.Depends}
		if !offlineName.MatchString(item.Name) || names[item.Name] || !offlineFilename.MatchString(item.Filename) || filenames[item.Filename] || item.Size <= 0 || item.Size > 64<<20 || len(item.Stanza) == 0 || len(item.Stanza) > 64<<10 {
			return fail()
		}
		names[item.Name] = true
		filenames[item.Filename] = true
		digest, err := hex.DecodeString(item.SHA256)
		content, exists := repo.Files[item.Filename]
		actual := sha256.Sum256(content)
		if err != nil || len(digest) != sha256.Size || !exists || int64(len(content)) != item.Size || !bytes.Equal(actual[:], digest) {
			return fail()
		}
		index.WriteString(item.Stanza)
	}
	if !bytes.Equal(repo.Files["Packages"], []byte(index.String())) || !validOfflineConfig(repo.Config) {
		return fail()
	}
	return repo, nil
}

func validOfflineConfig(data []byte) bool {
	prefix := "src xkeen file://" + OfflineRoot + "\ndest root /\nlists_dir ext /opt/var/opkg-lists-offline\n"
	if !strings.HasPrefix(string(data), prefix) {
		return false
	}
	architectures := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(string(data), prefix), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "arch" || !offlineName.MatchString(fields[1]) || architectures[fields[1]] {
			return false
		}
		priority, err := strconv.Atoi(fields[2])
		if err != nil || priority <= 0 || priority > 10000 {
			return false
		}
		architectures[fields[1]] = true
	}
	return architectures["all"] && len(architectures) >= 2
}

// DependencyVersions identifies the exact reviewed closure that opkg may select.
// Version satisfaction is checked by the preparation tool and by opkg itself.
func (r OfflineRepo) DependencyVersions(roots []string) (map[string]string, error) {
	versions := map[string]string{}
	var visit func(string) error
	visit = func(name string) error {
		item, found := r.Packages[name]
		if !found {
			name = r.Providers[name]
			item, found = r.Packages[name]
		}
		if !found || !offlineName.MatchString(name) {
			return ErrUnsafe
		}
		if _, visited := versions[name]; visited {
			return nil
		}
		versions[name] = item.Version
		for _, dependency := range strings.Split(item.Depends, ",") {
			fields := strings.Fields(dependency)
			if len(fields) == 0 {
				continue
			}
			if strings.Contains(dependency, "|") {
				return ErrUnsafe
			}
			if err := visit(fields[0]); err != nil {
				return err
			}
		}
		return nil
	}
	for _, name := range roots {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	return versions, nil
}
