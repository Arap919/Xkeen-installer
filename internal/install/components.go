package install

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"debug/elf"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/Arap919/xkeen-installer/internal/catalog"
)

const maxExpanded = 256 << 20
const maxFile = 64 << 20
const maxMembers = 1000

type payload struct {
	path      string
	data      []byte
	mode      fs.FileMode
	component catalog.Component
	preserve  bool
}

func loadArtifacts(ctx context.Context, artifacts []catalog.Artifact) ([]payload, error) {
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" {
			return errors.New("unsafe redirect")
		}
		return nil
	}}
	var out []payload
	for _, a := range artifacts {
		bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
		req, e := http.NewRequestWithContext(bounded, http.MethodGet, a.URL, nil)
		if e != nil {
			cancel()
			return nil, errors.New("download request failed")
		}
		res, e := client.Do(req)
		if e != nil {
			cancel()
			return nil, errors.New("artifact download failed")
		}
		b, e := io.ReadAll(io.LimitReader(res.Body, a.Size+1))
		closeErr := res.Body.Close()
		cancel()
		if e != nil || closeErr != nil || res.StatusCode != http.StatusOK {
			return nil, errors.New("artifact download failed")
		}
		if e = catalog.Verify(a, bytes.NewReader(b)); e != nil {
			return nil, errors.New("artifact integrity failed")
		}
		files, e := decodeArtifact(a, b)
		if e != nil {
			return nil, e
		}
		out = append(out, files...)
	}
	return out, nil
}
func memberSafe(p string) bool {
	return p != "" && p != "." && !strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsAny(p, "\\\x00\r\n")
}
func boundedRead(r io.Reader) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, maxFile+1))
	if e != nil || len(b) > maxFile {
		return nil, errors.New("archive file limit exceeded")
	}
	return b, nil
}
func executable(a catalog.Artifact, b []byte) error {
	f, e := elf.NewFile(bytes.NewReader(b))
	if e != nil {
		return errors.New("payload is not ELF")
	}
	defer f.Close()
	if f.OSABI != elf.ELFOSABI_NONE && f.OSABI != elf.ELFOSABI_LINUX {
		return errors.New("unsupported ELF ABI")
	}
	switch a.Arch {
	case catalog.ARM64:
		if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_AARCH64 {
			return errors.New("ELF architecture mismatch")
		}
	case catalog.MIPSel:
		if f.Class != elf.ELFCLASS32 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_MIPS {
			return errors.New("ELF architecture mismatch")
		}
	case catalog.MIPS:
		if f.Class != elf.ELFCLASS32 || f.Data != elf.ELFDATA2MSB || f.Machine != elf.EM_MIPS {
			return errors.New("ELF architecture mismatch")
		}
	default:
		return errors.New("unsupported ELF architecture")
	}
	return nil
}
func decodeArtifact(a catalog.Artifact, b []byte) ([]payload, error) {
	var out []payload
	add := func(p string, b []byte, mode fs.FileMode) {
		out = append(out, payload{path: p, data: b, mode: mode, component: a.Component})
	}
	switch a.Component {
	case catalog.XKeen:
		gz, e := gzip.NewReader(bytes.NewReader(b))
		if e != nil {
			return nil, errors.New("invalid gzip")
		}
		defer gz.Close()
		tr := tar.NewReader(io.LimitReader(gz, maxExpanded+1))
		var total int64
		for count := 0; ; count++ {
			h, e := tr.Next()
			if e == io.EOF {
				break
			}
			if e != nil || count >= maxMembers {
				return nil, errors.New("invalid tar archive")
			}
			n := strings.TrimSuffix(h.Name, "/")
			if !memberSafe(n) || !(n == "xkeen" || n == "_xkeen" || strings.HasPrefix(n, "_xkeen/")) {
				return nil, errors.New("unsafe tar path")
			}
			if h.Typeflag == tar.TypeDir {
				continue
			}
			if h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > maxFile || total+h.Size > maxExpanded {
				return nil, errors.New("unsafe tar member")
			}
			total += h.Size
			data, e := boundedRead(tr)
			if e != nil || int64(len(data)) != h.Size {
				return nil, errors.New("truncated tar member")
			}
			p := "/opt/sbin/" + n
			if strings.HasPrefix(n, "_xkeen/") {
				p = "/opt/sbin/.xkeen/" + strings.TrimPrefix(n, "_xkeen/")
			}
			add(p, data, 0755)
		}
		found := false
		seen := map[string]bool{}
		for _, f := range out {
			if seen[f.path] {
				return nil, errors.New("duplicate archive member")
			}
			seen[f.path] = true
			if f.path == "/opt/sbin/xkeen" {
				found = true
			}
		}
		if !found {
			return nil, errors.New("missing XKeen script")
		}
	case catalog.Mihomo:
		gz, e := gzip.NewReader(bytes.NewReader(b))
		if e != nil {
			return nil, errors.New("invalid gzip")
		}
		data, e := boundedRead(gz)
		ce := gz.Close()
		if e != nil || ce != nil {
			return nil, errors.New("invalid compressed core")
		}
		if e = executable(a, data); e != nil {
			return nil, e
		}
		add("/opt/sbin/mihomo", data, 0755)
	case catalog.Xray:
		zr, e := zip.NewReader(bytes.NewReader(b), int64(len(b)))
		if e != nil || len(zr.File) > maxMembers {
			return nil, errors.New("invalid zip")
		}
		var total uint64
		found := false
		for _, f := range zr.File {
			n := strings.TrimSuffix(f.Name, "/")
			total += f.UncompressedSize64
			if !memberSafe(n) || total > maxExpanded || f.UncompressedSize64 > maxFile || f.Mode()&fs.ModeSymlink != 0 {
				return nil, errors.New("unsafe zip member")
			}
			if f.FileInfo().IsDir() {
				continue
			}
			if !f.Mode().IsRegular() {
				return nil, errors.New("special zip member")
			}
			if n != "xray" {
				continue
			}
			if found {
				return nil, errors.New("duplicate xray")
			}
			found = true
			r, e := f.Open()
			if e != nil {
				return nil, errors.New("invalid zip member")
			}
			data, e := boundedRead(r)
			ce := r.Close()
			if e != nil || ce != nil {
				return nil, errors.New("invalid zip bytes")
			}
			if e = executable(a, data); e != nil {
				return nil, e
			}
			add("/opt/sbin/xray", data, 0755)
		}
		if !found {
			return nil, errors.New("xray missing")
		}
	case catalog.Yq:
		if e := executable(a, b); e != nil {
			return nil, e
		}
		add("/opt/sbin/yq", b, 0755)
	case catalog.UI:
		if e := executable(a, b); e != nil {
			return nil, e
		}
		add("/opt/sbin/xkeen-ui", b, 0755)
	case catalog.Watchdog:
		if len(b) > maxFile {
			return nil, errors.New("package too large")
		}
		add("/opt/.xkeen-installer-packages/router-watchdog_1.0.16-1_all.ipk", append([]byte(nil), b...), 0600)
	default:
		return nil, errors.New("unsupported component adapter")
	}
	return out, nil
}
