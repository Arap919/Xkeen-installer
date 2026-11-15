package bootstrap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"embed"
	"encoding/binary"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"io"
	"path"
	"strings"
)

func ValidateArchive(arch catalog.RouterArch, data []byte) error {
	g, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return ErrUnsafe
	}
	defer g.Close()
	tr := tar.NewReader(io.LimitReader(g, 128<<20))
	seen := map[string]byte{}
	links := map[string]string{}
	var total int64
	opkg := false
	for count := 0; ; count++ {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil || count >= 1000 {
			return ErrUnsafe
		}
		name := strings.TrimSuffix(h.Name, "/")
		if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\x00\r\n") {
			return ErrUnsafe
		}
		if _, ok := seen[name]; ok {
			return ErrUnsafe
		}
		seen[name] = h.Typeflag
		if h.Size < 0 || h.Size > 64<<20 {
			return ErrUnsafe
		}
		total += h.Size
		if total > 120<<20 {
			return ErrUnsafe
		}
		switch h.Typeflag {
		case tar.TypeDir:
		case tar.TypeReg:
			if name == "bin/opkg" {
				header := make([]byte, 20)
				if _, e = io.ReadFull(tr, header); e != nil {
					return ErrUnsafe
				}
				if !elfHeader(arch, header) {
					return ErrUnsafe
				}
				opkg = true
			}
		case tar.TypeSymlink:
			if h.Linkname == "" || strings.HasPrefix(h.Linkname, "/") || strings.ContainsAny(h.Linkname, "\\\x00\r\n") {
				return ErrUnsafe
			}
			target := path.Clean(path.Join(path.Dir(name), h.Linkname))
			if target == ".." || strings.HasPrefix(target, "../") {
				return ErrUnsafe
			}
			links[name] = target
		default:
			return ErrUnsafe
		}
	}
	if !opkg {
		return ErrUnsafe
	}
	for name, target := range links {
		visited := map[string]bool{name: true}
		for {
			if visited[target] {
				return ErrUnsafe
			}
			visited[target] = true
			next, ok := links[target]
			if !ok {
				if seen[target] != tar.TypeReg {
					return ErrUnsafe
				}
				break
			}
			target = next
		}
	}
	for name := range seen {
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			if seen[dir] == tar.TypeSymlink {
				return ErrUnsafe
			}
		}
	}
	// Force gzip CRC/trailer verification after tar's end-of-archive blocks.
	trailing, err := io.ReadAll(io.LimitReader(g, (1<<20)+1))
	if err != nil || len(trailing) > 1<<20 {
		return ErrUnsafe
	}
	for _, b := range trailing {
		if b != 0 {
			return ErrUnsafe
		}
	}
	return nil
}
func elfHeader(arch catalog.RouterArch, b []byte) bool {
	if len(b) < 20 || !bytes.Equal(b[:4], []byte{0x7f, 'E', 'L', 'F'}) || b[6] != 1 || (b[7] != 0 && b[7] != 3) {
		return false
	}
	var order binary.ByteOrder = binary.LittleEndian
	if b[5] == 2 {
		order = binary.BigEndian
	} else if b[5] != 1 {
		return false
	}
	if order.Uint16(b[16:18]) != 2 {
		return false
	}
	switch arch {
	case catalog.ARM64:
		return b[4] == 2 && b[5] == 1 && order.Uint16(b[18:20]) == 183
	case catalog.MIPS:
		return b[4] == 1 && b[5] == 2 && order.Uint16(b[18:20]) == 8
	case catalog.MIPSel:
		return b[4] == 1 && b[5] == 1 && order.Uint16(b[18:20]) == 8
	}
	return false
}

// Official reviewed bytes are bundled so initial setup does not depend on the
// Entware download server. Catalog pins and archive safety checks remain mandatory.
//
//go:embed archives/*.tar.gz
var bundledArchives embed.FS

func Download(ctx context.Context, a catalog.Artifact) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	canonical, err := catalog.Resolve(catalog.Entware, a.Arch)
	if err != nil || a != canonical {
		return nil, ErrUnsafe
	}
	b, err := bundledArchives.ReadFile("archives/" + string(a.Arch) + ".tar.gz")
	if err != nil {
		return nil, ErrUnsafe
	}
	if err = catalog.Verify(a, bytes.NewReader(b)); err != nil {
		return nil, ErrUnsafe
	}
	if err = ValidateArchive(a.Arch, b); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		clear(b)
		return nil, err
	}
	return b, nil
}
