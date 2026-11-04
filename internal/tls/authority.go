package tls

import (
	"bytes"
	stdtls "crypto/tls"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

var errStorage = errors.New("private TLS storage unavailable or unsafe")

// Only the final, application-owned directory is created. Existing parent paths
// may contain OS-managed aliases (for example macOS /var); keys stay under Root.
func openStore(dir string, create bool) (*os.Root, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, errStorage
	}
	info, e := os.Lstat(dir)
	created := false
	if errors.Is(e, fs.ErrNotExist) && create {
		if e = os.Mkdir(dir, 0700); e != nil {
			return nil, errStorage
		}
		created = true
		info, e = os.Lstat(dir)
	}
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errStorage
	}
	if e = privatePath(dir, true, created); e != nil {
		return nil, errStorage
	}
	r, e := os.OpenRoot(dir)
	if e != nil {
		return nil, errStorage
	}
	return r, nil
}
func readPrivate(r *os.Root, name string) ([]byte, error) {
	i, e := r.Lstat(name)
	if e != nil || !i.Mode().IsRegular() || i.Size() > 1<<20 {
		return nil, errStorage
	}
	if e = privatePath(filepath.Join(r.Name(), name), false, false); e != nil {
		return nil, errStorage
	}
	f, e := r.Open(name)
	if e != nil {
		return nil, errStorage
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		return nil, errStorage
	}
	return b, nil
}

// Save never overwrites a pre-existing authority or certificate. Partial stores
// fail closed; callers can select a new private location after reviewing them.
func (p TLSProposal) Save(dir string) error {
	if p.private == nil {
		return errStorage
	}
	r, e := openStore(dir, true)
	if e != nil {
		return e
	}
	defer r.Close()
	files := []struct {
		name string
		data []byte
	}{{"ca.crt", p.private.ca}, {"ca.key", p.private.caKey}, {"server.crt", p.private.cert}, {"server.key", p.private.key}}
	for _, f := range files {
		if len(f.data) == 0 {
			continue
		}
		if _, e = r.Lstat(f.name); e == nil {
			b, e := readPrivate(r, f.name)
			if e != nil || !bytes.Equal(b, f.data) {
				return errStorage
			}
		} else if !errors.Is(e, fs.ErrNotExist) {
			return errStorage
		}
	}
	for _, f := range files {
		if len(f.data) == 0 {
			continue
		}
		if _, e = r.Lstat(f.name); e == nil {
			continue
		}
		out, e := r.OpenFile(f.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return errStorage
		}
		if e = privatePath(filepath.Join(dir, f.name), false, true); e == nil {
			_, e = out.Write(f.data)
		}
		if e == nil {
			e = out.Sync()
		}
		ce := out.Close()
		if e != nil || ce != nil {
			return errStorage
		}
	}
	p.private.storageMu.Lock()
	p.private.storageDir = dir
	p.private.storageMu.Unlock()
	return nil
}
func Load(dir, address string) (TLSProposal, error) {
	r, e := openStore(dir, false)
	if e != nil {
		return TLSProposal{}, e
	}
	defer r.Close()
	c, e := readPrivate(r, "server.crt")
	if e != nil {
		return TLSProposal{}, e
	}
	k, e := readPrivate(r, "server.key")
	if e != nil {
		return TLSProposal{}, e
	}
	var ca []byte
	if _, e = r.Lstat("ca.crt"); e == nil {
		ca, e = readPrivate(r, "ca.crt")
		if e != nil {
			return TLSProposal{}, e
		}
	}
	p, e := PrepareTLS(address, ExistingTLS(c, k, ca))
	if e != nil {
		return TLSProposal{}, e
	}
	if _, e = r.Lstat("ca.key"); e == nil {
		p.private.caKey, e = readPrivate(r, "ca.key")
		if e != nil {
			return TLSProposal{}, e
		}
	}
	if len(p.private.caKey) > 0 {
		if _, e := stdtls.X509KeyPair(p.private.ca, p.private.caKey); e != nil {
			return TLSProposal{}, errStorage
		}
	}
	p.private.storageDir = dir
	return p, nil
}

// ReadyForDeployment rechecks genuine private local storage for an owned CA.
// External existing certificates have no CA private key and use manual trust.
func (p TLSProposal) ReadyForDeployment() error {
	if p.private == nil {
		return errStorage
	}
	if len(p.private.caKey) == 0 {
		return nil
	}
	p.private.storageMu.RLock()
	dir := p.private.storageDir
	p.private.storageMu.RUnlock()
	if dir == "" {
		return errStorage
	}
	stored, e := Load(dir, p.private.address)
	if e != nil {
		return errStorage
	}
	if !bytes.Equal(stored.private.caKey, p.private.caKey) || !bytes.Equal(stored.private.ca, p.private.ca) || !bytes.Equal(stored.private.cert, p.private.cert) || !bytes.Equal(stored.private.key, p.private.key) {
		return errStorage
	}
	return nil
}
