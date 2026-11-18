package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Arap919/xkeen-installer/internal/catalog"
	smb2 "github.com/cloudsoda/go-smb2"
)

var errSMB = errors.New("SMB operation failed; verify prepared storage and permissions")
var smbDNS = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

func validSMBHost(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	return len(h) <= 253 && smbDNS.MatchString(h) && !strings.Contains(h, "..")
}
func validSMBShare(s string) bool {
	return len(s) > 0 && len(s) <= 80 && !strings.ContainsAny(s, "/\\:$\x00\r\n\t") && s != "." && s != ".." && strings.TrimSpace(s) == s
}

type diskFile interface {
	io.Reader
	io.Writer
	io.Closer
	Stat() (fs.FileInfo, error)
	Sync() error
}
type bootstrapDisk interface {
	Lstat(string) (fs.FileInfo, error)
	ReadDir(string) ([]fs.FileInfo, error)
	OpenFile(string, int, fs.FileMode) (diskFile, error)
	Mkdir(string, fs.FileMode) error
	Remove(string) error
	RenameNoReplace(string, string) error
	AvailableBytes() (uint64, error)
}
type smbDisk struct{ share *smb2.Share }

func (d smbDisk) Lstat(p string) (fs.FileInfo, error)     { return d.share.Lstat(p) }
func (d smbDisk) ReadDir(p string) ([]fs.FileInfo, error) { return d.share.ReadDir(p) }
func (d smbDisk) OpenFile(p string, f int, m fs.FileMode) (diskFile, error) {
	return d.share.OpenFile(p, f, m)
}
func (d smbDisk) Mkdir(p string, m fs.FileMode) error { return d.share.Mkdir(p, m) }
func (d smbDisk) Remove(p string) error               { return d.share.Remove(p) }
func (d smbDisk) RenameNoReplace(a, b string) error {
	// The local dependency delta emits ReplaceIfExists=0 in the SMB SET_INFO
	// request. Destination races fail at the server without replacing foreign bytes.
	return d.share.RenameNoReplace(a, b)
}
func (d smbDisk) AvailableBytes() (uint64, error) {
	st, e := d.share.Statfs(".")
	if e != nil {
		return 0, e
	}
	n, size := st.AvailableBlockCount(), st.BlockSize()
	if size == 0 || n > ^uint64(0)/size {
		return 0, errSMB
	}
	return n * size, nil
}

type smbStore struct {
	gate    chan struct{}
	conn    net.Conn
	session *smb2.Session
}

// DialStore uses existing SMB2/3 only. The caller already bound the exact share
// root to the freshly selected firmware UUID; SMB enumeration alone cannot do so.
// Credentials stay in transient NTLM state and are never persisted or logged.
func DialStore(ctx context.Context, host, user, password string) (Store, func() error, error) {
	if !validSMBHost(host) || user == "" || password == "" || strings.ContainsAny(user, "\x00\r\n") {
		return nil, nil, errSMB
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, e := (&net.Dialer{}).DialContext(bounded, "tcp", net.JoinHostPort(host, "445"))
	if e != nil {
		if bounded.Err() != nil {
			return nil, nil, bounded.Err()
		}
		return nil, nil, errSMB
	}
	stop := context.AfterFunc(bounded, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	session, e := negotiateSMB(bounded, conn, host, user, password)
	if e != nil {
		conn.Close()
		if bounded.Err() != nil {
			return nil, nil, bounded.Err()
		}
		return nil, nil, errSMB
	}
	if bounded.Err() != nil {
		conn.Close()
		return nil, nil, bounded.Err()
	}
	conn.SetDeadline(time.Time{})
	s := &smbStore{conn: conn, session: session, gate: make(chan struct{}, 1)}
	closeStore := func() error { return conn.Close() }
	return s, closeStore, nil
}

// negotiateSMB is independently exercised over a local wire harness. This only
// establishes negotiation failure/cancellation behavior, not SMB share I/O coverage.
func negotiateSMB(ctx context.Context, conn net.Conn, host, user, password string) (*smb2.Session, error) {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	initiator := &smb2.NTLMInitiator{User: user, Password: password}
	// Required signing also makes the dependency reject guest/null sessions;
	// there is no unsigned or anonymous fallback for storage preflight/publish.
	session, e := (&smb2.Dialer{Initiator: initiator, Negotiator: smb2.Negotiator{RequireMessageSigning: true}}).DialConn(ctx, conn, host)
	initiator.Password = ""
	if ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	if e != nil {
		conn.Close()
		return nil, errSMB
	}
	return session, nil
}
func (s *smbStore) operation(ctx context.Context, v Volume, a catalog.Artifact, fn func(bootstrapDisk) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	case <-bounded.Done():
		return bounded.Err()
	}
	if !validSMBShare(v.Share) {
		return errSMB
	}
	stop := context.AfterFunc(bounded, func() { s.conn.Close() })
	defer stop()
	deadline, _ := bounded.Deadline()
	s.conn.SetDeadline(deadline)
	defer s.conn.SetDeadline(time.Time{})
	session := s.session.WithContext(bounded)
	names, e := session.ListSharenames()
	if e != nil {
		if bounded.Err() != nil {
			return bounded.Err()
		}
		return errSMB
	}
	matches := 0
	for _, name := range names {
		if name == v.Share {
			matches++
		}
	}
	if matches != 1 {
		return errSMB
	}
	share, e := session.Mount(v.Share)
	if e != nil {
		if bounded.Err() != nil {
			return bounded.Err()
		}
		return errSMB
	}
	share = share.WithContext(bounded)
	defer share.Umount()
	e = fn(smbDisk{share})
	if bounded.Err() != nil {
		return bounded.Err()
	}
	if e != nil {
		return errSMB
	}
	return nil
}
func (s *smbStore) Check(ctx context.Context, v Volume, a catalog.Artifact) error {
	canonical, e := catalog.ResolveVersion(a.Component, a.Arch, a.Version)
	if e != nil || a.Component != catalog.Entware || canonical != a {
		return errors.New("Entware artifact metadata mismatch")
	}
	return s.operation(ctx, v, a, func(d bootstrapDisk) error {
		_, e := checkDisk(d, a, "")
		return e
	})
}
func (s *smbStore) Publish(ctx context.Context, v Volume, a catalog.Artifact, b []byte) error {
	// Rebind exact reviewed metadata before any remote mutation.
	if e := catalog.Verify(a, bytes.NewReader(b)); e != nil {
		return errors.New("Entware artifact verification failed")
	}
	return s.operation(ctx, v, a, func(d bootstrapDisk) error { return publishDisk(d, a, b) })
}
func verifyReadback(a catalog.Artifact, r io.Reader) error {
	if a.Size <= 0 || a.Size > 64<<20 || len(a.Integrity.SHA256) != 64 {
		return errSMB
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(r, a.Size+1))
	if e != nil {
		return errSMB
	}
	if n != a.Size || fmt.Sprintf("%x", h.Sum(nil)) != a.Integrity.SHA256 {
		return errors.New("SMB archive readback mismatch")
	}
	return nil
}
func readArchive(d bootstrapDisk, p string, a catalog.Artifact) error {
	st, e := d.Lstat(p)
	if e != nil || !st.Mode().IsRegular() || st.Size() != a.Size {
		return errSMB
	}
	f, e := d.OpenFile(p, os.O_RDONLY, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e = f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() != a.Size {
		return errSMB
	}
	return verifyReadback(a, f)
}
func checkRoot(d bootstrapDisk) error {
	root, e := d.Lstat(".")
	if e != nil || !root.IsDir() || root.Mode()&fs.ModeSymlink != 0 {
		return errSMB
	}
	entries, e := d.ReadDir(".")
	if e != nil {
		return e
	}
	for _, entry := range entries {
		switch strings.ToLower(entry.Name()) {
		case "bin", "etc", "lib", "libexec", "sbin", "usr":
			return errors.New("existing Entware tree")
		case "install":
			if entry.Name() != "install" {
				return errSMB
			}
		}
	}
	return nil
}

// checkDisk rejects partial Entware and foreign/uncertain install contents.
// An existing install directory is accepted only as the sole exact reviewed archive.
func checkDisk(d bootstrapDisk, a catalog.Artifact, ownTemp string) (bool, error) {
	if e := checkRoot(d); e != nil {
		return false, e
	}
	free, e := d.AvailableBytes()
	if e != nil || a.Size <= 0 || free < uint64(a.Size)*2 {
		return false, errSMB
	}
	st, e := d.Lstat("install")
	if errors.Is(e, fs.ErrNotExist) {
		return false, nil
	}
	if e != nil || !st.IsDir() || st.Mode()&fs.ModeSymlink != 0 {
		return false, errSMB
	}
	entries, e := d.ReadDir("install")
	if e != nil {
		return false, e
	}
	var other []fs.FileInfo
	for _, entry := range entries {
		if ownTemp != "" && entry.Name() == ownTemp {
			continue
		}
		other = append(other, entry)
	}
	if len(other) == 0 && ownTemp != "" {
		return false, nil
	}
	if len(other) != 1 || other[0].Name() != archiveName(a.Arch) {
		return false, errSMB
	}
	if e = readArchive(d, "install/"+archiveName(a.Arch), a); e != nil {
		return false, e
	}
	return true, nil
}
func publishDisk(d bootstrapDisk, a catalog.Artifact, data []byte) error {
	if e := verifyReadback(a, bytes.NewReader(data)); e != nil {
		return e
	}
	existing, e := checkDisk(d, a, "")
	if e != nil {
		return e
	}
	if existing {
		return nil
	}
	if e = d.Mkdir("install", 0700); e != nil {
		return e
	}
	// Only the directory created by this call can be removed, and Remove never recurses.
	defer d.Remove("install")
	id := make([]byte, 16)
	if _, e = rand.Read(id); e != nil {
		return e
	}
	name := ".xkeen-tmp-" + hex.EncodeToString(id)
	tmp := "install/" + name
	f, e := d.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer d.Remove(tmp)
	if n, writeErr := f.Write(data); writeErr != nil || n != len(data) {
		f.Close()
		return errSMB
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = readArchive(d, tmp, a); e != nil {
		return e
	}
	if existing, e = checkDisk(d, a, name); e != nil || existing {
		if e != nil {
			return e
		}
		return errSMB
	}
	if e = d.RenameNoReplace(tmp, "install/"+archiveName(a.Arch)); e != nil {
		return e
	}
	return readArchive(d, "install/"+archiveName(a.Arch), a)
}
