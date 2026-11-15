package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Arap919/xkeen-installer/internal/catalog"
)

// Local filesystem harness verifies adapter policy, not the SMB wire protocol.
type localDisk struct {
	root    string
	corrupt bool
}

func (d localDisk) Lstat(p string) (fs.FileInfo, error) {
	return os.Lstat(filepath.Join(d.root, filepath.FromSlash(p)))
}
func (d localDisk) ReadDir(p string) ([]fs.FileInfo, error) {
	es, e := os.ReadDir(filepath.Join(d.root, p))
	if e != nil {
		return nil, e
	}
	var out []fs.FileInfo
	for _, entry := range es {
		info, e := entry.Info()
		if e != nil {
			return nil, e
		}
		out = append(out, info)
	}
	return out, nil
}
func (d localDisk) OpenFile(p string, f int, m fs.FileMode) (diskFile, error) {
	return os.OpenFile(filepath.Join(d.root, filepath.FromSlash(p)), f, m)
}
func (d localDisk) Mkdir(p string, m fs.FileMode) error { return os.Mkdir(filepath.Join(d.root, p), m) }
func (d localDisk) Remove(p string) error {
	return os.Remove(filepath.Join(d.root, filepath.FromSlash(p)))
}
func (d localDisk) RenameNoReplace(a, b string) error {
	// A local hard link gives the harness atomic create-if-absent semantics.
	if d.corrupt {
		os.WriteFile(filepath.Join(d.root, filepath.FromSlash(a)), []byte("bad"), 0600)
	}
	if e := os.Link(filepath.Join(d.root, filepath.FromSlash(a)), filepath.Join(d.root, filepath.FromSlash(b))); e != nil {
		return e
	}
	return os.Remove(filepath.Join(d.root, filepath.FromSlash(a)))
}
func (d localDisk) AvailableBytes() (uint64, error) { return 1 << 30, nil }
func smbTestArchive() (catalog.Artifact, []byte) {
	b := []byte("reviewed archive")
	h := sha256.Sum256(b)
	return catalog.Artifact{Component: catalog.Entware, Arch: catalog.ARM64, URL: "https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz", Size: int64(len(b)), Integrity: catalog.Integrity{SHA256: fmt.Sprintf("%x", h)}}, b
}
func TestSMBDiskPreservesExistingTreesAndUncertainInstall(t *testing.T) {
	for _, entry := range []string{"bin", "etc", "lib", "libexec", "sbin", "usr", "BIN", "install/foreign.tar.gz", "install/partial"} {
		t.Run(entry, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, entry)
			os.MkdirAll(filepath.Dir(p), 0700)
			os.WriteFile(p, []byte("preserve"), 0600)
			a, _ := smbTestArchive()
			if _, e := checkDisk(localDisk{root: root}, a, ""); e == nil {
				t.Fatal("existing data allowed")
			}
			got, _ := os.ReadFile(p)
			if string(got) != "preserve" {
				t.Fatal("existing data changed")
			}
		})
	}
}
func TestSMBDiskRejectsSymlinkInstallAndRoot(t *testing.T) {
	root := t.TempDir()
	os.Symlink(t.TempDir(), filepath.Join(root, "install"))
	a, _ := smbTestArchive()
	if _, e := checkDisk(localDisk{root: root}, a, ""); e == nil {
		t.Fatal("symlink install allowed")
	}
	outer := t.TempDir()
	link := filepath.Join(outer, "link")
	os.Symlink(root, link)
	if _, e := checkDisk(localDisk{root: link}, a, ""); e == nil {
		t.Fatal("symlink root allowed")
	}
}
func TestSMBPublishAtomicReadbackAndIdempotence(t *testing.T) {
	root := t.TempDir()
	d := localDisk{root: root}
	a, b := smbTestArchive()
	if e := publishDisk(d, a, b); e != nil {
		t.Fatal(e)
	}
	if e := publishDisk(d, a, b); e != nil {
		t.Fatal("idempotence", e)
	}
	got, _ := os.ReadFile(filepath.Join(root, "install", "aarch64-installer.tgz"))
	if !bytes.Equal(got, b) {
		t.Fatal("published bytes differ")
	}
	files, _ := os.ReadDir(filepath.Join(root, "install"))
	if len(files) != 1 {
		t.Fatal("temporary data leaked")
	}
}
func TestSMBPublishRejectsBadBytesForeignTargetAndCorruption(t *testing.T) {
	for _, mode := range []string{"payload", "foreign", "readback"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			d := localDisk{root: root, corrupt: mode == "readback"}
			a, b := smbTestArchive()
			if mode == "payload" {
				b = []byte("bad")
			}
			if mode == "foreign" {
				os.Mkdir(filepath.Join(root, "install"), 0700)
				os.WriteFile(filepath.Join(root, "install", "aarch64-installer.tgz"), []byte("foreign"), 0600)
			}
			if e := publishDisk(d, a, b); e == nil {
				t.Fatal("invalid publication succeeded")
			}
			if mode == "foreign" {
				got, _ := os.ReadFile(filepath.Join(root, "install", "aarch64-installer.tgz"))
				if string(got) != "foreign" {
					t.Fatal("foreign file changed")
				}
			}
		})
	}
}
func TestSMBBoundedReadbackRejectsOversize(t *testing.T) {
	a, b := smbTestArchive()
	if e := verifyReadback(a, io.MultiReader(bytes.NewReader(b), bytes.NewReader([]byte("extra")))); e == nil {
		t.Fatal("oversize accepted")
	}
}
func TestSMBHostAndShareValidation(t *testing.T) {
	for _, host := range []string{"http://router", "router:445", "router/path", "user@router", "router\n", ""} {
		if validSMBHost(host) {
			t.Fatal("unsafe host", host)
		}
	}
	for _, host := range []string{"192.168.1.1", "router.local", "::1"} {
		if !validSMBHost(host) {
			t.Fatal("valid host rejected", host)
		}
	}
	for _, share := range []string{"../disk", "disk/sub", "disk\\sub", "disk$", ""} {
		if validSMBShare(share) {
			t.Fatal("unsafe share", share)
		}
	}
}

func TestSMBNegotiationRequiresSigningOnWire(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	mode := make(chan uint16, 1)
	go func() {
		defer server.Close()
		header := make([]byte, 4)
		if _, err := io.ReadFull(server, header); err != nil {
			mode <- 0
			return
		}
		n := binary.BigEndian.Uint32(header)
		if n < 70 || n > 65536 {
			mode <- 0
			return
		}
		request := make([]byte, n)
		if _, err := io.ReadFull(server, request); err != nil {
			mode <- 0
			return
		}
		// SMB2 NEGOTIATE SecurityMode is uint16 at body offset 4 (packet offset 68).
		// Bit 0x0002 is SIGNING_REQUIRED, not merely SIGNING_ENABLED (0x0001).
		mode <- binary.LittleEndian.Uint16(request[68:70])
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	session, err := negotiateSMB(ctx, client, "router", "admin", "private-password")
	if session != nil || err == nil || err.Error() != errSMB.Error() {
		t.Fatal("closed fixture negotiation not private", err)
	}
	select {
	case got := <-mode:
		if got&0x0002 == 0 {
			t.Fatalf("SMB wire does not require signing: security mode %#x", got)
		}
	case <-ctx.Done():
		t.Fatal("SMB negotiation fixture stalled")
	}
}

func TestSMBNegotiationCancellationClosesWire(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, server); close(done) }()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := negotiateSMB(ctx, client, "router", "admin", "private-password")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatal("handshake cancellation", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handshake wire not closed")
	}
}
func TestSMBNegotiationRejectsMalformedWirePrivately(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		header := make([]byte, 4)
		if _, e := io.ReadFull(server, header); e != nil {
			return
		}
		n := binary.BigEndian.Uint32(header)
		if n > 65536 {
			return
		}
		if _, e := io.CopyN(io.Discard, server, int64(n)); e != nil {
			return
		}
		server.Write([]byte{0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := negotiateSMB(ctx, client, "router", "admin", "private-password")
	client.Close()
	if err == nil || err.Error() != errSMB.Error() {
		t.Fatal("malformed SMB wire accepted or exposed", err)
	}
}
