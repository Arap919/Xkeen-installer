package router

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type HostKeyKind string

const (
	HostKeyFirstUse HostKeyKind = "first-use"
	HostKeyChanged  HostKeyKind = "changed"
)

// HostKeyError carries public identity only. The GUI must explicitly save an approved fingerprint.
type HostKeyError struct {
	Kind        HostKeyKind
	Address     string
	Fingerprint string
	Expected    string
	Algorithm   string
}

func (e *HostKeyError) Error() string {
	return "SSH host key " + string(e.Kind) + " at " + e.Address + " (" + e.Fingerprint + ")"
}

type SSHConfig struct {
	Address            string
	User               string
	Auth               []ssh.AuthMethod
	HostKeyFingerprint string
	Timeout            time.Duration
}
type SSHTransport struct {
	client *ssh.Client
	mu     sync.Mutex
	sftp   *sftp.Client
}

func DialSSH(ctx context.Context, c SSHConfig) (*SSHTransport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.Timeout <= 0 {
		c.Timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	config := &ssh.ClientConfig{User: c.User, Auth: c.Auth, HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		kind := HostKeyChanged
		if c.HostKeyFingerprint == "" {
			kind = HostKeyFirstUse
		} else if c.HostKeyFingerprint == fingerprint {
			return nil
		}
		return &HostKeyError{kind, c.Address, fingerprint, c.HostKeyFingerprint, key.Type()}
	}}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", c.Address)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	cc, chans, reqs, err := ssh.NewClientConn(conn, c.Address, config)
	close(done)
	if ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &SSHTransport{client: ssh.NewClient(cc, chans, reqs)}, nil
}
func (t *SSHTransport) Close() error { return t.client.Close() }

// Cancellation closes the connection, unblocking SSH/SFTP even during server stalls.
// Callers reconnect and inspect again; canceled commands may already have executed remotely.
func (t *SSHTransport) operation(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	case <-ctx.Done():
		t.client.Close()
		<-done
		return ctx.Err()
	}
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1<<20 {
		return 0, errors.New("SSH output limit exceeded")
	}
	return b.Buffer.Write(p)
}
func (t *SSHTransport) Run(ctx context.Context, command string) (Result, error) {
	var result Result
	err := t.operation(ctx, func() error {
		s, err := t.client.NewSession()
		if err != nil {
			return err
		}
		defer s.Close()
		var out, stderr limitedBuffer
		s.Stdout = &out
		s.Stderr = &stderr
		err = s.Run(command)
		result.Stdout = append([]byte(nil), out.Bytes()...)
		result.Stderr = append([]byte(nil), stderr.Bytes()...)
		if err != nil {
			var exit *ssh.ExitError
			if errors.As(err, &exit) {
				result.ExitCode = exit.ExitStatus()
				return nil
			}
			return errors.New("SSH command transport failed")
		}
		return nil
	})
	return result, err
}
func (t *SSHTransport) fileClient() (*sftp.Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sftp == nil {
		c, err := sftp.NewClient(t.client)
		if err != nil {
			return nil, errors.New("SFTP subsystem unavailable")
		}
		t.sftp = c
	}
	return t.sftp, nil
}

// checkPath rejects symlink ancestors beneath the selected /opt storage root.
func checkPath(c *sftp.Client, p string, missing bool) error {
	if err := safePath(p); err != nil {
		return err
	}
	parts := strings.Split(strings.TrimPrefix(p, "/opt/"), "/")
	current := "/opt"
	for _, part := range parts {
		current = path.Join(current, part)
		e, err := c.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) && missing {
			return nil
		}
		if err != nil {
			return err
		}
		if e.Mode()&fs.ModeSymlink != 0 {
			return ErrUnsafePath
		}
	}
	return nil
}
func (t *SSHTransport) Read(ctx context.Context, p string) ([]byte, error) {
	var data []byte
	err := t.operation(ctx, func() error {
		c, err := t.fileClient()
		if err != nil {
			return err
		}
		if err := checkPath(c, p, false); err != nil {
			return err
		}
		f, err := c.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("not a regular remote file")
		}
		data, err = io.ReadAll(io.LimitReader(f, maxInventoryBytes+1))
		if int64(len(data)) > maxInventoryBytes {
			return errors.New("remote file size limit exceeded")
		}
		return err
	})
	return data, err
}
func (t *SSHTransport) Stat(ctx context.Context, p string) (Entry, error) {
	var entry Entry
	err := t.operation(ctx, func() error {
		c, err := t.fileClient()
		if err != nil {
			return err
		}
		if err := safePath(p); err != nil {
			return err
		}
		if parent := path.Dir(p); parent != "/opt" {
			if err := checkPath(c, parent, false); err != nil {
				return err
			}
		}
		e, err := c.Lstat(p)
		if err != nil {
			return err
		}
		entry = Entry{p, e.Mode(), e.Size()}
		return nil
	})
	return entry, err
}
func (t *SSHTransport) ReadDir(ctx context.Context, p string) ([]Entry, error) {
	var entries []Entry
	err := t.operation(ctx, func() error {
		c, err := t.fileClient()
		if err != nil {
			return err
		}
		if err := checkPath(c, p, false); err != nil {
			return err
		}
		list, err := c.ReadDir(p)
		if err != nil {
			return err
		}
		for _, e := range list {
			if path.Base(e.Name()) != e.Name() || e.Name() == "." || e.Name() == ".." {
				return ErrUnsafePath
			}
			entries = append(entries, Entry{path.Join(p, e.Name()), e.Mode(), e.Size()})
		}
		return nil
	})
	return entries, err
}
func (t *SSHTransport) MkdirAll(ctx context.Context, p string, mode fs.FileMode) error {
	return t.operation(ctx, func() error {
		c, err := t.fileClient()
		if err != nil {
			return err
		}
		if err := checkPath(c, p, true); err != nil {
			return err
		}
		current := "/opt"
		for _, part := range strings.Split(strings.TrimPrefix(p, "/opt/"), "/") {
			current = path.Join(current, part)
			e, err := c.Lstat(current)
			if errors.Is(err, fs.ErrNotExist) {
				if err = c.Mkdir(current); err != nil {
					return err
				}
				if err = c.Chmod(current, mode.Perm()); err != nil {
					return err
				}
				continue
			}
			if err != nil {
				return err
			}
			if !e.IsDir() || e.Mode()&fs.ModeSymlink != 0 {
				return ErrUnsafePath
			}
			if strings.HasPrefix(current, "/opt/.xkeen-installer-backups") && e.Mode().Perm() != 0700 {
				return errors.New("backup directory is not private")
			}
		}
		return nil
	})
}
func (t *SSHTransport) AvailableBytes(ctx context.Context, p string) (uint64, error) {
	var available uint64
	err := t.operation(ctx, func() error {
		if p != "/opt" {
			if err := safePath(p); err != nil {
				return err
			}
		}
		c, err := t.fileClient()
		if err != nil {
			return err
		}
		s, err := c.StatVFS(p)
		if err != nil {
			return errors.New("SFTP free-space query unsupported or failed")
		}
		if s.Frsize != 0 && s.Bavail > ^uint64(0)/s.Frsize {
			return errors.New("invalid filesystem capacity")
		}
		available = s.Frsize * s.Bavail
		return nil
	})
	return available, err
}
func (t *SSHTransport) WriteAtomic(ctx context.Context, p string, data []byte, mode fs.FileMode) error {
	return t.operation(ctx, func() error {
		c, err := t.fileClient()
		if err != nil {
			return err
		}
		if err := checkPath(c, p, true); err != nil {
			return err
		}
		if mode&^fs.FileMode(0777) != 0 {
			return errors.New("unsupported file mode")
		}
		if _, ok := c.HasExtension("posix-rename@openssh.com"); !ok {
			return errors.New("atomic SFTP rename unsupported")
		}
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return err
		}
		temp := path.Join(path.Dir(p), ".xkeen-tmp-"+hex.EncodeToString(id))
		f, err := c.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err != nil {
			return err
		}
		defer c.Remove(temp)
		if err := f.Chmod(0600); err != nil {
			f.Close()
			return err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return err
		}
		if err := f.Chmod(mode.Perm()); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := checkPath(c, p, true); err != nil {
			return err
		}
		if err := c.PosixRename(temp, p); err != nil {
			return fmt.Errorf("atomic remote rename: %w", err)
		}
		return nil
	})
}
