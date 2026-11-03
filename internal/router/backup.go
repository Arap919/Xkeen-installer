package router

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"path"
)

type BackupFile struct {
	Path   string
	Mode   fs.FileMode
	Size   int64
	SHA256 string
}
type BackupManifest struct {
	Root               string
	Files              []BackupFile
	Versions           map[string]string
	ActiveCore         string
	ActiveCoreEvidence string
	verified           bool
}

// Verified is true only for a manifest produced after successful copy and read-back.
func (m BackupManifest) Verified() bool { return m.verified }
func Backup(ctx context.Context, t Transport, s Snapshot) (BackupManifest, error) {
	fail := func(err error) (BackupManifest, error) { return BackupManifest{}, err }
	if !s.inspected {
		return fail(errors.New("backup requires inspected snapshot"))
	}
	var needed uint64 = 1 << 20
	// Recheck every source before the first remote write; a stale plan must be inspected again.
	for _, e := range s.Files {
		if err := safePath(e.Path); err != nil {
			return fail(err)
		}
		old, ok := s.contents[e.Path]
		if !ok {
			return fail(errors.New("snapshot inventory incomplete"))
		}
		current, err := t.Stat(ctx, e.Path)
		if err != nil {
			return fail(err)
		}
		if current.Mode != e.Mode || current.Size != e.Size {
			return fail(errors.New("source metadata changed; inspect again"))
		}
		b, err := t.Read(ctx, e.Path)
		if err != nil {
			return fail(err)
		}
		if !bytes.Equal(old, b) {
			return fail(errors.New("source changed; inspect again"))
		}
		needed += uint64(len(old)) + 4096
	}
	free, err := t.AvailableBytes(ctx, "/opt")
	if err != nil {
		return fail(err)
	}
	if free < needed {
		return fail(errors.New("insufficient backup space"))
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return fail(err)
	}
	m := BackupManifest{Root: "/opt/.xkeen-installer-backups/" + hex.EncodeToString(id), Versions: map[string]string{}, ActiveCore: s.ActiveCore, ActiveCoreEvidence: s.ActiveCoreEvidence}
	if err := t.MkdirAll(ctx, m.Root, 0700); err != nil {
		return fail(err)
	}
	for _, e := range s.Files {
		dest := m.Root + e.Path
		if err := t.MkdirAll(ctx, path.Dir(dest), 0700); err != nil {
			return fail(err)
		}
		b := s.contents[e.Path]
		if err := t.WriteAtomic(ctx, dest, b, e.Mode.Perm()); err != nil {
			return fail(err)
		}
		actual, err := t.Read(ctx, dest)
		if err != nil {
			return fail(err)
		}
		stat, err := t.Stat(ctx, dest)
		if err != nil {
			return fail(err)
		}
		if !bytes.Equal(b, actual) || stat.Mode.Perm() != e.Mode.Perm() {
			return fail(errors.New("backup verification failed"))
		}
		digest := sha256.Sum256(actual)
		m.Files = append(m.Files, BackupFile{e.Path, e.Mode, e.Size, hex.EncodeToString(digest[:])})
	}
	for k, v := range s.Versions {
		m.Versions[k] = v
	}
	m.verified = true
	return m, nil
}
