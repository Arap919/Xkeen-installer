//go:build !windows

package tls

import (
	"io/fs"
	"os"
	"path/filepath"
)

func privatePath(path string, dir, created bool) error {
	info, e := os.Lstat(path)
	if e != nil {
		return errStorage
	}
	mode := fs.FileMode(0600)
	if dir {
		mode = 0700
	}
	if info.Mode().Perm() != mode || info.Mode()&os.ModeSymlink != 0 {
		return errStorage
	}
	return nil
}

const durableWriteFlags = 0

func saveLocation(dir string, _ []string) (string, error) { return dir, nil }
func publishStore(_, _ string) error                      { return errStorage } // Unix saves directly and syncs both directory entries.
func syncStore(r *os.Root, dir string) error {
	if e := syncStoreFiles(r); e != nil {
		return errStorage
	}
	store, e := r.Open(".")
	if e != nil {
		return errStorage
	}
	e = store.Sync()
	ce := store.Close()
	if e != nil || ce != nil {
		return errStorage
	}
	parent, e := os.Open(filepath.Dir(dir))
	if e != nil {
		return errStorage
	}
	e = parent.Sync()
	ce = parent.Close()
	if e != nil || ce != nil {
		return errStorage
	}
	return nil
}
