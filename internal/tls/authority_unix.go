//go:build !windows

package tls

import (
	"io/fs"
	"os"
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
