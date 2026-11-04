//go:build windows

package tls

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Protect newly created application-owned paths using an explicit non-inherited
// current-user/SYSTEM DACL. Existing paths must already carry this exact DACL.
func privatePath(path string, dir, created bool) error {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return errStorage
	}
	flags := ""
	if dir {
		flags = "OICI"
	}
	sddl := "D:P(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;" + user.User.Sid.String() + ")"
	expected, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		return errStorage
	}
	acl, _, e := expected.DACL()
	if e != nil {
		return errStorage
	}
	if created {
		e = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
		if e != nil {
			return errStorage
		}
	}
	actual, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil || actual.String() != expected.String() {
		return errStorage
	}
	return nil
}

// O_SYNC is mapped by Go to FILE_FLAG_WRITE_THROUGH; File.Sync additionally
// FlushFileBuffers. Windows does not offer POSIX-equivalent unprivileged parent
// directory fsync. New stores use documented write-through directory publication.
const durableWriteFlags = os.O_SYNC

func saveLocation(dir string, names []string) (string, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return "", errStorage
	}
	info, e := os.Lstat(dir)
	if e == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || privatePath(dir, true, false) != nil {
			return "", errStorage
		}
		root, e := os.OpenRoot(dir)
		if e != nil {
			return "", errStorage
		}
		f, e := root.Open(".")
		if e != nil {
			root.Close()
			return "", errStorage
		}
		entries, e := f.ReadDir(-1)
		ce := f.Close()
		root.Close()
		if e != nil || ce != nil {
			return "", errStorage
		}
		if len(entries) > 0 {
			if len(entries) != len(names) {
				return "", errStorage
			}
			allowed := map[string]bool{}
			for _, name := range names {
				allowed[name] = true
			}
			for _, entry := range entries {
				if !allowed[entry.Name()] || !entry.Type().IsRegular() {
					return "", errStorage
				}
			}
			return dir, nil
		}
		// A verified empty private destination has no authority to preserve. Remove
		// only this empty directory; publication below still refuses replacement.
		if e = os.Remove(dir); e != nil {
			return "", errStorage
		}
	} else if !errors.Is(e, fs.ErrNotExist) {
		return "", errStorage
	}
	stage, e := os.MkdirTemp(filepath.Dir(dir), ".xkeen-ca-stage-")
	if e != nil {
		return "", errStorage
	}
	if e = privatePath(stage, true, true); e != nil {
		return "", errStorage
	}
	return stage, nil
}
func publishStore(stage, dir string) error {
	source, e := windows.UTF16PtrFromString(stage)
	if e != nil {
		return errStorage
	}
	target, e := windows.UTF16PtrFromString(dir)
	if e != nil {
		return errStorage
	}
	const moveWriteThrough = 0x8
	if windows.MoveFileEx(source, target, moveWriteThrough) != nil {
		return errStorage
	}
	return nil
}
func syncStore(r *os.Root, _ string) error { return syncStoreFiles(r) }
