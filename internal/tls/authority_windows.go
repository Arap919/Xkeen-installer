//go:build windows

package tls

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Protect newly created application-owned paths using an explicit non-inherited
// current-user/SYSTEM DACL. Existing paths must already carry this exact DACL.
func privatePath(path string, dir, created bool) (failure error) {
	operation := "WINDOWS_TOKEN"
	defer func() {
		if failure != nil {
			failure = &StorageError{Operation: operation, cause: failure}
		}
	}()
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return errStorage
	}
	flags := ""
	if dir {
		flags = "OICI"
	}
	sddl := "D:P(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;" + user.User.Sid.String() + ")"
	operation = "WINDOWS_DACL_BUILD"
	expected, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		return errStorage
	}
	acl, _, e := expected.DACL()
	if e != nil {
		return errStorage
	}
	if created {
		operation = "WINDOWS_DACL_SET"
		e = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
		if e != nil {
			return errStorage
		}
	}
	operation = "WINDOWS_DACL_READ"
	actual, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return errStorage
	}
	operation = "WINDOWS_DACL_COMPARE"
	if !samePrivateDACL(actual, expected) {
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
		return "", e
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

// Compare access rules rather than SDDL formatting/control metadata such as AI.
// Require protected non-null DACLs with exactly the reviewed allow ACEs; only
// ACE ordering may differ. Masks, inheritance flags and SID bytes remain exact.
func samePrivateDACL(actual, expected *windows.SECURITY_DESCRIPTOR) bool {
	control, _, err := actual.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 || control&windows.SE_DACL_PRESENT == 0 {
		return false
	}
	a, _, err := actual.DACL()
	if err != nil || a == nil {
		return false
	}
	e, _, err := expected.DACL()
	if err != nil || e == nil || e.AceCount != 2 || a.AceCount != e.AceCount {
		return false
	}
	matched := make([]bool, int(e.AceCount))
	for i := uint32(0); i < uint32(a.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(a, i, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < 8 || ace.Header.AceSize > 1024 {
			return false
		}
		found := false
		for j := uint32(0); j < uint32(e.AceCount); j++ {
			if matched[j] {
				continue
			}
			var want *windows.ACCESS_ALLOWED_ACE
			if windows.GetAce(e, j, &want) != nil || want == nil {
				return false
			}
			if ace.Header.AceSize == want.Header.AceSize && bytes.Equal(unsafe.Slice((*byte)(unsafe.Pointer(ace)), int(ace.Header.AceSize)), unsafe.Slice((*byte)(unsafe.Pointer(want)), int(want.Header.AceSize))) {
				matched[j] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	runtime.KeepAlive(actual)
	runtime.KeepAlive(expected)
	return true
}
