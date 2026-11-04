//go:build windows

package tls

import (
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
