//go:build windows

package tls

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// Windows storage privacy is enforced by protected DACLs, not os.FileMode.
func storageDACL(t *testing.T, directory, allowEveryone bool) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	sddl := "D:P(A;" + flags + ";FA;;;SY)(A;" + flags + ";FA;;;" + user.User.Sid.String() + ")"
	if allowEveryone {
		sddl += "(A;" + flags + ";FR;;;WD)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	return sd
}

func TestWindowsPrivateStorageDACL(t *testing.T) {
	p, err := PrepareTLS("router.test", TLSState{})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "ca")
	if err := p.Save(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "ca.key", "ca.crt", "server.key", "server.crt"} {
		path := filepath.Join(dir, name)
		actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(path, err)
		}
		expected := storageDACL(t, name == "", false)
		if !samePrivateDACL(actual, expected) {
			t.Fatalf("storage DACL differs from protected current-user/SYSTEM policy: %s", path)
		}
	}
	if err := p.ReadyForDeployment(); err != nil {
		t.Fatal("private store did not retain deployment evidence", err)
	}
}

func TestWindowsPermissiveStorageDACLRejected(t *testing.T) {
	for _, target := range []string{"directory", "ca.key", "server.key"} {
		t.Run(target, func(t *testing.T) {
			p, err := PrepareTLS("router.test", TLSState{})
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), "ca")
			if err := p.Save(dir); err != nil {
				t.Fatal(err)
			}
			path := dir
			directory := target == "directory"
			if !directory {
				path = filepath.Join(dir, target)
			}
			sd := storageDACL(t, directory, true)
			dacl, _, err := sd.DACL()
			if err != nil {
				t.Fatal(err)
			}
			if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(dir, "router.test"); err == nil {
				t.Fatal("permissive storage loaded")
			}
			if err := p.Save(dir); err == nil {
				t.Fatal("permissive storage saved")
			}
			if err := p.ReadyForDeployment(); err == nil {
				t.Fatal("permissive storage retained deployment evidence")
			}
		})
	}
}

func TestWindowsPrivateDACLSemanticComparison(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	system := "(A;OICI;FA;;;SY)"
	owner := "(A;OICI;FA;;;" + sid + ")"
	expected, err := windows.SecurityDescriptorFromString("D:P" + system + owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, sddl string
		want       bool
	}{
		{"same", "D:P" + system + owner, true},
		{"auto-inheritance metadata", "D:PAI" + system + owner, true},
		{"reordered allow entries", "D:P" + owner + system, true},
		{"unprotected", "D:" + system + owner, false},
		{"extra reader", "D:P" + system + owner + "(A;OICI;FR;;;WD)", false},
		{"missing user", "D:P" + system, false},
		{"duplicate system", "D:P" + system + system, false},
		{"different mask", "D:P" + system + "(A;OICI;FR;;;" + sid + ")", false},
		{"different inheritance", "D:P" + system + "(A;;FA;;;" + sid + ")", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if got := samePrivateDACL(actual, expected); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
