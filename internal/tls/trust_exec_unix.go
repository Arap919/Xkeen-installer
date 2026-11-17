//go:build !windows

package tls

import (
	"errors"
	"os"
	"runtime"
)

func trustedUtilityPaths(name string) ([]string, error) {
	var paths []string
	switch runtime.GOOS {
	case "darwin":
		if name == "osascript" || name == "/usr/bin/osascript" {
			paths = []string{"/usr/bin/osascript"}
		}
	case "linux":
		switch name {
		case "install":
			paths = []string{"/usr/bin/install", "/bin/install"}
		case "/usr/bin/install", "/bin/install":
			paths = []string{name}
		case "update-ca-certificates":
			paths = []string{"/usr/sbin/update-ca-certificates", "/sbin/update-ca-certificates"}
		case "/usr/sbin/update-ca-certificates", "/sbin/update-ca-certificates":
			paths = []string{name}
		}
	}
	if len(paths) == 0 {
		return nil, errors.New("unsupported trust utility")
	}
	return paths, nil
}

func trustUtilityExecutable(mode os.FileMode) bool { return mode.Perm()&0111 != 0 }

func trustCommandEnvironment() ([]string, error) {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}, nil
}
