package tls

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func trustedUtilityPaths(name string) ([]string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil || !filepath.IsAbs(dir) {
		return nil, errors.New("system directory unavailable")
	}
	path := filepath.Join(dir, "certutil.exe")
	if name != "certutil" && !strings.EqualFold(name, path) {
		return nil, errors.New("unsupported trust utility")
	}
	return []string{path}, nil
}

// Windows executability is determined by the fixed .exe utility, not POSIX bits.
func trustUtilityExecutable(os.FileMode) bool { return true }

func trustCommandEnvironment() ([]string, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil || !filepath.IsAbs(system) {
		return nil, errors.New("system directory unavailable")
	}
	root, err := windows.GetWindowsDirectory()
	if err != nil || !filepath.IsAbs(root) {
		return nil, errors.New("Windows directory unavailable")
	}
	return []string{"PATH=" + system, "SystemRoot=" + root, "WINDIR=" + root, "LANG=C", "LC_ALL=C"}, nil
}
