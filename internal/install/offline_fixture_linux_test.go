package install

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arap919/xkeen-installer/internal/bootstrap"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/router"
)

// This transport is only used in an explicitly marked, disposable --network none
// Docker fixture. It cannot be enabled by a normal test invocation or a router.
type nativeOfflineFixture struct{ arch catalog.RouterArch }

func (n nativeOfflineFixture) Run(ctx context.Context, command string) (router.Result, error) {
	args := []string{"-c", command}
	program := "/bin/sh"
	if n.arch != catalog.ARM64 {
		program = "/usr/local/bin/proot"
		args = append([]string{"--kill-on-exit", "-0", "-q", "/usr/bin/qemu-" + string(n.arch) + "-static", "-r", "/fixture", "-b", "/opt", "-b", "/proc", "-b", "/dev", "-w", "/", "/opt/bin/sh"}, args...)
	}
	child := exec.CommandContext(ctx, program, args...)
	child.Env = append(os.Environ(), "OPKG_CONF_DIR=/opt/etc/opkg", "OFFLINE_ROOT=/must-not-use-inherited-root", "TMPDIR=/must-not-use-inherited-tmp")
	output, err := child.CombinedOutput()
	result := router.Result{Stdout: output}
	if err != nil {
		result.ExitCode = 1
	}
	return result, err
}
func (n nativeOfflineFixture) Read(_ context.Context, path string) ([]byte, error) {
	return os.ReadFile(path)
}
func (n nativeOfflineFixture) Stat(_ context.Context, path string) (router.Entry, error) {
	value, err := os.Lstat(path)
	if err != nil {
		return router.Entry{}, err
	}
	return router.Entry{Path: path, Mode: value.Mode(), Size: value.Size()}, nil
}
func (n nativeOfflineFixture) ReadDir(ctx context.Context, root string) ([]router.Entry, error) {
	values, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var entries []router.Entry
	for _, value := range values {
		entry, err := n.Stat(ctx, filepath.Join(root, value.Name()))
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
func (n nativeOfflineFixture) MkdirAll(_ context.Context, path string, mode fs.FileMode) error {
	return os.MkdirAll(path, mode)
}
func (n nativeOfflineFixture) AvailableBytes(context.Context, string) (uint64, error) {
	return 1 << 30, nil
}
func (n nativeOfflineFixture) WriteAtomic(_ context.Context, path string, data []byte, mode fs.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".fixture-write-")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err = temporary.Chmod(mode); err == nil {
		_, err = temporary.Write(data)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

func TestNativeOfflinePackagePhase(t *testing.T) {
	value := os.Getenv("XKEEN_OFFLINE_FIXTURE_ARCH")
	if value == "" {
		t.Skip("requires the disposable SEC-001 Docker fixture")
	}
	marker, err := os.ReadFile("/fixture-isolated")
	if err != nil || string(marker) != "SEC001_NETWORK_NONE\n" {
		t.Fatal("disposable fixture marker missing")
	}
	arch := catalog.RouterArch(value)
	if arch != catalog.ARM64 && arch != catalog.MIPS && arch != catalog.MIPSel {
		t.Fatal("unsupported fixture architecture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	transport := nativeOfflineFixture{arch: arch}
	repo, err := bootstrap.OfflineRepository(ctx, arch)
	if err != nil {
		t.Fatal(err)
	}
	roots := []string{"curl", "jq", "ip-full", "iptables", "ipset", "ca-bundle", "coreutils-uname", "coreutils-nohup", "conntrack", "cron", "python3", "ca-certificates", "python3-yaml", "wget-ssl"}
	targets, err := repo.DependencyVersions(roots)
	if err != nil {
		t.Fatal(err)
	}
	if err = inspectPackageFeeds(ctx, transport); err != nil {
		t.Fatal(err)
	}
	if err = inspectPackageState(ctx, transport, targets); err != nil {
		t.Fatal(err)
	}
	opkg, err := stageOfflineRepository(ctx, transport, "native-fixture", repo)
	if err != nil {
		t.Fatal(err)
	}
	// Both inherited configuration and stale default lists must be ignored.
	if err = os.MkdirAll("/opt/etc/opkg", 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/opt/etc/opkg/fixture-hostile.conf", []byte("src/gz hostile http://127.0.0.1:1/must-not-fetch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = inspectPackageFeeds(ctx, transport); !errors.Is(err, ErrInsecureFeeds) {
		t.Fatal("additional HTTP configuration accepted")
	}
	if err = os.MkdirAll("/opt/var/opkg-lists", 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/opt/var/opkg-lists/xkeen", []byte("Package: curl\nVersion: 99999\nFilename: http://127.0.0.1:1/must-not-fetch\n\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{opkg + " update", opkg + " install " + strings.Join(roots, " ")} {
		result, err := transport.Run(ctx, command)
		if err != nil || result.ExitCode != 0 {
			t.Fatalf("private offline opkg failed: %v\n%s", err, result.Stdout)
		}
		if strings.Contains(string(result.Stdout), "http://") || strings.Contains(string(result.Stdout), "https://") {
			t.Fatal("private opkg attempted a network source")
		}
	}
	watchdog, err := catalog.Resolve(catalog.Watchdog, arch)
	if err != nil {
		t.Fatal(err)
	}
	watchdogBytes, err := os.ReadFile("/watchdog.ipk")
	if err != nil || catalog.Verify(watchdog, bytes.NewReader(watchdogBytes)) != nil {
		t.Fatal("reviewed watchdog fixture missing or changed")
	}
	targets["router-watchdog"] = watchdog.Version
	if err = inspectPackageState(ctx, transport, targets); err != nil {
		t.Fatal(err)
	}
	watchdogPath := "/opt/.xkeen-installer-stage/native-fixture/watchdog.ipk"
	if err = writeChecked(ctx, transport, payload{path: watchdogPath, data: watchdogBytes, mode: 0600}); err != nil {
		t.Fatal(err)
	}
	result, err := transport.Run(ctx, opkg+" install "+quote(watchdogPath))
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("offline watchdog package failed: %v\n%s", err, result.Stdout)
	}
	if err = os.Remove("/opt/etc/opkg/fixture-hostile.conf"); err != nil {
		t.Fatal(err)
	}
	if err = inspectPackageFeeds(ctx, transport); err != nil {
		t.Fatal(err)
	}
	status, err := os.ReadFile("/opt/lib/opkg/status")
	if err != nil {
		t.Fatal(err)
	}
	bad := append(append([]byte(nil), status...), []byte("\n\nPackage: unrelated-fixture\nVersion: 1\nStatus: install ok unpacked\nArchitecture: all\n\n")...)
	if err = os.WriteFile("/opt/lib/opkg/status", bad, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll("/opt/lib/opkg/info", 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/opt/lib/opkg/info/unrelated-fixture.postinst", []byte("#!/bin/sh\ntouch /opt/fixture-unpacked-hook-ran\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = inspectPackageState(ctx, transport, targets); !errors.Is(err, ErrPackageState) {
		t.Fatal("unfinished unrelated package accepted")
	}
	if _, err = os.Stat("/opt/fixture-unpacked-hook-ran"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("guard executed unrelated hook")
	}
	// Harmless reproduction of the old behavior in isolation: skipping the guard
	// lets an unrelated unpacked postinst execute on an already-installed request.
	result, err = transport.Run(ctx, opkg+" install curl")
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("pending-hook reproduction failed: %v\n%s", err, result.Stdout)
	}
	if _, err = os.Stat("/opt/fixture-unpacked-hook-ran"); err != nil {
		t.Fatal("opkg did not reproduce pending-hook path")
	}
	if err = os.WriteFile("/opt/lib/opkg/status", status, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove("/opt/fixture-unpacked-hook-ran"); err != nil {
		t.Fatal(err)
	}
	modified := string(status)
	found := false
	blocks := strings.Split(modified, "\n\n")
	for i, block := range blocks {
		if strings.HasPrefix(block, "Package: curl\n") {
			lines := strings.Split(block, "\n")
			for j, line := range lines {
				if strings.HasPrefix(line, "Version: ") {
					lines[j] = "Version: 0"
					found = true
				}
			}
			blocks[i] = strings.Join(lines, "\n")
		}
	}
	if !found {
		t.Fatal("curl status missing")
	}
	if err = os.WriteFile("/opt/lib/opkg/status", []byte(strings.Join(blocks, "\n\n")), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/opt/lib/opkg/info/curl.prerm", []byte("#!/bin/sh\ntouch /opt/fixture-old-hook-ran\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = inspectPackageState(ctx, transport, targets); !errors.Is(err, ErrOldPackageHooks) {
		t.Fatal("unknown old upgrade hook accepted")
	}
	if _, err = os.Stat("/opt/fixture-old-hook-ran"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("guard executed old upgrade hook")
	}
	// Exercise the exact derivative's failure branch, with no CA/network import.
	if err = os.Remove("/opt/usr/lib/locale/locale-archive"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/opt/bin/localedef.new", []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	result, _ = transport.Run(ctx, "/opt/bin/env -i PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin /bin/sh /opt/lib/opkg/info/locales.postinst")
	if result.ExitCode == 0 || strings.Contains(string(result.Stdout), "Downloading...") {
		t.Fatal("locales failure branch did not fail without download")
	}
	t.Log("private opkg, hostile environment/config/stale lists, unfinished-state guard, old-hook guard, and locales failure branch verified")
}
