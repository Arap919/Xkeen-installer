package tls

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestExecRunnerRejectsHostilePATH(t *testing.T) {
	dir := t.TempDir()
	name := "untrusted-trust-tool"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(dir, name)
	marker := filepath.Join(dir, "executed")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n: > \""+marker+"\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if found, err := (ExecRunner{}).LookPath(name); err == nil {
		t.Fatalf("resolved hostile utility: %s", found)
	}
	if err := (ExecRunner{}).Run(context.Background(), path); err == nil {
		t.Fatal("ran a utility outside trusted system locations")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("hostile utility executed")
	}
}

func TestExecRunnerIgnoresShadowedTrustUtility(t *testing.T) {
	dir := t.TempDir()
	name := "install"
	if runtime.GOOS == "darwin" {
		name = "osascript"
	}
	if runtime.GOOS == "windows" {
		name = "certutil"
	}
	filename := name
	if runtime.GOOS == "windows" {
		filename += ".exe"
	}
	fake := filepath.Join(dir, filename)
	marker := filepath.Join(dir, "executed")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n: > \""+marker+"\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	found, err := (ExecRunner{}).LookPath(name)
	if err == nil && (found == fake || !filepath.IsAbs(found)) {
		t.Fatalf("resolved hostile utility: %s", found)
	}
	if err := (ExecRunner{}).Run(context.Background(), fake); err == nil {
		t.Fatal("accepted hostile absolute utility")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("hostile utility executed")
	}
}

func TestTrustUtilityAvailability(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	if _, err := availableTrustUtility([]string{missing, dir}); err == nil {
		t.Fatal("accepted missing utility or directory")
	}
	file := filepath.Join(dir, "utility")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if _, err := availableTrustUtility([]string{file}); err == nil {
			t.Fatal("accepted non-executable utility")
		}
	}
	if err := os.Chmod(file, 0700); err != nil {
		t.Fatal(err)
	}
	if path, err := availableTrustUtility([]string{missing, file}); err != nil || path != file {
		t.Fatalf("available candidate: %q %v", path, err)
	}
}

func TestTrustCommandPreservesArgvAndClearsEnvironment(t *testing.T) {
	name := "install"
	if runtime.GOOS == "darwin" {
		name = "osascript"
	}
	if runtime.GOOS == "windows" {
		name = "certutil"
	}
	path, err := (ExecRunner{}).LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "OPENSSL_CONF", "SystemRoot", "WINDIR"} {
		t.Setenv(key, "hostile inherited value")
	}
	args := []string{"-option", filepath.Join(t.TempDir(), `CA with spaces 'and "quotes"`, "ca.crt")}
	cmd, err := trustExecCommand(context.Background(), path, args...)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cmd.Args[1:], args) {
		t.Fatalf("argv changed: %#v", cmd.Args)
	}
	env := map[string]string{}
	for _, entry := range cmd.Env {
		key, value, _ := strings.Cut(entry, "=")
		env[key] = value
		if strings.Contains(value, "hostile") {
			t.Fatalf("inherited environment: %s", key)
		}
	}
	if env["PATH"] == "" || env["LANG"] != "C" || env["LC_ALL"] != "C" {
		t.Fatalf("missing controlled environment: %#v", env)
	}
	for _, key := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "OPENSSL_CONF"} {
		if _, ok := env[key]; ok {
			t.Fatalf("unsafe variable: %s", key)
		}
	}
	if runtime.GOOS == "windows" && (env["SystemRoot"] == "" || env["WINDIR"] == "") {
		t.Fatal("missing OS-derived Windows directories")
	}
}

type noTrustCommands struct{ t *testing.T }

func (r noTrustCommands) LookPath(string) (string, error) {
	r.t.Fatal("decline resolved a command")
	return "", os.ErrNotExist
}
func (r noTrustCommands) Run(context.Context, string, ...string) error {
	r.t.Fatal("decline ran a command")
	return nil
}

func TestTrustDeclineNeverResolvesUtilities(t *testing.T) {
	p, err := PrepareTLS("router.test", TLSState{})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "ca")
	if err := p.Save(dir); err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"darwin", "linux", "windows"} {
		a, err := p.TrustAction(platform, dir)
		if err != nil {
			t.Fatal(err)
		}
		if result := ApplyTrust(context.Background(), a, a.ID, false, noTrustCommands{t}); result.Status != TrustPending || result.Code != "approval_required" {
			t.Fatal(result)
		}
	}
}
