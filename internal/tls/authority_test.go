package tls

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStoragePrivateAndUnsafePaths(t *testing.T) {
	p, _ := PrepareTLS("router.test", TLSState{})
	dir := filepath.Join(t.TempDir(), "ca")
	if e := p.Save(dir); e != nil {
		t.Fatal(e)
	}
	for _, n := range []string{"ca.key", "ca.crt", "server.key", "server.crt"} {
		i, e := os.Stat(filepath.Join(dir, n))
		if e != nil || i.Mode().Perm() != 0600 {
			t.Fatal(n, e)
		}
	}
	i, _ := os.Stat(dir)
	if i.Mode().Perm() != 0700 {
		t.Fatal(i.Mode())
	}
	q, e := Load(dir, "router.test")
	if e != nil {
		t.Fatal(e)
	}
	a, b, _ := p.ServerPair()
	c, d, _ := q.ServerPair()
	if !bytes.Equal(a, c) || !bytes.Equal(b, d) {
		t.Fatal("bytes changed")
	}
	if e = p.Save(dir); e != nil {
		t.Fatal("idempotent save", e)
	}
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(dir, link)
	if p.Save(link) == nil {
		t.Fatal("symlink")
	}
	if p.Save(dir+"/../bad") == nil {
		t.Fatal("unclean")
	}
	os.Remove(filepath.Join(dir, "server.key"))
	os.Symlink(filepath.Join(dir, "ca.key"), filepath.Join(dir, "server.key"))
	if _, e = Load(dir, "router.test"); e == nil {
		t.Fatal("linked key")
	}
}

type fakeCommands struct {
	calls       int
	unavailable bool
}

func (f *fakeCommands) LookPath(n string) (string, error) {
	if f.unavailable {
		return "", os.ErrNotExist
	}
	return "/usr/bin/" + n, nil
}
func (f *fakeCommands) Run(context.Context, string, ...string) error { f.calls++; return nil }
func TestTrustApprovalExactCA(t *testing.T) {
	p, _ := PrepareTLS("router.test", TLSState{})
	dir := filepath.Join(t.TempDir(), "ca")
	if e := p.Save(dir); e != nil {
		t.Fatal(e)
	}
	a, e := p.TrustAction("darwin", dir)
	if e != nil {
		t.Fatal(e)
	}
	f := &fakeCommands{}
	r := ApplyTrust(context.Background(), a, "", false, f)
	if r.Status != TrustPending || f.calls != 0 {
		t.Fatal(r)
	}
	r = ApplyTrust(context.Background(), a, a.ID, true, f)
	if r.Status != TrustInstalled || f.calls != 1 {
		t.Fatal(r)
	}
	f.unavailable = true
	r = ApplyTrust(context.Background(), a, a.ID, true, f)
	if r.Status != TrustManual || f.calls != 1 {
		t.Fatal(r)
	}
}

func TestTrustPlatformsTamperingAndRefusal(t *testing.T) {
	p, _ := PrepareTLS("router.test", TLSState{})
	dir := filepath.Join(t.TempDir(), "ca")
	if e := p.Save(dir); e != nil {
		t.Fatal(e)
	}
	for _, platform := range []string{"windows", "darwin", "linux"} {
		a, e := p.TrustAction(platform, dir)
		if e != nil {
			t.Fatal(e)
		}
		f := &fakeCommands{}
		original := a
		a.Description = "changed operation"
		if r := ApplyTrust(context.Background(), a, a.ID, true, f); r.Status != TrustPending || f.calls != 0 {
			t.Fatal("tampered action executed")
		}
		a = original
		if r := ApplyTrust(context.Background(), a, "wrong CA", true, f); r.Status != TrustPending || f.calls != 0 {
			t.Fatal("wrong approval executed")
		}
		var encoded []byte
		encoded, _ = json.Marshal(a)
		var deserialized TrustAction
		json.Unmarshal(encoded, &deserialized)
		if r := ApplyTrust(context.Background(), deserialized, deserialized.ID, true, f); r.Status != TrustPending || f.calls != 0 {
			t.Fatal("serialized action executed")
		}
		for _, command := range a.commands {
			if command.name == "sudo" || command.name == "pkexec" {
				t.Fatal("hidden privilege elevation")
			}
			for _, arg := range command.args {
				if strings.Contains(arg, "PRIVATE KEY") {
					t.Fatal("key argv")
				}
			}
		}
		declined := &failingCommands{}
		if r := ApplyTrust(context.Background(), a, a.ID, true, declined); r.Status != TrustPending {
			t.Fatal("trust refusal not pending", r)
		}
	}
}

type failingCommands struct{}

func (*failingCommands) LookPath(n string) (string, error) { return n, nil }
func (*failingCommands) Run(context.Context, string, ...string) error {
	return errors.New("private failure text")
}
func TestUnsafeStoragePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes only")
	}
	p, _ := PrepareTLS("router.test", TLSState{})
	dir := filepath.Join(t.TempDir(), "ca")
	if e := p.Save(dir); e != nil {
		t.Fatal(e)
	}
	os.Chmod(filepath.Join(dir, "ca.key"), 0644)
	if _, e := Load(dir, "router.test"); e == nil {
		t.Fatal("open CA key accepted")
	}
	os.Chmod(dir, 0755)
	if p.Save(dir) == nil {
		t.Fatal("open store accepted")
	}
}

func TestStoreDirectorySyncFailureCannotMintEvidence(t *testing.T) {
	p, _ := PrepareTLS("router.test", TLSState{})
	dir := filepath.Join(t.TempDir(), "ca")
	calls := 0
	failSync := func(r *os.Root, path string) error {
		calls++
		if path != dir {
			t.Error("wrong sync directory")
		}
		for _, name := range []string{"ca.crt", "ca.key", "server.crt", "server.key"} {
			if _, e := r.Lstat(name); e != nil {
				t.Error("sync before file entries", name)
			}
		}
		return errors.New("sync failed")
	}
	if e := p.save(dir, failSync); e == nil {
		t.Fatal("failed directory sync accepted")
	}
	if calls != 1 || p.private.storageDir != "" || p.ReadyForDeployment() == nil {
		t.Fatal("failed save minted evidence")
	}
	if _, e := load(dir, "router.test", failSync); e == nil {
		t.Fatal("load bypassed failed directory sync")
	}
	if e := p.save(dir, failSync); e == nil {
		t.Fatal("repeated save bypassed sync")
	}
	if e := p.Save(dir); e != nil {
		t.Fatal(e)
	}
	if e := p.save(dir, failSync); e == nil || p.private.storageDir != "" || p.ReadyForDeployment() == nil {
		t.Fatal("failed resave retained prior evidence")
	}
	q, e := Load(dir, "router.test")
	if e != nil || q.ReadyForDeployment() != nil {
		t.Fatal("successful durable retry", e)
	}
}
