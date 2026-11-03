package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"testing"
)

type fakeTransport struct {
	files     map[string][]byte
	modes     map[string]fs.FileMode
	arch      string
	endian    string
	shell     bool
	free      uint64
	writes    int
	corrupt   bool
	failWrite bool
}

func fixture() *fakeTransport {
	return &fakeTransport{files: map[string][]byte{"/opt/bin/opkg": []byte("binary"), "/opt/etc/xray/configs/00.json": []byte("private-secret"), "/opt/etc/xray/configs/01.json": []byte("other"), "/opt/etc/init.d/S05crond": []byte("init"), "/opt/etc/xkeen-ui/tls/server.key": []byte("tls-secret"), "/opt/var/spool/cron/crontabs/root": []byte("cron")}, modes: map[string]fs.FileMode{}, arch: "aarch64", shell: true, free: 1 << 30}
}
func (f *fakeTransport) Run(_ context.Context, c string) (Result, error) {
	switch c {
	case shellProbe:
		if f.shell {
			return Result{Stdout: []byte("XKEEN_SHELL_OK\n")}, nil
		}
		return Result{Stdout: []byte("Keenetic CLI")}, nil
	case archProbe:
		return Result{Stdout: []byte(f.arch)}, nil
	case endianProbe:
		return Result{Stdout: []byte(" 127 69 76 70 1 1")}, nil
	case versionProbe:
		return Result{Stdout: []byte("Package: opkg\nVersion: 1\n")}, nil
	}
	return Result{}, errors.New("unexpected command")
}
func (f *fakeTransport) Read(_ context.Context, p string) ([]byte, error) {
	b, ok := f.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}
func (f *fakeTransport) Stat(_ context.Context, p string) (Entry, error) {
	if b, ok := f.files[p]; ok {
		return Entry{Path: p, Mode: f.mode(p), Size: int64(len(b))}, nil
	}
	for q := range f.files {
		if strings.HasPrefix(q, p+"/") {
			return Entry{Path: p, Mode: fs.ModeDir | 0700}, nil
		}
	}
	return Entry{}, fs.ErrNotExist
}
func (f *fakeTransport) mode(p string) fs.FileMode {
	if m, ok := f.modes[p]; ok {
		return m
	}
	return 0600
}
func (f *fakeTransport) ReadDir(ctx context.Context, p string) ([]Entry, error) {
	seen := map[string]bool{}
	var out []Entry
	for q := range f.files {
		if strings.HasPrefix(q, p+"/") {
			name := strings.Split(strings.TrimPrefix(q, p+"/"), "/")[0]
			if !seen[name] {
				seen[name] = true
				e, _ := f.Stat(ctx, path.Join(p, name))
				out = append(out, e)
			}
		}
	}
	return out, nil
}
func (f *fakeTransport) MkdirAll(_ context.Context, p string, m fs.FileMode) error {
	f.writes++
	return nil
}
func (f *fakeTransport) AvailableBytes(context.Context, string) (uint64, error) { return f.free, nil }
func (f *fakeTransport) WriteAtomic(_ context.Context, p string, b []byte, m fs.FileMode) error {
	f.writes++
	if f.failWrite {
		return errors.New("write failed")
	}
	f.files[p] = append([]byte(nil), b...)
	f.modes[p] = m
	if f.corrupt {
		f.files[p] = []byte("broken")
	}
	return nil
}
func TestInspectArchitecturesAndPrivateRecursiveInventory(t *testing.T) {
	for _, a := range []struct{ raw, want string }{{"aarch64", "arm64"}, {"mipsel", "mipsel"}, {"mips", "mipsel"}} {
		t.Run(a.raw, func(t *testing.T) {
			f := fixture()
			f.arch = a.raw
			s, err := Inspect(context.Background(), f)
			if err != nil {
				t.Fatal(err)
			}
			if string(s.Arch) != a.want || !s.Entware {
				t.Fatalf("bad snapshot: %+v", s)
			}
			if len(s.Files) != 5 {
				t.Fatalf("inventory: %v", s.Files)
			}
			b, _ := json.Marshal(s)
			if strings.Contains(string(b), "private-secret") || strings.Contains(string(b), "tls-secret") {
				t.Fatal("secret serialized")
			}
			data, ok := s.Config("/opt/etc/xray/configs/00.json")
			if !ok || string(data) != "private-secret" {
				t.Fatal("missing private config")
			}
			data[0] = 'X'
			again, _ := s.Config("/opt/etc/xray/configs/00.json")
			if string(again) != "private-secret" {
				t.Fatal("mutable snapshot")
			}
			if len(s.CronInit) != 1 || s.CronInit[0] != "/opt/etc/init.d/S05crond" {
				t.Fatal(s.CronInit)
			}
		})
	}
}
func TestInspectRejectsCLIUnknownCPUAndSymlink(t *testing.T) {
	for _, kind := range []string{"cli", "cpu", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture()
			switch kind {
			case "cli":
				f.shell = false
			case "cpu":
				f.arch = "riscv64"
			case "symlink":
				f.modes["/opt/etc/xray/configs/00.json"] = fs.ModeSymlink | 0777
			}
			if _, err := Inspect(context.Background(), f); err == nil {
				t.Fatal("expected refusal")
			}
			if f.writes != 0 {
				t.Fatal("inspection mutated router")
			}
		})
	}
}
func TestBackupVerifiedPrivateAndPermissionPreserving(t *testing.T) {
	f := fixture()
	f.modes["/opt/etc/init.d/S05crond"] = 0755
	s, err := Inspect(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Backup(context.Background(), f, s)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Verified() || len(m.Files) != 5 {
		t.Fatal(m)
	}
	for _, e := range m.Files {
		if string(f.files[m.Root+e.Path]) != string(f.files[e.Path]) || f.modes[m.Root+e.Path] != e.Mode {
			t.Fatal("copy mismatch")
		}
	}
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), "private-secret") {
		t.Fatal("manifest leaked content")
	}
}
func TestBackupFailuresDoNotAuthorizeMutation(t *testing.T) {
	for _, kind := range []string{"space", "corrupt", "write", "changed"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture()
			s, _ := Inspect(context.Background(), f)
			switch kind {
			case "space":
				f.free = 0
			case "corrupt":
				f.corrupt = true
			case "write":
				f.failWrite = true
			case "changed":
				f.files["/opt/etc/xray/configs/00.json"] = []byte("changed")
			}
			m, err := Backup(context.Background(), f, s)
			if err == nil || m.Verified() {
				t.Fatal("unsafe backup accepted")
			}
			if (kind == "space" || kind == "changed") && f.writes != 0 {
				t.Fatal("mutated before preflight")
			}
		})
	}
}

func TestSnapshotFormattingNeverPrintsPrivateBytes(t *testing.T) {
	f := fixture()
	s, err := Inspect(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{fmt.Sprintf("%v", s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s)} {
		if strings.Contains(text, "private-secret") || strings.Contains(text, "tls-secret") || strings.Contains(text, "112, 114, 105, 118, 97, 116, 101") || strings.Contains(text, "contents:") {
			t.Fatal("private bytes in public formatting")
		}
	}
}
func TestInspectAbsentEntwareAndUnrelatedSymlinks(t *testing.T) {
	f := fixture()
	delete(f.files, "/opt/bin/opkg")
	f.files["/opt/etc/localtime"] = []byte("ignored")
	f.modes["/opt/etc/localtime"] = fs.ModeSymlink | 0777
	s, err := Inspect(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if s.Entware {
		t.Fatal("missing opkg treated as installed")
	}
}

type bigEndianTransport struct{ *fakeTransport }

func (f bigEndianTransport) Run(ctx context.Context, c string) (Result, error) {
	if c == endianProbe {
		return Result{Stdout: []byte(" 127 69 76 70 1 2")}, nil
	}
	return f.fakeTransport.Run(ctx, c)
}
func TestInspectBigEndianMIPS(t *testing.T) {
	f := fixture()
	f.arch = "mips"
	s, err := Inspect(context.Background(), bigEndianTransport{f})
	if err != nil || string(s.Arch) != "mips" {
		t.Fatal(s, err)
	}
}
