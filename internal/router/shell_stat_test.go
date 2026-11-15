package router

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"golang.org/x/crypto/ssh"
)

func statFixtureClient(t *testing.T, script string) *SSHTransport {
	t.Helper()
	addr, key := sshFixtureWithStat(t, script, true)
	client, err := DialSSH(context.Background(), SSHConfig{Address: addr, User: "root", HostKeyFingerprint: ssh.FingerprintSHA256(key.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func TestShellStatBusyBoxTerseMetadata(t *testing.T) {
	client := statFixtureClient(t, busyBoxStatFixture)
	ctx := context.Background()
	p := "/opt/user's $(touch HACKED); [config]*"
	r, err := client.Run(ctx, "printf abc > "+shellQuote(p)+"; chmod 7754 "+shellQuote(p)+"; mkdir '/opt/directory'; ln -s "+shellQuote(p)+" '/opt/link'; ln -s '/opt/missing' '/opt/dangling'; mkfifo '/opt/fifo'")
	if err != nil || r.ExitCode != 0 {
		t.Fatal(r, err)
	}
	for _, tc := range []struct {
		path string
		mode fs.FileMode
		size int64
	}{
		{p, 0754 | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky, 3},
		{"/opt/directory", fs.ModeDir | 0700, -1},
		{"/opt/link", fs.ModeSymlink, -1},
		{"/opt/dangling", fs.ModeSymlink, -1},
		{"/opt/fifo", fs.ModeIrregular, -1},
	} {
		t.Run(tc.path, func(t *testing.T) {
			e, err := client.Stat(ctx, tc.path)
			if err != nil || e.Path != tc.path || e.Mode.Type() != tc.mode.Type() || tc.size >= 0 && e.Size != tc.size {
				t.Fatalf("metadata = %+v, %v; want mode %v, size %d", e, err, tc.mode, tc.size)
			}
			if tc.path == p && e.Mode != tc.mode {
				t.Fatalf("permission bits = %v; want %v", e.Mode, tc.mode)
			}
		})
	}
	if _, err := client.Stat(ctx, "/opt/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing entry: %v", err)
	}
	if _, err := client.Stat(ctx, "/opt/link/child"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink ancestor: %v", err)
	}
	r, err = client.Run(ctx, "[ ! -e HACKED ]")
	if err != nil || r.ExitCode != 0 {
		t.Fatal("filename was evaluated as shell source", r, err)
	}
}

func TestShellStatRejectsMalformedTerseMetadata(t *testing.T) {
	for name, record := range map[string]string{
		"empty":              "",
		"missing mode":       "$2 3 8",
		"bad prefix":         "other 3 8 81a4 0 0",
		"invalid mode":       "$2 3 8 xyz 0 0",
		"mode overflow":      "$2 3 8 1000081a4 0 0",
		"unknown mode bits":  "$2 3 8 181a4 0 0",
		"directory mismatch": "$2 3 8 41ed 0 0",
		"negative size":      "$2 -1 8 81a4 0 0",
		"signed size":        "$2 +3 8 81a4 0 0",
		"invalid size":       "$2 x 8 81a4 0 0",
		"size overflow":      "$2 9223372036854775808 8 81a4 0 0",
	} {
		t.Run(name, func(t *testing.T) {
			client := statFixtureClient(t, "#!/bin/sh\nprintf '%s\\n' \""+record+"\"\n")
			ctx := context.Background()
			if r, err := client.Run(ctx, "printf abc > '/opt/config'"); err != nil || r.ExitCode != 0 {
				t.Fatal(r, err)
			}
			if e, err := client.Stat(ctx, "/opt/config"); err == nil {
				t.Fatalf("accepted malformed metadata: %+v", e)
			}
		})
	}
}
