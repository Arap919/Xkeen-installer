package router

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func sshFixture(t *testing.T) (string, ssh.Signer) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					c.Close()
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					if ch.ChannelType() != "session" {
						ch.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					channel, requests, err := ch.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer channel.Close()
						for r := range requests {
							if r.Type == "subsystem" {
								var subsystem struct{ Name string }
								if err := ssh.Unmarshal(r.Payload, &subsystem); err != nil || subsystem.Name != "sftp" {
									r.Reply(false, nil)
									continue
								}
								r.Reply(true, nil)
								handlers := sftp.InMemHandler()
								if err := handlers.FileCmd.Filecmd(&sftp.Request{Method: "Mkdir", Filepath: "/opt"}); err != nil {
									return
								}
								handlers.FileCmd.Filecmd(&sftp.Request{Method: "Mkdir", Filepath: "/opt/configs"})
								server := sftp.NewRequestServer(channel, handlers)
								defer server.Close()
								server.Serve()
								return
							} else if r.Type == "exec" {
								var command struct{ Command string }
								ssh.Unmarshal(r.Payload, &command)
								r.Reply(true, nil)
								switch command.Command {
								case "ok":
									channel.Write([]byte("safe-output"))
									channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
									return
								case "fail":
									channel.Stderr().Write([]byte("private"))
									channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{7}))
									return
								case "wait":
									for range requests {
									}
									return
								}
								r.Reply(false, nil)
							} else {
								r.Reply(false, nil)
							}
						}
					}()
				}
			}()
		}
	}()
	return l.Addr().String(), signer
}
func TestSSHRequiresExplicitFirstUseAndRejectsChangedKey(t *testing.T) {
	addr, key := sshFixture(t)
	_, err := DialSSH(context.Background(), SSHConfig{Address: addr, User: "root"})
	var host *HostKeyError
	if !errors.As(err, &host) || host.Kind != HostKeyFirstUse || host.Fingerprint != ssh.FingerprintSHA256(key.PublicKey()) {
		t.Fatalf("first use: %v", err)
	}
	_, err = DialSSH(context.Background(), SSHConfig{Address: addr, User: "root", HostKeyFingerprint: "SHA256:wrong"})
	if !errors.As(err, &host) || host.Kind != HostKeyChanged {
		t.Fatalf("changed: %v", err)
	}
}
func TestSSHPinnedCommandExitAndCancellation(t *testing.T) {
	addr, key := sshFixture(t)
	client, err := DialSSH(context.Background(), SSHConfig{Address: addr, User: "root", HostKeyFingerprint: ssh.FingerprintSHA256(key.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	r, err := client.Run(context.Background(), "ok")
	if err != nil || string(r.Stdout) != "safe-output" || r.ExitCode != 0 {
		t.Fatal(r, err)
	}
	r, err = client.Run(context.Background(), "fail")
	if err != nil || r.ExitCode != 7 {
		t.Fatal(r, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = client.Run(ctx, "wait")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatal("cancellation", err)
	}
}
func TestSSHCancelsHandshakeAndRefusesUnsafePaths(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e == nil {
			defer c.Close()
			buf := make([]byte, 100)
			for {
				if _, e = c.Read(buf); e != nil {
					return
				}
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err = DialSSH(ctx, SSHConfig{Address: l.Addr().String(), User: "root", HostKeyFingerprint: "SHA256:pinned"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	for _, p := range []string{"/etc/passwd", "/opt/../etc/shadow", "/opt/a\ncommand", "relative"} {
		if safePath(p) == nil {
			t.Fatal(p)
		}
	}
}

func TestSSHSFTPSafeAtomicRoundTrip(t *testing.T) {
	addr, key := sshFixture(t)
	client, err := DialSSH(context.Background(), SSHConfig{Address: addr, User: "root", HostKeyFingerprint: ssh.FingerprintSHA256(key.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()

	for _, content := range []string{"first private bytes", "replaced private bytes"} {
		if err := client.WriteAtomic(ctx, "/opt/configs/user's config.json", []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		b, err := client.Read(ctx, "/opt/configs/user's config.json")
		if err != nil || string(b) != content {
			t.Fatalf("round trip failed: %v", err)
		}
	}
	entries, err := client.ReadDir(ctx, "/opt/configs")
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary file leaked", err)
	}
	if err := client.WriteAtomic(ctx, "/opt/../escape", []byte("private"), 0600); !errors.Is(err, ErrUnsafePath) {
		t.Fatal("unsafe write allowed", err)
	}
}
