package router

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// This SSH protocol fixture never starts a host shell or executes its input.
func cliFixture(t *testing.T, mode string) (*SSHTransport, <-chan string) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if string(p) != "fixture-password" {
			return nil, errors.New("private-auth")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	commands := make(chan string, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		conn, chs, reqs, e := ssh.NewServerConn(c, cfg)
		if e != nil {
			return
		}
		defer conn.Close()
		go ssh.DiscardRequests(reqs)
		for ch := range chs {
			channel, rs, e := ch.Accept()
			if e != nil {
				return
			}
			go func() {
				defer channel.Close()
				pty := false
				for r := range rs {
					switch r.Type {
					case "pty-req":
						pty = true
						r.Reply(mode != "reject", nil)
					case "shell":
						r.Reply(pty, nil)
						if !pty {
							return
						}
						io.WriteString(channel, "KeeneticOS fixture\r\n(config)> ")
						scanner := bufio.NewScanner(channel)
						var lines []string
						if !scanner.Scan() {
							return
						}
						lines = append(lines, scanner.Text())
						if mode == "stall" {
							for range rs {
							}
							return
						}
						if mode == "overflow" {
							io.WriteString(channel, strings.Repeat("x", 2<<20))
						} else if mode == "error" {
							io.WriteString(channel, "Command::Base error[7405600]: private-password\r\n(config)> ")
						} else {
							io.WriteString(channel, "hw_id: KN-1010\r\narch: mips\r\n(config)> ")
						}
						if scanner.Scan() {
							lines = append(lines, scanner.Text())
						}
						commands <- strings.Join(lines, "\n")
						channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{0}))
						return
					default:
						r.Reply(false, nil)
					}
				}
			}()
		}
	}()
	c, err := DialSSH(context.Background(), SSHConfig{Address: l.Addr().String(), User: "admin", Auth: []ssh.AuthMethod{ssh.Password("fixture-password")}, HostKeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, commands
}
func TestCLIAllowsOnlyExactReviewedBootstrapInitrc(t *testing.T) {
	command := "opkg initrc /opt/etc/init.d"
	c, commands := cliFixture(t, "ok")
	if _, err := c.RunCLI(context.Background(), command); err != nil {
		t.Fatal("reviewed bootstrap initrc blocked", err)
	}
	if got := <-commands; got != command+"\nexit" {
		t.Fatal("unexpected CLI input", got)
	}
	for _, unsafe := range []string{
		"opkg initrc /opt/etc/init.d/",
		"opkg initrc /opt/etc/init.d/rc.unslung",
		"opkg initrc /opt/custom.sh",
		"opkg initrc /opt/etc/init.d; reboot",
		"opkg initrc /opt/etc/init.d\nreboot",
	} {
		if allowedCLI(unsafe) {
			t.Fatal("unreviewed initrc accepted", unsafe)
		}
	}
}

func TestCLITerminalUsesPTYAndShellWithoutExec(t *testing.T) {
	c, commands := cliFixture(t, "ok")
	out, err := c.runCLITerminal(context.Background(), "show version")
	if err != nil || !strings.Contains(string(out), "KN-1010") {
		t.Fatal("CLI read failed", err)
	}
	if got := <-commands; got != "show version\nexit" {
		t.Fatal("unexpected CLI input", got)
	}
}
func TestCLIRejectsUnreviewedCommandsBeforeTransport(t *testing.T) {
	c := &SSHTransport{}
	for _, cmd := range []string{"", "show version; reboot", "show version\nreboot", "opkg disk ../:/", "opkg disk 00112233-4455-6677-8899-aabbccddeeff:/;reboot", "opkg initrc /x", "system reboot"} {
		if _, err := c.RunCLI(context.Background(), cmd); err == nil {
			t.Fatal("allowed unsafe command", cmd)
		}
	}
}
func TestCLIErrorOutputRemainsPrivateAndBounded(t *testing.T) {
	for _, mode := range []string{"error", "overflow", "reject"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := cliFixture(t, mode)
			out, err := c.runCLITerminal(context.Background(), "show running-config")
			if err == nil || len(out) != 0 || strings.Contains(err.Error(), "private-password") {
				t.Fatal("unsafe error", err)
			}
		})
	}
}
func TestCLICancellationUnblocksStalledSession(t *testing.T) {
	c, _ := cliFixture(t, "stall")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	out, err := c.runCLITerminal(ctx, "show media")
	if !errors.Is(err, context.DeadlineExceeded) || len(out) != 0 || time.Since(start) > time.Second {
		t.Fatal("unbounded cancellation", err)
	}
}
func TestCLIAuthenticationRejectionDoesNotExposeServerText(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
		return nil, errors.New("private-password server detail")
	}}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		ssh.NewServerConn(conn, cfg)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := DialSSH(ctx, SSHConfig{Address: listener.Addr().String(), User: "admin", Auth: []ssh.AuthMethod{ssh.Password("wrong")}, HostKeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey())})
	if client != nil {
		client.Close()
		t.Fatal("rejected authentication accepted")
	}
	if err == nil || strings.Contains(err.Error(), "private-password") {
		t.Fatal("authentication error exposed server text")
	}
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("authentication did not close")
	}
}
