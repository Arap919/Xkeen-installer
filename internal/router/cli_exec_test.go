package router

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arap919/xkeen-installer/internal/bootstrap"
	"golang.org/x/crypto/ssh"
)

type cliExecEvents struct {
	mu       sync.Mutex
	commands []string
	terminal int
}

func (e *cliExecEvents) snapshot() ([]string, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.commands...), e.terminal
}

// The fixture accepts native SSH exec requests only. It never executes input
// locally and rejects terminal requests so any fallback is observable.
func cliExecFixture(t *testing.T, mode string) (*SSHTransport, *cliExecEvents, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	events := &cliExecEvents{}
	started, done := make(chan struct{}), make(chan struct{})
	var startOnce sync.Once
	go func() {
		defer close(done)
		socket, err := listener.Accept()
		if err != nil {
			return
		}
		defer socket.Close()
		// A deadline bounds leaked sessions without controlling protocol order.
		socket.SetDeadline(time.Now().Add(5 * time.Second))
		connection, channels, requests, err := ssh.NewServerConn(socket, config)
		if err != nil {
			return
		}
		defer connection.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			if incoming.ChannelType() != "session" {
				incoming.Reject(ssh.UnknownChannelType, "session required")
				continue
			}
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			go func() {
				defer channel.Close()
				for request := range requests {
					if request.Type != "exec" {
						if request.Type == "pty-req" || request.Type == "shell" {
							events.mu.Lock()
							events.terminal++
							events.mu.Unlock()
						}
						request.Reply(false, nil)
						continue
					}
					var payload struct{ Command string }
					if ssh.Unmarshal(request.Payload, &payload) != nil {
						request.Reply(false, nil)
						return
					}
					events.mu.Lock()
					events.commands = append(events.commands, payload.Command)
					events.mu.Unlock()
					startOnce.Do(func() { close(started) })
					if mode == "reject" {
						request.Reply(false, nil)
						return
					}
					request.Reply(true, nil)
					if mode == "stall" {
						// Wait for channel/connection closure, not stdin EOF: ordinary
						// exec clients may close stdin before the command completes.
						for range requests {
						}
						return
					}
					output := cliExecResponse(payload.Command)
					if mode == "csi-prefix" {
						// Captured from KN-2610 even without PTY; fragment the CSI
						// across writes to exercise cleanup after complete collection.
						io.WriteString(channel, "\x1b")
						io.WriteString(channel, "[K\n")
					}
					status := uint32(0)
					switch mode {
					case "csi-only":
						output = "\x1b[K\n"
					case "csi-error":
						output = "Command::Base er\x1b[0mror[7405600]: private-exec-fixture-secret"
					case "literal-escape":
						output = "description: \\033[K\n"
					case "nonzero":
						status = 1
						output = "private-exec-fixture-secret"
					case "missing-status":
						output = "private-exec-fixture-secret"
					case "stderr":
						io.WriteString(channel.Stderr(), "private-exec-fixture-secret")
					case "empty":
						output = " \r\n\t"
					case "firmware-error":
						output = "Command::Base error[7405600]: private-exec-fixture-secret"
					case "overflow":
						output = strings.Repeat("x", maxCLIOutput+1)
					}
					io.WriteString(channel, output)
					if mode != "missing-status" {
						channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{status}))
					}
					return
				}
			}()
		}
	}()
	transport, err := DialSSH(context.Background(), SSHConfig{Address: listener.Addr().String(), User: "admin", HostKeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { transport.Close() })
	return transport, events, started, done
}

func cliExecResponse(command string) string {
	switch command {
	case "show version":
		return "hw_id: KN-2610\narch: mips\nmodel: Giant\n"
	case "show media":
		return `media:
 name: Media0
 bus: usb
 state: ACTIVE
 serial: REDACTED
 partition:
  id: Partition1
  uuid: a48bca5d-5c3e-4a5f-a2fc-5087d910e6b7
  label: EXT4-NEOC9GHh
  fstype: ext4
  state: MOUNTED
  total: 30324928512
  free: 30322806784
  used-by: cifs
  used-by: opkg
`
	case "show running-config":
		return "opkg disk EXT4-NEOC9GHh:/\nopkg initrc \"\"\n"
	case "show cifs":
		return `enabled: yes
automount: yes
permissive: yes
map-hidden: no
master: no
share:
 mount: 29f680ff-11d2-4b34-6f04-1f6fe0129d88:
 label: NEW VOLUME
 description:
 active: no
share:
 mount: 919c87eb-1084-463b-8ed3-f750095b2ac5:
 label: Untitled
 description:
 active: no
share:
 mount: a48bca5d-5c3e-4a5f-a2fc-5087d910e6b7:
 label: EXT4-NEOC9GHh
 description:
 active: yes
`
	default:
		return "error: unreviewed fixture command"
	}
}

func TestCLIReadOnlyExecDrivesBootstrapInspect(t *testing.T) {
	transport, events, _, _ := cliExecFixture(t, "ok")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	snapshot, err := bootstrap.Inspect(ctx, transport)
	if err != nil {
		t.Fatal(err)
	}
	volumes := snapshot.EligibleVolumes()
	if len(volumes) != 1 {
		t.Fatalf("eligible volume count = %d, want 1", len(volumes))
	}
	if volumes[0].UUID != "a48bca5d-5c3e-4a5f-a2fc-5087d910e6b7" || volumes[0].Share != "EXT4-NEOC9GHh" {
		t.Fatalf("active EXT4 root or exact SMB label lost: %+v", volumes[0])
	}
	commands, terminal := events.snapshot()
	if terminal != 0 || !reflect.DeepEqual(commands, []string{"show version", "show media", "show running-config", "show cifs"}) {
		t.Fatalf("unexpected SSH requests: exec=%q terminal=%d", commands, terminal)
	}
}

func TestCLIReadOnlyExecFailuresRemainPrivateWithoutFallback(t *testing.T) {
	for _, mode := range []string{"reject", "nonzero", "missing-status", "stderr", "empty", "firmware-error", "overflow", "csi-only", "csi-error"} {
		t.Run(mode, func(t *testing.T) {
			transport, events, _, _ := cliExecFixture(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			out, err := transport.RunCLI(ctx, "show cifs")
			if err == nil || out != nil {
				t.Fatal("failed exec returned success or remote output")
			}
			if strings.Contains(err.Error(), "private-exec-fixture-secret") {
				t.Fatal("remote text leaked through error")
			}
			commands, terminal := events.snapshot()
			if terminal != 0 || !reflect.DeepEqual(commands, []string{"show cifs"}) {
				t.Fatalf("exec retried or fell back: exec=%q terminal=%d", commands, terminal)
			}
		})
	}
}

func TestCLIReadOnlyExecCancellationClosesSession(t *testing.T) {
	transport, events, started, serverDone := cliExecFixture(t, "stall")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		output []byte
		err    error
	}
	finished := make(chan outcome, 1)
	go func() { out, err := transport.RunCLI(ctx, "show cifs"); finished <- outcome{out, err} }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("exec never started")
	}
	cancel()
	select {
	case got := <-finished:
		if !errors.Is(got.err, context.Canceled) || got.output != nil {
			t.Fatal("cancellation returned output or lost context error", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock exec")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("canceled SSH connection remained open")
	}
	commands, terminal := events.snapshot()
	if terminal != 0 || !reflect.DeepEqual(commands, []string{"show cifs"}) {
		t.Fatal("canceled command retried or used terminal")
	}
}

func TestCLIMutationDoesNotUseReadOnlyExec(t *testing.T) {
	transport, events, _, _ := cliExecFixture(t, "ok")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if out, err := transport.RunCLI(ctx, "opkg initrc /opt/etc/init.d"); err == nil || out != nil {
		t.Fatal("mutation bypassed terminal rejection")
	}
	commands, terminal := events.snapshot()
	if len(commands) != 0 || terminal == 0 {
		t.Fatal("mutation used exec or skipped terminal")
	}
}

func TestCLIReadOnlyExecRemovesCapturedCSIForFullInspect(t *testing.T) {
	transport, events, _, _ := cliExecFixture(t, "csi-prefix")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	snapshot, err := bootstrap.Inspect(ctx, transport)
	if err != nil {
		t.Fatal("captured ESC[K rejected during discovery", err)
	}
	volumes := snapshot.EligibleVolumes()
	if len(volumes) != 1 || volumes[0].UUID != "a48bca5d-5c3e-4a5f-a2fc-5087d910e6b7" || volumes[0].Share != "EXT4-NEOC9GHh" {
		t.Fatal("captured control prefix hid selected USB root")
	}
	commands, terminal := events.snapshot()
	if terminal != 0 || !reflect.DeepEqual(commands, []string{"show version", "show media", "show running-config", "show cifs"}) {
		t.Fatal("unexpected request mode or retry", commands, terminal)
	}
}
func TestCLIReadOnlyExecPreservesPrintedEscapeNotation(t *testing.T) {
	transport, _, _, _ := cliExecFixture(t, "literal-escape")
	out, err := transport.RunCLI(context.Background(), "show cifs")
	if err != nil || string(out) != "description: \\033[K\n" {
		t.Fatalf("printable value changed: %q %v", out, err)
	}
}
