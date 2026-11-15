package router

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Arap919/xkeen-installer/internal/bootstrap"
	"golang.org/x/crypto/ssh"
)

// This server implements a terminal protocol only; it never invokes a host shell.
type interactiveCLIResult struct {
	command string
	err     error
}

type interactiveCLIOptions struct {
	pager         bool
	response      string
	status        uint32
	missingStatus bool
	responseReady chan<- struct{}
	nestedPrompt  bool
	rawResponse   bool
}

func interactiveCLIFixture(t *testing.T, options interactiveCLIOptions) (*SSHTransport, <-chan interactiveCLIResult) {
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
	result := make(chan interactiveCLIResult, 1)
	go func() {
		outcome := interactiveCLIResult{}
		defer func() { result <- outcome }()
		socket, err := listener.Accept()
		if err != nil {
			outcome.err = err
			return
		}
		defer socket.Close()
		// A deadline is a leak guard, not terminal synchronization.
		socket.SetDeadline(time.Now().Add(5 * time.Second))
		connection, channels, requests, err := ssh.NewServerConn(socket, config)
		if err != nil {
			outcome.err = err
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
				outcome.err = err
				return
			}
			defer channel.Close()
			pty := false
			for request := range requests {
				switch request.Type {
				case "pty-req":
					pty = true
					request.Reply(true, nil)
				case "shell":
					request.Reply(pty, nil)
					if !pty {
						outcome.err = errors.New("shell requested without PTY")
						return
					}
					go ssh.DiscardRequests(requests)
					outcome.command, outcome.err = serveInteractiveCLI(channel, options)
					return
				default:
					request.Reply(false, nil)
				}
			}
		}
	}()
	transport, err := DialSSH(context.Background(), SSHConfig{Address: listener.Addr().String(), User: "admin", HostKeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { transport.Close() })
	return transport, result
}

func serveInteractiveCLI(channel ssh.Channel, options interactiveCLIOptions) (string, error) {
	input := make(chan byte)
	readError := make(chan error, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		var b [1]byte
		for {
			_, err := io.ReadFull(channel, b[:])
			if err != nil {
				readError <- err
				return
			}
			select {
			case input <- b[0]:
			case <-stop:
				return
			}
		}
	}()
	write := func(parts ...string) error {
		for _, part := range parts {
			if _, err := io.WriteString(channel, part); err != nil {
				return err
			}
		}
		return nil
	}
	read := func() (byte, error) {
		select {
		case b := <-input:
			return b, nil
		case err := <-readError:
			return 0, fmt.Errorf("premature terminal EOF: %w", err)
		}
	}
	line := func() (string, error) {
		var value strings.Builder
		for value.Len() < 256 {
			b, err := read()
			if err != nil {
				return "", err
			}
			if b == '\n' {
				s := value.String()
				if !strings.HasSuffix(s, "\r") {
					return "", errors.New("terminal requires CRLF")
				}
				return strings.TrimSuffix(s, "\r"), nil
			}
			value.WriteByte(b)
		}
		return "", errors.New("terminal input exceeded fixture bound")
	}
	// Firmware drops input during startup. Drain any eagerly queued bytes while
	// emitting the banner, before making its fragmented ANSI prompt available.
	for _, fragment := range []string{"\r\nKeeneticOS 5.1.8\r\n", "\x1b[", "0m"} {
		if err := write(fragment); err != nil {
			return "", err
		}
		select {
		case <-input:
		default:
		}
	}
	if err := write("(con", "fig)", ">", " "); err != nil {
		return "", err
	}
	command, err := line()
	if err != nil {
		return "", err
	}
	if !allowedCLI(command) {
		return command, errors.New("startup discarded command or premature exit")
	}
	firstResponse := "fixture-response-first\r\n"
	if options.rawResponse {
		firstResponse = ""
	}
	if err := write(command, "\r\n", firstResponse); err != nil {
		return command, err
	}
	if options.responseReady != nil {
		// The test cancels only after a real command response has arrived. The
		// server deliberately withholds its prompt and requires session closure.
		close(options.responseReady)
		if _, err := read(); err == nil {
			return command, errors.New("input arrived before command completion prompt")
		}
		return command, nil
	}
	response := options.response
	if options.pager {
		markers := []string{"--More--", "--More-- "}
		if options.rawResponse {
			// Split real schema evidence at a complete line, as a firmware pager
			// does. Do not mix synthetic response markers into parser input.
			lines := strings.SplitAfter(response, "\n")
			middle := len(lines) / 2
			if err := write(strings.Join(lines[:middle], "")); err != nil {
				return command, err
			}
			response = strings.Join(lines[middle:], "")
			markers = []string{"--More-- "}
		}
		for _, marker := range markers {
			if err := write(marker[:4], marker[4:]); err != nil {
				return command, err
			}
			b, err := read()
			if err != nil {
				return command, err
			}
			if b != ' ' {
				return command, errors.New("pager requires single space before exit")
			}
			continuation := "\r\x1b[2Kfixture-response-next\r\n"
			if options.rawResponse {
				continuation = "\r\x1b[2K"
			}
			if err := write(continuation); err != nil {
				return command, err
			}
		}
	}
	promptSuffix := "fig)> "
	if options.nestedPrompt {
		promptSuffix = "fig-opkg)> "
	}
	lastResponse := "\r\nfixture-response-last\r\n"
	if options.rawResponse {
		lastResponse = "\r\n"
	}
	if err := write(response, lastResponse, "\x1b[0m(con", promptSuffix); err != nil {
		return command, err
	}
	exit, err := line()
	if err != nil {
		return command, err
	}
	if exit != "exit" {
		return command, errors.New("expected exit after complete response")
	}
	if options.nestedPrompt {
		if err := write("\r\n(config)> "); err != nil {
			return command, err
		}
		exit, err = line()
		if err != nil {
			return command, err
		}
		if exit != "exit" {
			return command, errors.New("expected second exit after returning to root prompt")
		}
	}
	if !options.missingStatus {
		_, err = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{options.status}))
	}
	return command, err
}

func awaitInteractiveCLI(t *testing.T, result <-chan interactiveCLIResult, command string) {
	t.Helper()
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.command != command {
			t.Fatalf("command = %q, want %q", got.command, command)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("terminal fixture did not finish")
	}
}

func TestCLIInteractiveStartupAndPagedReadOnlyResponses(t *testing.T) {
	for _, command := range []string{"show version", "show media", "show running-config", "show cifs"} {
		t.Run(command, func(t *testing.T) {
			transport, result := interactiveCLIFixture(t, interactiveCLIOptions{pager: true})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			out, err := transport.runCLITerminal(ctx, command)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(out), "--More--") {
				t.Fatal("consumed terminal pager marker leaked into command output")
			}
			for _, part := range []string{"fixture-response-first", "fixture-response-next", "fixture-response-last"} {
				if !strings.Contains(string(out), part) {
					t.Fatalf("missing response part %q", part)
				}
			}
			awaitInteractiveCLI(t, result, command)
		})
	}
}

func TestCLIInteractiveMutationFailuresRemainPrivate(t *testing.T) {
	for name, options := range map[string]interactiveCLIOptions{
		"firmware-error": {response: "Command::Base error[7405600]: private-fixture-secret"},
		"nonzero-status": {response: "private-fixture-secret", status: 1},
		"missing-status": {response: "private-fixture-secret", missingStatus: true},
	} {
		t.Run(name, func(t *testing.T) {
			transport, result := interactiveCLIFixture(t, options)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			out, err := transport.runCLITerminal(ctx, "system configuration save")
			if err == nil || len(out) != 0 {
				t.Fatal("uncertain mutation reported as success or returned output")
			}
			if strings.Contains(err.Error(), "private-fixture-secret") {
				t.Fatal("remote output leaked through error")
			}
			awaitInteractiveCLI(t, result, "system configuration save")
		})
	}
}

func TestCLIInteractiveCancellationClosesIncompleteResponse(t *testing.T) {
	responseReady := make(chan struct{})
	transport, result := interactiveCLIFixture(t, interactiveCLIOptions{responseReady: responseReady})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		out []byte
		err error
	}
	finished := make(chan outcome, 1)
	go func() { out, err := transport.runCLITerminal(ctx, "show media"); finished <- outcome{out, err} }()
	select {
	case <-responseReady:
	case <-time.After(3 * time.Second):
		t.Fatal("command response never arrived")
	}
	cancel()
	select {
	case got := <-finished:
		if !errors.Is(got.err, context.Canceled) || len(got.out) != 0 {
			t.Fatal("cancellation returned output or lost context error", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock terminal session")
	}
	awaitInteractiveCLI(t, result, "show media")
}

func TestCLIInteractiveUnwindsNestedCommandPrompt(t *testing.T) {
	const command = "opkg initrc /opt/etc/init.d"
	transport, result := interactiveCLIFixture(t, interactiveCLIOptions{nestedPrompt: true})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := transport.runCLITerminal(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "fixture-response-last") {
		t.Fatal("nested command response missing")
	}
	awaitInteractiveCLI(t, result, command)
}

// Only CIFS uses the SSH terminal here: the first three discovery responses are
// fixed firmware evidence, isolating the terminal-to-CIFS-parser boundary.
type interactiveCIFSInspectCLI struct {
	transport *SSHTransport
}

func (c interactiveCIFSInspectCLI) RunCLI(ctx context.Context, command string) ([]byte, error) {
	switch command {
	case "show version":
		return []byte("hw_id: KN-2610\narch: mips\nmodel: Giant\n"), nil
	case "show media":
		return []byte(`media:
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
`), nil
	case "show running-config":
		return []byte("opkg disk EXT4-NEOC9GHh:/\nopkg initrc \"\"\n"), nil
	case "show cifs":
		return c.transport.runCLITerminal(ctx, command)
	default:
		return nil, errors.New("unexpected discovery command")
	}
}

func TestCLIInteractiveCIFSEchoFlowsThroughBootstrapInspect(t *testing.T) {
	const cifsResponse = `enabled: yes
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
	transport, result := interactiveCLIFixture(t, interactiveCLIOptions{rawResponse: true, pager: true, response: cifsResponse})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	snapshot, err := bootstrap.Inspect(ctx, interactiveCIFSInspectCLI{transport: transport})
	if err != nil {
		t.Fatal("interactive CIFS echo rejected during inspection", err)
	}
	volumes := snapshot.EligibleVolumes()
	if len(volumes) != 1 {
		t.Fatalf("eligible volume count = %d, want 1", len(volumes))
	}
	if volumes[0].UUID != "a48bca5d-5c3e-4a5f-a2fc-5087d910e6b7" || volumes[0].Share != "EXT4-NEOC9GHh" {
		t.Fatalf("active EXT4 root or exact SMB label lost: %+v", volumes[0])
	}
	awaitInteractiveCLI(t, result, "show cifs")
}

func TestCLIInteractivePreservesLiteralPagerTextInDescription(t *testing.T) {
	const response = "enabled: yes\nshare:\n mount: a48bca5d-5c3e-4a5f-a2fc-5087d910e6b7:\n label: EXT4-NEOC9GHh\n description: --More--\n active: yes\n"
	// There is no terminal pager: any space sent in response to the field value
	// becomes part of the exit line, which the fixture rejects.
	transport, result := interactiveCLIFixture(t, interactiveCLIOptions{rawResponse: true, response: response})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := transport.runCLITerminal(ctx, "show cifs")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), " description: --More--\n") {
		t.Fatal("literal field value was changed or removed")
	}
	awaitInteractiveCLI(t, result, "show cifs")
}
