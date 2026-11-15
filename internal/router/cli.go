package router

import (
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const maxCLIOutput = 1 << 20

var cliUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var cliFailure = regexp.MustCompile(`(?im)(error\[|error:|unknown command|invalid command|permission denied|command not found|no such command)`)
var cliANSI = regexp.MustCompile("\\x1b\\[[0-?]*[ -/]*[@-~]")
var cliPrompt = regexp.MustCompile(`(?m)^\((?:config|show|opkg)(?:-[A-Za-z0-9_-]+)?\)>[ \t]*\z`)
var cliPager = regexp.MustCompile(`(?im)^[ \t]*--more--[ \t]*\z`)

func allowedCLI(command string) bool {
	switch command {
	case "show version", "show media", "show running-config", "show cifs", "no opkg disk", "system configuration save", "opkg initrc /opt/etc/init.d":
		return true
	}
	const prefix = "opkg disk "
	if !strings.HasPrefix(command, prefix) || !strings.HasSuffix(command, ":/") {
		return false
	}
	return cliUUID.MatchString(strings.TrimSuffix(strings.TrimPrefix(command, prefix), ":/"))
}

func readOnlyCLI(command string) bool {
	return command == "show version" || command == "show media" || command == "show running-config" || command == "show cifs"
}

type cliBuffer struct {
	mu       sync.Mutex
	data     bytes.Buffer
	overflow bool
	changed  chan struct{}
}

func (b *cliBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	if len(p) > maxCLIOutput-b.data.Len() {
		b.overflow = true
	} else if !b.overflow {
		b.data.Write(p)
	}
	b.mu.Unlock()
	select {
	case b.changed <- struct{}{}:
	default:
	}
	return len(p), nil
}
func (b *cliBuffer) snapshot() (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.overflow {
		return "", errors.New("firmware output limit exceeded")
	}
	value := cliANSI.ReplaceAllString(b.data.String(), "")
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.ReplaceAll(value, "\b", ""), nil
}

// runCLITerminal drives firmware mutations through the native terminal. Input
// stays open and no command is sent before the firmware's initial prompt.
// Output remains private; failed/canceled mutations must never be retried blindly.
func (t *SSHTransport) runCLITerminal(ctx context.Context, command string) ([]byte, error) {
	if !allowedCLI(command) {
		return nil, errors.New("firmware command is not allowed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t == nil || t.client == nil {
		return nil, errors.New("firmware connection unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	output := cliBuffer{changed: make(chan struct{}, 1)}
	var result []byte
	err := t.operation(bounded, func() error {
		session, err := t.client.NewSession()
		if err != nil {
			return errors.New("firmware session unavailable")
		}
		defer session.Close()
		session.Stdout = &output
		session.Stderr = &output
		input, err := session.StdinPipe()
		if err != nil {
			return errors.New("firmware input unavailable")
		}
		if err = session.RequestPty("vt100", 24, 120, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
			return errors.New("firmware terminal unavailable")
		}
		if err = session.Shell(); err != nil {
			return errors.New("firmware CLI unavailable")
		}
		finished := make(chan struct{})
		var waitErr error
		go func() { waitErr = session.Wait(); close(finished) }()
		defer func() { session.Close(); <-finished }()

		var consumedPagers []struct{ start, end int }
		// Offsets are taken only at complete prompts. ANSI and CR normalization is
		// used for matching and parsing, never echoed into a public error or report.
		waitPrompt := func(after int, paging bool) (string, int, bool, error) {
			lastPager := -1
			terminalFinished := false
			for {
				if e := bounded.Err(); e != nil {
					return "", 0, false, e
				}
				text, e := output.snapshot()
				if e != nil {
					return "", 0, false, e
				}
				if len(text) < after {
					return "", 0, false, errors.New("firmware terminal framing failed")
				}
				tail := text[after:]
				if loc := cliPrompt.FindStringIndex(tail); loc != nil && loc[1] == len(tail) {
					return tail[:loc[0]], len(text), false, nil
				}
				if terminalFinished {
					if waitErr != nil {
						return "", 0, true, errors.New("firmware command transport failed")
					}
					return "", len(text), true, nil
				}
				if paging {
					if loc := cliPager.FindStringIndex(tail); loc != nil && after+loc[0] != lastPager {
						lastPager = after + loc[0]
						if _, e = io.WriteString(input, " "); e != nil {
							return "", 0, false, errors.New("firmware pager transport failed")
						}
						consumedPagers = append(consumedPagers, struct{ start, end int }{after + loc[0], after + loc[1]})
						continue
					}
				}
				select {
				case <-bounded.Done():
					return "", 0, false, bounded.Err()
				case <-output.changed:
				case <-finished:
					// Re-read the fully drained output before deciding whether the last
					// prompt arrived concurrently with terminal completion.
					terminalFinished = true
				}
			}
		}
		_, offset, closed, err := waitPrompt(0, false)
		if err != nil {
			return err
		}
		if closed {
			return errors.New("firmware closed before initial prompt")
		}
		if e := bounded.Err(); e != nil {
			return e
		}
		if _, err = io.WriteString(input, command+"\r\n"); err != nil {
			return errors.New("firmware input transport failed")
		}
		commandStart := offset
		body, offset, closed, err := waitPrompt(offset, readOnlyCLI(command))
		if err != nil {
			return err
		}
		if closed {
			return errors.New("firmware closed before command completion")
		}
		// Remove terminal presentation only where a pager was actually continued.
		// Literal marker text in configuration values must remain byte-for-byte.
		for i := len(consumedPagers) - 1; i >= 0; i-- {
			start, end := consumedPagers[i].start-commandStart, consumedPagers[i].end-commandStart
			if start < 0 || end > len(body) || start > end {
				return errors.New("firmware pager framing failed")
			}
			body = body[:start] + body[end:]
		}
		// Unwind command groups one prompt at a time; never queue exit while a show
		// command is still running or waiting at a pager.
		for i := 0; i < 3; i++ {
			if _, err = io.WriteString(input, "exit\r\n"); err != nil {
				return errors.New("firmware exit transport failed")
			}
			_, offset, closed, err = waitPrompt(offset, false)
			if err != nil {
				return err
			}
			if closed {
				if len(strings.TrimSpace(body)) == 0 || cliFailure.MatchString(body) {
					return errors.New("firmware command rejected")
				}
				result = []byte(body)
				return nil
			}
		}
		return errors.New("firmware terminal did not exit")
	})
	if err != nil {
		if bounded.Err() != nil {
			return nil, bounded.Err()
		}
		return nil, err
	}
	return result, nil
}

var _ io.Writer = (*cliBuffer)(nil)
