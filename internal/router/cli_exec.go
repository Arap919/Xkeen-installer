package router

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"
)

// RunCLI reads firmware state through native exec, without terminal formatting.
// Mutations retain the reviewed terminal path; failures never trigger a retry.
func (t *SSHTransport) RunCLI(ctx context.Context, command string) ([]byte, error) {
	if readOnlyCLI(command) {
		return t.runCLIExec(ctx, command)
	}
	return t.runCLITerminal(ctx, command)
}

// Do not retain server stderr: only its presence is relevant to discovery safety.
type cliExecStderr struct {
	mu         sync.Mutex
	unexpected bool
}

func (b *cliExecStderr) Write(p []byte) (int, error) {
	b.mu.Lock()
	b.unexpected = b.unexpected || len(bytes.TrimSpace(p)) != 0
	b.mu.Unlock()
	return len(p), nil
}
func (b *cliExecStderr) rejected() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.unexpected }

func (t *SSHTransport) runCLIExec(ctx context.Context, command string) ([]byte, error) {
	if !readOnlyCLI(command) || !allowedCLI(command) {
		return nil, errors.New("firmware exec command is not allowed")
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if t == nil || t.client == nil {
		return nil, errors.New("firmware connection unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var output cliBuffer
	var stderr cliExecStderr
	err := t.operation(bounded, func() error {
		session, e := t.client.NewSession()
		if e != nil {
			return errors.New("firmware exec session unavailable")
		}
		defer session.Close()
		session.Stdout = &output
		session.Stderr = &stderr
		// Native KeeneticOS exec interprets the closed CLI allowlist directly. No PTY,
		// shell request, extra exit command or response-dependent fallback is used.
		if e = session.Run(command); e != nil {
			return errors.New("firmware exec did not complete successfully")
		}
		return nil
	})
	if err != nil {
		if bounded.Err() != nil {
			return nil, bounded.Err()
		}
		return nil, err
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.overflow {
		return nil, errors.New("firmware output limit exceeded")
	}
	// Keenetic emits CSI formatting (including ESC[K) even for non-PTY exec.
	// Strip complete control sequences after collecting the full bounded response,
	// before checking emptiness/errors or passing text to the metadata parser.
	data := cliANSI.ReplaceAll(output.data.Bytes(), nil)
	if stderr.rejected() || len(bytes.TrimSpace(data)) == 0 || cliFailure.Match(data) {
		return nil, errors.New("firmware exec response rejected")
	}
	return bytes.Clone(data), nil
}
