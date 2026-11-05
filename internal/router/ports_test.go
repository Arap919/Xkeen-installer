package router

import (
	"context"
	"strings"
	"testing"
	"time"
)

type listenerTransport struct {
	*fakeTransport
	output string
	exe    string
	code   int
}

type boundedListenerTransport struct {
	listenerTransport
	t        *testing.T
	deadline time.Time
}

func (f *boundedListenerTransport) Run(ctx context.Context, command string) (Result, error) {
	if command == "netstat -lntp" || command == "readlink /proc/42/exe" {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			f.t.Fatal("port probe has no bounded total deadline")
		}
		if f.deadline.IsZero() {
			f.deadline = deadline
		} else if !f.deadline.Equal(deadline) {
			f.t.Fatal("ownership probe reset total deadline")
		}
	}
	return f.listenerTransport.Run(ctx, command)
}

func TestPortProbeHasSingleDeadlineAndRowBound(t *testing.T) {
	header := "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\n"
	row := "tcp6 0 0 :::1000 :::* LISTEN 42/xkeen-ui\n"
	f := &boundedListenerTransport{listenerTransport: listenerTransport{fakeTransport: fixture(), output: header + row, exe: "/opt/sbin/xkeen-ui"}, t: t}
	var s Snapshot
	if err := inspectPorts(context.Background(), f, &s); err != nil || s.CheckUIPort(1000, true) != nil {
		t.Fatal("bounded ownership probe failed", err)
	}
	overflow := listenerTransport{fakeTransport: fixture(), output: header + strings.Repeat(row, 1025), exe: "/opt/sbin/xkeen-ui"}
	s = Snapshot{}
	if err := inspectPorts(context.Background(), overflow, &s); err != nil || s.CheckUIPort(1000, true) == nil {
		t.Fatal("listener row limit not enforced", err)
	}
}

func (f listenerTransport) Run(ctx context.Context, command string) (Result, error) {
	if command == "netstat -lntp" {
		return Result{Stdout: []byte(f.output), ExitCode: f.code}, nil
	}
	if command == "readlink /proc/42/exe" {
		return Result{Stdout: []byte(f.exe)}, nil
	}
	return f.fakeTransport.Run(ctx, command)
}

func TestUIPortEvidenceFailsClosedAndChecksActualOwner(t *testing.T) {
	header := "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\n"
	for _, tc := range []struct {
		name, output, exe string
		existing, want    bool
	}{
		{"free", header, "", false, true},
		{"foreign-v4", header + "tcp 0 0 0.0.0.0:1000 0.0.0.0:* LISTEN 42/xkeen-ui\n", "/tmp/xkeen-ui", true, false},
		{"genuine-v6", header + "tcp6 0 0 :::1000 :::* LISTEN 42/xkeen-ui\n", "/opt/sbin/xkeen-ui", true, true},
		{"no-existing-init", header + "tcp6 0 0 :::1000 :::* LISTEN 42/xkeen-ui\n", "/opt/sbin/xkeen-ui", false, false},
		{"hidden-owner", header + "tcp6 0 0 :::1000 :::* LISTEN -\n", "", true, false},
		{"missing", "", "", false, false},
		{"malformed", header + "truncated\n", "", false, false},
		{"other-port", header + "tcp6 0 0 :::999 :::* LISTEN -\n", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := listenerTransport{fakeTransport: fixture(), output: tc.output, exe: tc.exe}
			s, err := Inspect(context.Background(), f)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.CheckUIPort(1000, tc.existing) == nil; got != tc.want {
				t.Fatalf("allowed=%t want=%t", got, tc.want)
			}
			if f.writes != 0 {
				t.Fatal("inspection mutated router")
			}
		})
	}
	if (Snapshot{}).CheckUIPort(1000, true) == nil {
		t.Fatal("uninspected snapshot accepted")
	}
}
