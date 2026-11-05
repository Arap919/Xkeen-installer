package router

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
)

const tcpListenersProbe = "netstat -lntp"

// Only numeric PIDs may enter this fixed, read-only /proc probe. Filesystem
// transport methods deliberately retain their /opt-only contract.
func processExecutable(ctx context.Context, t Transport, pid string) (string, error) {
	n, err := strconv.ParseUint(pid, 10, 32)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != pid {
		return "", nil
	}
	r, err := t.Run(ctx, "readlink /proc/"+pid+"/exe")
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "", err
	}
	if err != nil || r.ExitCode != 0 || len(r.Stdout) > 256 {
		return "", nil
	}
	return strings.TrimSpace(string(r.Stdout)), nil
}

// Missing tooling, hidden socket owners and unsupported output remain unknown.
// Parsing includes every TCP listener, including IPv6 wildcard bindings.
func inspectPorts(ctx context.Context, t Transport, s *Snapshot) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r, err := t.Run(ctx, tcpListenersProbe)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if err != nil || r.ExitCode != 0 || len(r.Stdout) > 1<<20 {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(r.Stdout)), "\n")
	if len(lines) < 2 || len(lines) > 1026 || !strings.HasPrefix(lines[0], "Active Internet connections") || !strings.HasPrefix(lines[1], "Proto ") || !strings.Contains(lines[1], "PID/Program") {
		return nil
	}
	ports := map[int][]string{}
	for _, line := range lines[2:] {
		fields := strings.Fields(line)
		if len(fields) != 7 || (fields[0] != "tcp" && fields[0] != "tcp6") || fields[5] != "LISTEN" {
			return nil
		}
		address := fields[3]
		colon := strings.LastIndexByte(address, ':')
		if colon < 0 {
			return nil
		}
		port, e := strconv.Atoi(address[colon+1:])
		if e != nil || port < 1 || port > 65535 {
			return nil
		}
		owner := strings.SplitN(fields[6], "/", 2)[0]
		exe, e := processExecutable(ctx, t, owner)
		if e != nil {
			return e
		}
		ports[port] = append(ports[port], exe)
	}
	s.ports, s.portsKnown = ports, true
	return nil
}

// CheckUIPort uses private discovery evidence; JSON cannot mint socket ownership.
func (s Snapshot) CheckUIPort(port int, existingUI bool) error {
	if !s.portsKnown || port < 1 || port > 65535 {
		return errors.New("Не удалось достоверно проверить TCP-порт панели")
	}
	for _, exe := range s.ports[port] {
		if !existingUI || (exe != "/opt/sbin/xkeen-ui" && exe != "/opt/bin/xkeen-ui") {
			return errors.New("TCP-порт панели занят посторонним или неизвестным процессом")
		}
	}
	return nil
}
