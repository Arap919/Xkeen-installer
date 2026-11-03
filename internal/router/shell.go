package router

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// SFTP is optional: stock Dropbear shell access can perform the same safe filesystem operations.
func (t *SSHTransport) hasSFTP(ctx context.Context) bool {
	return t.operation(ctx, func() error { _, err := t.fileClient(); return err }) == nil
}
func (t *SSHTransport) Read(ctx context.Context, p string) ([]byte, error) {
	if t.hasSFTP(ctx) {
		return t.sftpRead(ctx, p)
	}
	return t.shellRead(ctx, p)
}
func (t *SSHTransport) Stat(ctx context.Context, p string) (Entry, error) {
	if t.hasSFTP(ctx) {
		return t.sftpStat(ctx, p)
	}
	return t.shellStat(ctx, p)
}
func (t *SSHTransport) ReadDir(ctx context.Context, p string) ([]Entry, error) {
	if t.hasSFTP(ctx) {
		return t.sftpReadDir(ctx, p)
	}
	return t.shellReadDir(ctx, p)
}
func (t *SSHTransport) MkdirAll(ctx context.Context, p string, m fs.FileMode) error {
	if t.hasSFTP(ctx) {
		return t.sftpMkdirAll(ctx, p, m)
	}
	return t.shellMkdirAll(ctx, p, m)
}
func (t *SSHTransport) AvailableBytes(ctx context.Context, p string) (uint64, error) {
	if t.hasSFTP(ctx) {
		n, err := t.sftpAvailableBytes(ctx, p)
		if err == nil {
			return n, nil
		}
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
	}
	return t.shellAvailableBytes(ctx, p)
}
func (t *SSHTransport) WriteAtomic(ctx context.Context, p string, b []byte, m fs.FileMode) error {
	if t.hasSFTP(ctx) {
		c, _ := t.fileClient()
		if _, ok := c.HasExtension("posix-rename@openssh.com"); ok {
			return t.sftpWriteAtomic(ctx, p, b, m)
		}
	}
	return t.shellWriteAtomic(ctx, p, b, m)
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

// Every command uses only fixed syntax, validated paths, numeric modes and random IDs.
// File bytes travel exclusively through stdin; they are never shell source.
func shellGuard(p string, final bool) (string, error) {
	if err := safePath(p); err != nil {
		return "", err
	}
	parts := strings.Split(strings.TrimPrefix(p, "/opt/"), "/")
	if !final {
		parts = parts[:len(parts)-1]
	}
	current := "/opt"
	var command strings.Builder
	for _, part := range parts {
		current = path.Join(current, part)
		fmt.Fprintf(&command, "if [ -L %s ]; then exit 45; fi; ", shellQuote(current))
	}
	return command.String(), nil
}
func (t *SSHTransport) shellCommand(ctx context.Context, command string, input []byte) ([]byte, error) {
	r, err := t.runInput(ctx, command, input)
	if err != nil {
		return nil, err
	}
	switch r.ExitCode {
	case 0:
		return r.Stdout, nil
	case 44:
		return nil, fs.ErrNotExist
	case 45:
		return nil, ErrUnsafePath
	default:
		return nil, errors.New("remote shell filesystem operation failed")
	}
}
func (t *SSHTransport) shellStat(ctx context.Context, p string) (Entry, error) {
	guard, err := shellGuard(p, false)
	if err != nil {
		return Entry{}, err
	}
	q := shellQuote(p)
	b, err := t.shellCommand(ctx, guard+"if [ ! -e "+q+" ] && [ ! -L "+q+" ]; then exit 44; fi; if [ -L "+q+" ]; then printf 'l '; elif [ -d "+q+" ]; then printf 'd '; elif [ -f "+q+" ]; then printf 'f '; else printf 's '; fi; stat -c '%a %s' -- "+q, nil)
	if err != nil {
		return Entry{}, err
	}
	fields := strings.Fields(string(b))
	if len(fields) != 3 {
		return Entry{}, errors.New("unsupported remote stat output")
	}
	mode, err := strconv.ParseUint(fields[1], 8, 32)
	if err != nil {
		return Entry{}, errors.New("invalid remote mode")
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return Entry{}, errors.New("invalid remote size")
	}
	m := fs.FileMode(mode & 0777)
	if mode&04000 != 0 {
		m |= fs.ModeSetuid
	}
	if mode&02000 != 0 {
		m |= fs.ModeSetgid
	}
	if mode&01000 != 0 {
		m |= fs.ModeSticky
	}
	switch fields[0] {
	case "d":
		m |= fs.ModeDir
	case "l":
		m |= fs.ModeSymlink
	case "f":
	default:
		m |= fs.ModeIrregular
	}
	return Entry{p, m, size}, nil
}
func (t *SSHTransport) shellRead(ctx context.Context, p string) ([]byte, error) {
	guard, err := shellGuard(p, true)
	if err != nil {
		return nil, err
	}
	q := shellQuote(p)
	b, err := t.shellCommand(ctx, guard+"[ -e "+q+" ] || exit 44; [ -f "+q+" ] || exit 46; cat -- "+q, nil)
	if int64(len(b)) > maxInventoryBytes {
		return nil, errors.New("remote file size limit exceeded")
	}
	return b, err
}
func (t *SSHTransport) shellReadDir(ctx context.Context, p string) ([]Entry, error) {
	guard, err := shellGuard(p, true)
	if err != nil {
		return nil, err
	}
	q := shellQuote(p)
	b, err := t.shellCommand(ctx, guard+"[ -d "+q+" ] || exit 44; for p in "+q+"/.[!.]* "+q+"/..?* "+q+"/*; do [ -e \"$p\" ] || [ -L \"$p\" ] || continue; printf '%s\\0' \"${p##*/}\"; done", nil)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for _, name := range strings.Split(string(b), "\x00") {
		if name == "" {
			continue
		}
		if path.Base(name) != name || name == "." || name == ".." {
			return nil, ErrUnsafePath
		}
		entry, err := t.shellStat(ctx, path.Join(p, name))
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
func (t *SSHTransport) shellMkdirAll(ctx context.Context, p string, m fs.FileMode) error {
	if _, err := shellGuard(p, true); err != nil {
		return err
	}
	if m&^fs.FileMode(0777) != 0 {
		return errors.New("unsupported file mode")
	}
	current := "/opt"
	for _, part := range strings.Split(strings.TrimPrefix(p, "/opt/"), "/") {
		current = path.Join(current, part)
		e, err := t.shellStat(ctx, current)
		if errors.Is(err, fs.ErrNotExist) {
			guard, _ := shellGuard(current, true)
			q := shellQuote(current)
			_, err = t.shellCommand(ctx, guard+"umask 077; mkdir -- "+q+" && chmod "+fmt.Sprintf("%o", m.Perm())+" "+q, nil)
			if err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !e.Mode.IsDir() || e.Mode&fs.ModeSymlink != 0 {
			return ErrUnsafePath
		}
		if strings.HasPrefix(current, "/opt/.xkeen-installer-backups") && e.Mode.Perm() != 0700 {
			return errors.New("backup directory is not private")
		}
	}
	return nil
}
func (t *SSHTransport) shellAvailableBytes(ctx context.Context, p string) (uint64, error) {
	if p != "/opt" {
		if _, err := shellGuard(p, true); err != nil {
			return 0, err
		}
	}
	b, err := t.shellCommand(ctx, "df -Pk "+shellQuote(p), nil)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 {
		return 0, errors.New("unsupported remote df output")
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 6 {
		return 0, errors.New("unsupported remote df output")
	}
	available, err := strconv.ParseUint(fields[len(fields)-3], 10, 64)
	if err != nil || available > ^uint64(0)/1024 {
		return 0, errors.New("invalid remote capacity")
	}
	return available * 1024, nil
}
func (t *SSHTransport) shellWriteAtomic(ctx context.Context, p string, b []byte, m fs.FileMode) error {
	guard, err := shellGuard(p, true)
	if err != nil {
		return err
	}
	if m&^fs.FileMode(0777) != 0 {
		return errors.New("unsupported file mode")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	temp := path.Join(path.Dir(p), ".xkeen-tmp-"+hex.EncodeToString(id))
	q := shellQuote(p)
	qt := shellQuote(temp)
	cleanup := shellQuote("rm -f -- " + qt)
	command := guard + "[ ! -d " + q + " ] || exit 46; umask 077; trap " + cleanup + " 0; (set -C; cat > " + qt + ") || exit 46; chmod " + fmt.Sprintf("%o", m.Perm()) + " " + qt + " || exit 46; " + guard + "[ ! -d " + q + " ] || exit 46; mv -f -- " + qt + " " + q
	_, err = t.shellCommand(ctx, command, b)
	return err
}
