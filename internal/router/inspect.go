package router

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/Arap919/xkeen-installer/internal/catalog"
)

const shellProbe = "printf 'XKEEN_SHELL_OK\\n'"
const archProbe = "uname -m"
const endianProbe = "od -An -tu1 -N6 /bin/sh"
const activeCoreProbe = "ps w"
const versionProbe = "/opt/bin/opkg list-installed"

var inventoryRoots = []string{"/opt/etc/xkeen", "/opt/etc/xray", "/opt/etc/mihomo", "/opt/etc/xkeen-ui", "/opt/etc/nginx/ssl", "/opt/etc/lighttpd/conf.d/90-xkeenui.conf", "/opt/etc/router-watchdog.json", "/opt/etc/router-watchdog.json-old", "/opt/etc/router-watchdog.json-upgrade", "/opt/etc/crontab", "/opt/etc/cron.1min", "/opt/etc/init.d", "/opt/share/www/XKeen-UI", "/opt/var/spool/cron", "/opt/lib/opkg/status", "/opt/etc/ndm/netfilter.d/proxy.sh", "/opt/etc/ndm/schedule.d/00-xkeen-hotspot-sync.sh"}

const maxInventoryBytes = int64(64 << 20)
const maxInventoryEntries = 10000

type Snapshot struct {
	Arch               catalog.RouterArch
	Entware            bool
	Available          uint64
	Files              []Entry
	CronInit           []string
	Versions           map[string]string
	ActiveCore         string
	ActiveCoreEvidence string
	contents           map[string][]byte
	inspected          bool
}

// Config returns a defensive copy for backend configuration preparation. JSON cannot expose it.
func (s Snapshot) Config(p string) ([]byte, bool) {
	b, ok := s.contents[p]
	return append([]byte(nil), b...), ok
}
func Inspect(ctx context.Context, t Transport) (Snapshot, error) {
	s := Snapshot{contents: map[string][]byte{}, Versions: map[string]string{"xkeen": "unknown", "xray": "unknown", "mihomo": "unknown"}, ActiveCore: "unknown", ActiveCoreEvidence: "unavailable"}
	r, err := t.Run(ctx, shellProbe)
	if err != nil {
		return Snapshot{}, err
	}
	if r.ExitCode != 0 || string(r.Stdout) != "XKEEN_SHELL_OK\n" {
		return Snapshot{}, errors.New("SSH endpoint is not a compatible POSIX shell")
	}
	r, err = t.Run(ctx, archProbe)
	if err != nil {
		return Snapshot{}, err
	}
	if r.ExitCode != 0 {
		return Snapshot{}, errors.New("cannot inspect CPU")
	}
	switch strings.TrimSpace(string(r.Stdout)) {
	case "aarch64", "arm64":
		s.Arch = catalog.ARM64
	case "mipsel", "mipsle":
		s.Arch = catalog.MIPSel
	case "mips":
		r, err = t.Run(ctx, endianProbe)
		if err != nil {
			return Snapshot{}, err
		}
		if r.ExitCode != 0 {
			return Snapshot{}, errors.New("cannot inspect MIPS byte order")
		}
		b := strings.Fields(string(r.Stdout))
		if len(b) != 6 || strings.Join(b[:4], " ") != "127 69 76 70" {
			return Snapshot{}, errors.New("unknown executable byte order")
		}
		switch b[5] {
		case "1":
			s.Arch = catalog.MIPSel
		case "2":
			s.Arch = catalog.MIPS
		default:
			return Snapshot{}, errors.New("unknown executable byte order")
		}
	default:
		return Snapshot{}, errors.New("unsupported CPU")
	}
	e, err := t.Stat(ctx, "/opt/bin/opkg")
	if err == nil {
		if !e.Mode.IsRegular() {
			return Snapshot{}, errors.New("opkg is not a regular file")
		}
		r, err = t.Run(ctx, versionProbe)
		if err != nil {
			return Snapshot{}, err
		}
		if r.ExitCode != 0 {
			return Snapshot{}, errors.New("opkg is present but unusable")
		}
		s.Entware = true
		for _, line := range strings.Split(string(r.Stdout), "\n") {
			parts := strings.Split(line, " - ")
			if len(parts) == 2 {
				s.Versions[parts[0]] = parts[1]
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Snapshot{}, err
	}
	r, err = t.Run(ctx, activeCoreProbe)
	if err != nil {
		return Snapshot{}, err
	}
	if r.ExitCode == 0 {
		seen := map[string]bool{}

		commandColumn := 2 // Conservative PID USER COMMAND fallback when a header is absent.
		for _, line := range strings.Split(string(r.Stdout), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if fields[0] == "PID" {
				for i, field := range fields {
					if field == "COMMAND" || field == "CMD" || field == "ARGS" {
						commandColumn = i
					}
				}
				continue
			}
			if len(fields) <= commandColumn {
				continue
			}
			switch fields[commandColumn] {
			case "/opt/sbin/mihomo", "/opt/bin/mihomo":
				seen["mihomo"] = true
			case "/opt/sbin/xray", "/opt/bin/xray":
				seen["xray"] = true
			}
		}

		s.ActiveCoreEvidence = "no-core-process"
		if len(seen) == 1 {
			for core := range seen {
				s.ActiveCore = core
			}
			s.ActiveCoreEvidence = "single-core-process"
		} else if len(seen) > 1 {
			s.ActiveCoreEvidence = "multiple-core-processes"
		}
	}
	s.Available, err = t.AvailableBytes(ctx, "/opt")
	if err != nil {
		return Snapshot{}, err
	}
	var total int64
	count := 0
	var walk func(string) error
	walk = func(p string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := safePath(p); err != nil {
			return err
		}
		e, err := t.Stat(ctx, p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		count++
		if count > maxInventoryEntries {
			return errors.New("inventory entry limit exceeded")
		}
		if e.Mode&fs.ModeSymlink != 0 {
			return fmt.Errorf("inventory contains symlink at %s; manual backup required", p)
		}
		if e.Mode.IsDir() {
			children, err := t.ReadDir(ctx, p)
			if err != nil {
				return err
			}
			for _, child := range children {
				if p == "/opt/etc/init.d" {
					name := strings.ToLower(path.Base(child.Path))
					owned := false
					for _, component := range []string{"xkeen", "xray", "mihomo", "cron", "lighttpd"} {
						if strings.Contains(name, component) {
							owned = true
						}
					}
					if !owned {
						continue
					}
				}

				if path.Dir(child.Path) != p {
					return ErrUnsafePath
				}
				if err := walk(child.Path); err != nil {
					return err
				}
			}
			return nil
		}
		if !e.Mode.IsRegular() {
			return errors.New("inventory contains special file")
		}
		if e.Size < 0 || e.Size > maxInventoryBytes-total {
			return errors.New("inventory size limit exceeded")
		}
		b, err := t.Read(ctx, p)
		if err != nil {
			return err
		}
		if int64(len(b)) != e.Size {
			return errors.New("file changed during inventory")
		}
		total += e.Size
		e.Path = p
		s.Files = append(s.Files, e)
		s.contents[p] = b
		if path.Dir(p) == "/opt/etc/init.d" && strings.Contains(strings.ToLower(path.Base(p)), "cron") {
			s.CronInit = append(s.CronInit, p)
		}
		return nil
	}
	for _, root := range inventoryRoots {
		if err := walk(root); err != nil {
			return Snapshot{}, fmt.Errorf("inspect inventory: %w", err)
		}
	}
	sort.Slice(s.Files, func(i, j int) bool { return s.Files[i].Path < s.Files[j].Path })
	sort.Strings(s.CronInit)
	s.inspected = true
	return s, nil
}

// String and GoString deliberately omit the private configuration map.
func (s Snapshot) String() string {
	return fmt.Sprintf("Snapshot{Arch:%s Entware:%t Files:%d}", s.Arch, s.Entware, len(s.Files))
}
func (s Snapshot) GoString() string { return s.String() }
