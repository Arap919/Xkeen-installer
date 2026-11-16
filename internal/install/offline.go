package install

import (
	"context"
	"errors"
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/Arap919/xkeen-installer/internal/router"
)

var ErrInsecureFeeds = errors.New("Установка остановлена до пакетных изменений: проверьте /opt/etc/opkg.conf и /opt/etc/opkg/*.conf. Разрешены HTTPS-репозитории с проверкой сертификатов или локальный репозиторий установщика; HTTP, no_check_certificate и неизвестные источники запрещены. Настройки не изменены")
var ErrExternalPackageHooks = errors.New("Установка остановлена: обнаружен /opt/lib/functions.sh с дополнительными opkg hooks вне проверенного набора. Перед продолжением требуется отдельная проверка этих hooks; файл не изменён")

func validateFeedData(configs [][]byte) error {
	sources := map[string]bool{}
	for _, data := range configs {
		if len(data) > 128<<10 || strings.ContainsAny(string(data), "\x00\\") {
			return ErrInsecureFeeds
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			if strings.ContainsAny(line, "\"'") {
				return ErrInsecureFeeds
			}
			if fields[0] == "option" && len(fields) >= 2 && fields[1] == "no_check_certificate" {
				return ErrInsecureFeeds
			}
			if fields[0] == "include" || fields[0] == "include_dir" || strings.HasPrefix(fields[0], "dist") {
				return ErrInsecureFeeds
			}
			if fields[0] != "src" && fields[0] != "src/gz" {
				continue
			}
			if len(fields) < 3 || sources[fields[1]] {
				return ErrInsecureFeeds
			}
			if len(fields) > 3 && !strings.HasPrefix(fields[3], "#") {
				return ErrInsecureFeeds
			}
			target, err := url.Parse(fields[2])
			if err != nil || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
				return ErrInsecureFeeds
			}
			if fields[2] != "file:///opt/.xkeen-installer-repository" && (target.Scheme != "https" || target.Hostname() == "") {
				return ErrInsecureFeeds
			}
			sources[fields[1]] = true
		}
	}
	if len(sources) == 0 {
		return ErrInsecureFeeds
	}
	return nil
}

// Package configuration is inspected without logging feed URLs or credentials.
func inspectPackageFeeds(ctx context.Context, t router.Transport) error {
	if _, err := t.Stat(ctx, "/opt/lib/functions.sh"); err == nil {
		return ErrExternalPackageHooks
	} else if !errors.Is(err, fs.ErrNotExist) {
		return ErrExternalPackageHooks
	}
	var configs [][]byte
	read := func(filename string) error {
		entry, err := t.Stat(ctx, filename)
		if err != nil || !entry.Mode.IsRegular() || entry.Size < 0 || entry.Size > 128<<10 {
			return ErrInsecureFeeds
		}
		data, err := t.Read(ctx, filename)
		if err != nil || int64(len(data)) != entry.Size {
			return ErrInsecureFeeds
		}
		configs = append(configs, data)
		return nil
	}
	if err := read("/opt/etc/opkg.conf"); err != nil {
		return err
	}
	if entry, err := t.Stat(ctx, "/opt/etc/opkg"); err == nil {
		if !entry.Mode.IsDir() {
			return ErrInsecureFeeds
		}
		entries, err := t.ReadDir(ctx, "/opt/etc/opkg")
		if err != nil || len(entries) > 64 {
			return ErrInsecureFeeds
		}
		for _, item := range entries {
			if strings.HasSuffix(item.Path, ".conf") {
				if path.Dir(item.Path) != "/opt/etc/opkg" {
					return ErrInsecureFeeds
				}
				if err := read(item.Path); err != nil {
					return err
				}
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return ErrInsecureFeeds
	}
	return validateFeedData(configs)
}

var packageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.-]*$`)
var ErrPackageState = errors.New("Установка остановлена: состояние /opt/lib/opkg/status неполное или содержит незавершённые операции. Сначала проверьте и восстановите систему пакетов из доверенных локальных пакетов; мастер не запускает старые hooks и не изменяет status")
var ErrOldPackageHooks = errors.New("Установка остановлена: версия установленного пакета отличается от закреплённого набора, и присутствуют старые hooks вне проверенного набора. Сначала требуется отдельная проверка этого обновления; установленные пакеты и hooks не изменены")

func installedPackageVersions(data []byte) (map[string]string, error) {
	if len(data) == 0 || len(data) > 8<<20 || strings.ContainsRune(string(data), 0) {
		return nil, ErrPackageState
	}
	packages := map[string]string{}
	for _, block := range strings.Split(strings.TrimSpace(string(data)), "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				continue
			}
			key, value, found := strings.Cut(line, ":")
			if !found {
				return nil, ErrPackageState
			}
			if key != "Package" && key != "Version" && key != "Status" {
				continue
			}
			if _, duplicate := fields[key]; duplicate {
				return nil, ErrPackageState
			}
			fields[key] = strings.TrimSpace(value)
		}
		status := strings.Fields(fields["Status"])
		name := fields["Package"]
		if !packageName.MatchString(name) || packages[name] != "" || fields["Version"] == "" || len(status) != 3 || status[0] != "install" || status[2] != "installed" {
			return nil, ErrPackageState
		}
		packages[name] = fields["Version"]
	}
	if len(packages) == 0 {
		return nil, ErrPackageState
	}
	return packages, nil
}

// opkg install configures all unpacked packages, not only the requested names.
// Reject unfinished global state and old callbacks of dependencies being changed.
func inspectPackageState(ctx context.Context, t router.Transport, targets map[string]string) error {
	entry, err := t.Stat(ctx, "/opt/lib/opkg/status")
	if err != nil || !entry.Mode.IsRegular() || entry.Size <= 0 || entry.Size > 8<<20 {
		return ErrPackageState
	}
	data, err := t.Read(ctx, "/opt/lib/opkg/status")
	if err != nil || int64(len(data)) != entry.Size {
		return ErrPackageState
	}
	installed, err := installedPackageVersions(data)
	if err != nil {
		return err
	}
	for name, version := range targets {
		old, exists := installed[name]
		if !exists || old == version {
			continue
		}
		for _, suffix := range []string{"preinst", "postinst", "prerm", "postrm"} {
			if _, err := t.Stat(ctx, "/opt/lib/opkg/info/"+name+"."+suffix); err == nil {
				return ErrOldPackageHooks
			} else if !errors.Is(err, fs.ErrNotExist) {
				return ErrOldPackageHooks
			}
		}
	}
	return nil
}

// PackageFailureMessage exposes only static, reviewed remediation instructions.
// Wrapped transport output is never included in a user-facing package failure.
func PackageFailureMessage(err error) string {
	for _, known := range []error{ErrInsecureFeeds, ErrExternalPackageHooks, ErrPackageState, ErrOldPackageHooks} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return ""
}
