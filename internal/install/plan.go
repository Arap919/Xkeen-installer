package install

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/router"
)

func fingerprint(s router.Snapshot) ([32]byte, error) {
	type file struct {
		Path string
		Mode fs.FileMode
		SHA  [32]byte
	}
	files := make([]file, 0, len(s.Files))
	for _, f := range s.Files {
		b, ok := s.Config(f.Path)
		if !ok {
			return [32]byte{}, errors.New("Данные проверки недоступны")
		}
		files = append(files, file{f.Path, f.Mode, sha256.Sum256(b)})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	b, _ := json.Marshal(struct {
		Arch             catalog.RouterArch
		Entware          bool
		Versions         map[string]string
		Active, Evidence string
		Files            []file
	}{s.Arch, s.Entware, s.Versions, s.ActiveCore, s.ActiveCoreEvidence, files})
	return sha256.Sum256(b), nil
}
func BuildPlan(s router.Snapshot, selection Selection, proposal config.ConfigProposal) (Plan, error) {
	fail := func(s string) (Plan, error) { return Plan{}, errors.New(s) }
	if s.ActiveCoreEvidence == "multiple-core-processes" {
		return fail("Одновременно запущены оба ядра; сначала устраните неоднозначность вручную")
	}
	if !s.Entware {
		return fail("Entware не установлен: выполните ручную подготовку OPKG и повторите проверку")
	}
	active := selection.Config.ActiveCore
	if active == "" {
		active = catalog.Component(s.ActiveCore)
	}
	selected := map[catalog.Component]bool{}
	for _, c := range selection.Config.Cores {
		if selected[c] || (c != catalog.Xray && c != catalog.Mihomo) {
			return fail("Некорректный выбор ядер")
		}
		selected[c] = true
	}
	if !selected[active] {
		return fail("Выберите активное установленное ядро явно")
	}
	if active != catalog.Mihomo {
		for _, f := range s.Files {
			if f.Path == "/opt/etc/cron.1min/router-watchdog" {
				return fail("Перед запуском Xray отключите существующее расписание watchdog вручную и повторите проверку")
			}
			if f.Path == "/opt/etc/crontab" {
				b, _ := s.Config(f.Path)
				if bytes.Contains(b, []byte("router-watchdog")) {
					return fail("Перед запуском Xray отключите существующее расписание watchdog вручную и повторите проверку")
				}
			}
		}
	}
	// Only the intentionally inactive, generated Xray base can remain unfinished.
	// All other merge conflicts stop the plan, even if public readiness was edited.
	for _, c := range proposal.Conflicts {
		if !(active != catalog.Xray && c.Path == config.XrayPath && strings.HasPrefix(c.Reason, "Add a user proxy outbound")) {
			return fail("Конфигурация требует ручного согласования")
		}
	}
	d := &planData{snapshot: s, selection: selection, active: active, existingInitMode: 0755}
	var err error
	d.fingerprint, err = fingerprint(s)
	if err != nil {
		return Plan{}, err
	}
	allowed := map[string]bool{}
	seen := map[string]bool{}
	for c := range selected {
		canonical := config.XrayPath
		if c == catalog.Mihomo {
			canonical = config.MihomoPath
		}
		for _, f := range s.Files {
			if (c == catalog.Xray && strings.HasPrefix(f.Path, "/opt/etc/xray/") && strings.HasSuffix(f.Path, ".json")) || (c == catalog.Mihomo && strings.HasPrefix(f.Path, "/opt/etc/mihomo/") && (strings.HasSuffix(f.Path, ".yaml") || strings.HasSuffix(f.Path, ".yml"))) {
				allowed[f.Path] = true
			}
		}
		allowed[canonical] = true
		var targets []string
		for _, f := range proposal.Files {
			if f.Path == canonical || allowed[f.Path] && ((c == catalog.Xray && strings.HasPrefix(f.Path, "/opt/etc/xray/")) || (c == catalog.Mihomo && strings.HasPrefix(f.Path, "/opt/etc/mihomo/"))) {
				targets = append(targets, f.Path)
			}
		}
		if len(targets) == 0 {
			return fail("Нет конфигурации выбранного ядра")
		}
		// Prepare again from backend bytes, never trust frontend readiness flags.
		for _, p := range targets {
			b, ok := proposal.File(p)
			if !ok {
				return fail("Закрытые данные конфигурации недоступны")
			}
			old, exists := s.Config(p)
			if exists && !bytes.Equal(old, b) {
				return fail("Существующая конфигурация должна быть сохранена")
			}
			if !exists && p != canonical {
				return fail("Неподдерживаемый путь новой конфигурации")
			}
			check, e := config.Prepare(s, config.Selection{Cores: []catalog.Component{c}, ActiveCore: c}, config.LocalImport(c, b))
			if e != nil {
				return fail("Конфигурация не прошла подготовку")
			}
			// Existing data takes precedence and the import-replacement conflict is expected here.
			for _, conflict := range check.Conflicts {
				if exists && strings.HasPrefix(conflict.Reason, "Import would replace") {
					continue
				}
				return fail("Конфигурация не прошла структурную проверку")
			}
			if c == catalog.Xray && unconfiguredXrayBase(b) {
				if c == active {
					return fail("Настройте соединение Xray перед активацией")
				}
				if len(d.pending) == 0 {
					d.pending = append(d.pending, "Xray установлен как неактивное ядро; соединение и маршрутизация требуют настройки перед его запуском")
				}
			}
			mode := fs.FileMode(0600)
			if exists {
				for _, f := range s.Files {
					if f.Path == p {
						mode = f.Mode.Perm()
					}
				}
			}
			d.configs = append(d.configs, payload{path: p, data: append([]byte(nil), b...), mode: mode, preserve: exists})
			seen[p] = true
		}
	}
	if selection.Config.Watchdog {
		if active != catalog.Mihomo || len(s.CronInit) != 1 || s.CronInit[0] != "/opt/etc/init.d/S10cron" {
			return fail("Watchdog требует активный совместимый Mihomo и проверенный S10cron; настройте cron вручную")
		}
		for _, f := range s.Files {
			if f.Path == "/opt/etc/init.d/S10cron" && f.Mode.Perm()&0111 == 0 {
				return fail("Скрипт cron не исполняемый; требуется ручная проверка")
			}
		}
		b, ok := proposal.File(config.MihomoPath)
		if !ok {
			return fail("Watchdog требует основной config.yaml")
		}
		check, e := config.Prepare(s, config.Selection{Cores: []catalog.Component{catalog.Mihomo}, ActiveCore: catalog.Mihomo, Watchdog: true}, config.LocalImport(catalog.Mihomo, b))
		if e != nil {
			return fail("Watchdog не прошёл подготовку")
		}
		for _, c := range check.Conflicts {
			if strings.HasPrefix(c.Reason, "Import would replace") {
				continue
			}
			return fail("Watchdog несовместим с конфигурацией Mihomo")
		}
		want, ok := check.File(config.WatchdogPath)
		got, have := proposal.File(config.WatchdogPath)
		if !ok || !have || !bytes.Equal(want, got) {
			return fail("Конфигурация watchdog не согласована")
		}
		_, exists := s.Config(config.WatchdogPath)
		mode := fs.FileMode(0600)
		if exists {
			for _, f := range s.Files {
				if f.Path == config.WatchdogPath {
					mode = f.Mode.Perm()
				}
			}
		}
		d.configs = append(d.configs, payload{path: config.WatchdogPath, data: got, mode: mode, preserve: exists})
		seen[config.WatchdogPath] = true
	}
	for _, f := range proposal.Files {
		if !seen[f.Path] {
			return fail("В предложении есть невыбранные файлы")
		}
	}
	if b, ok := s.Config("/opt/etc/init.d/S05xkeen"); ok {
		configured := catalog.Xray
		if bytes.Contains(b, []byte(`name_client="mihomo"`)) {
			configured = catalog.Mihomo
		}
		d.configuredCore = configured
		if (s.ActiveCore == "xray" || s.ActiveCore == "mihomo") && string(configured) != s.ActiveCore {
			return fail("Активное ядро не соответствует init; требуется ручная проверка")
		}
		marker := []byte("name_client=\"" + string(configured) + "\"")
		if bytes.Count(b, marker) != 1 || bytes.Count(b, []byte(`name_client="`)) != 1 || !bytes.HasPrefix(b, []byte("#!/bin/sh")) || !bytes.Contains(b, []byte("proxy_start()")) || !bytes.Contains(b, []byte("proxy_stop()")) || !bytes.Contains(b, []byte(`case "$1" in`)) {
			return fail("Нестандартный init XKeen требует ручной проверки")
		}
		d.existingInit = append([]byte(nil), b...)
		for _, f := range s.Files {
			if f.Path == "/opt/etc/init.d/S05xkeen" {
				d.existingInitMode = f.Mode.Perm()
			}
		}
	}
	if len(d.existingInit) == 0 && s.ActiveCoreEvidence == "single-core-process" {
		return fail("Запущенное ядро без известного init требует ручной проверки")
	}
	if active == catalog.Mihomo {
		found := false
		for _, f := range d.configs {
			if f.path == config.MihomoPath {
				found = true
			}
		}
		if !found {
			return fail("Для запуска Mihomo требуется основной config.yaml")
		}
	}
	if active == catalog.Xray {
		found := false
		for _, f := range d.configs {
			if strings.HasPrefix(f.path, "/opt/etc/xray/configs/") {
				found = true
			}
		}
		if !found {
			return fail("Для запуска Xray требуется конфигурация в штатном configs каталоге")
		}
	}
	if selection.UI {
		if init, ok := s.Config("/opt/etc/init.d/S99xkeen-ui"); ok && (!bytes.Contains(init, []byte("PROCS=xkeen-ui")) || !bytes.Contains(init, []byte(". /opt/etc/init.d/rc.func"))) {
			return fail("Нестандартный init панели требует ручной проверки")
		}
		port, existing, e := plannedUIPort(s)
		if e != nil {
			return Plan{}, e
		}
		if e = s.CheckUIPort(port, existing); e != nil {
			return Plan{}, e
		}
		d.uiPort = port
	}
	components := []catalog.Component{catalog.XKeen}
	for _, c := range []catalog.Component{catalog.Mihomo, catalog.Xray} {
		if selected[c] {
			components = append(components, c)
			if c == catalog.Mihomo {
				components = append(components, catalog.Yq)
			}
		}
	}
	if selection.UI {
		components = append(components, catalog.UI)
	}
	if selection.Config.Watchdog {
		components = append(components, catalog.Watchdog)
	}
	p := Plan{ActiveCore: active, Dependencies: []string{"curl", "jq", "ip-full", "iptables", "ipset", "ca-bundle", "coreutils-uname", "coreutils-nohup", "conntrack"}}
	if selection.UI {
		p.Notes = append(p.Notes, fmt.Sprintf("Проверен TCP-порт панели: %d; перед записью проверка будет повторена", d.uiPort))
	}
	if selection.Config.Watchdog {
		p.Dependencies = append(p.Dependencies, "python3", "python3-yaml", "wget-ssl")
	}
	for _, c := range components {
		a, e := catalog.Resolve(c, s.Arch)
		if e != nil {
			return fail("Архитектура компонента не поддерживается")
		}
		if c == catalog.Yq {
			p.Notes = append(p.Notes, "Для Mihomo устанавливается закреплённый yq "+runtimeVersion(a)+" (релиз "+a.Version+")")
		}
		p.Artifacts = append(p.Artifacts, a)
	}
	for _, a := range p.Artifacts {
		target := map[catalog.Component]string{catalog.XKeen: "/opt/sbin/xkeen + /opt/sbin/.xkeen/", catalog.Mihomo: "/opt/sbin/mihomo", catalog.Xray: "/opt/sbin/xray", catalog.Yq: "/opt/sbin/yq", catalog.UI: "/opt/sbin/xkeen-ui", catalog.Watchdog: "IPK: /opt/bin/router-watchdog + /opt/libexec/router-watchdog/ + /opt/etc/cron.1min/router-watchdog"}[a.Component]
		p.Changes = append(p.Changes, FileChange{target, "Установить закреплённый артефакт " + a.Version, "0755 (IPK: штатные права пакета)"})
	}
	for _, f := range d.configs {
		action := "Создать"
		if f.preserve {
			action = "Сохранить без изменения"
		}
		p.Changes = append(p.Changes, FileChange{f.path, action, fmt.Sprintf("%04o", f.mode)})
	}
	initAction := "Создать штатный init"
	if len(d.existingInit) > 0 {
		initAction = "Сохранить init"
		if d.active != d.configuredCore {
			initAction = "Изменить только name_client для выбранного ядра"
		}
	}
	p.Changes = append(p.Changes, FileChange{"/opt/etc/init.d/S05xkeen", initAction, fmt.Sprintf("%04o", d.existingInitMode)})
	if selection.UI {
		action := "Создать отключённый init; TLS ещё не проверен"
		if _, ok := s.Config("/opt/etc/init.d/S99xkeen-ui"); ok {
			action = "Сохранить существующий init и его флаги"
		}
		p.Changes = append(p.Changes, FileChange{"/opt/etc/init.d/S99xkeen-ui", action, "0755 (существующие права сохраняются)"})
	}
	p.Changes = append(p.Changes, FileChange{"/opt/etc/ndm/netfilter.d/proxy.sh + /opt/etc/ndm/schedule.d/00-xkeen-hotspot-sync.sh", "Штатные hooks запуска XKeen; существующие файлы включены в резервную копию", "Штатные права XKeen"})
	sort.Slice(p.Changes, func(i, j int) bool { return p.Changes[i].Path < p.Changes[j].Path })
	d.artifacts = append([]catalog.Artifact(nil), p.Artifacts...)
	var needed uint64 = 32 << 20
	for _, a := range p.Artifacts {
		needed += uint64(a.Size) * 5
	}
	for _, f := range s.Files {
		needed += uint64(f.Size) + 4096
	}
	if s.Available < needed {
		return fail("Недостаточно места для установки и резервной копии")
	}
	p.Steps = []Step{{"download", "Загрузить закреплённые версии и проверить SHA256 и архитектуру"}, {"reinspect", "Повторно проверить конфигурации, пакеты и активное ядро"}, {"backup", "Создать закрытую резервную копию и проверить чтением"}, {"dependencies", "Обновить индекс opkg и установить только перечисленные зависимости"}, {"stop", "Остановить выбранную службу перед заменой файлов"}, {"install", "Установить проверенные бинарные файлы и модули; сохранить настройки"}, {"configure", "Создать только отсутствующие конфигурации"}, {"validate", "Проверить установленные байты, версии и конфигурацию штатным валидатором"}, {"activate", "Запустить выбранное ядро и проверить процесс"}}
	if selection.Config.Watchdog {
		p.Steps = append(p.Steps, Step{"watchdog", "Установить проверенный IPK штатными hooks и согласовать cron"})
	}
	if selection.UI {
		p.Notes = append(p.Notes, "Новая панель устанавливается без запуска: HTTPS и готовность PWA требуют отдельной проверки TLS")
		p.Steps = append(p.Steps, Step{"ui", "Установить панель с сохранением настроек и закрытого состояния"})
	}
	p.Notes = append(p.Notes, d.pending...)
	p.Notes = append(p.Notes, "Отмена не откатывает opkg и завершённые записи; повтор требует новой проверки", "KeeneticOS, форматирование, выбор диска и перезагрузка не изменяются")
	id := make([]byte, 16)
	if _, err = rand.Read(id); err != nil {
		return fail("Не удалось создать план")
	}
	p.ID = hex.EncodeToString(id)
	p.private = d
	d.preview = publicPlan(p)
	return p, nil
}
func safeTarget(p string) bool {
	return strings.HasPrefix(p, "/opt/") && path.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n")
}

// Recognize only the installer's known unfinished base, including whitespace or
// key-order changes. Its status comes from private bytes, not mutable DTO flags.
func unconfiguredXrayBase(data []byte) bool {
	base, err := config.Prepare(router.Snapshot{}, config.Selection{Cores: []catalog.Component{catalog.Xray}, ActiveCore: catalog.Xray}, config.Import{})
	if err != nil {
		return false
	}
	expected, ok := base.File(config.XrayPath)
	if !ok {
		return false
	}
	var actualValue, baseValue any
	if json.Unmarshal(data, &actualValue) != nil || json.Unmarshal(expected, &baseValue) != nil {
		return false
	}
	actualJSON, _ := json.Marshal(actualValue)
	baseJSON, _ := json.Marshal(baseValue)
	return bytes.Equal(actualJSON, baseJSON)
}
