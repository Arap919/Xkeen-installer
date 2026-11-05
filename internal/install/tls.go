package install

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/router"
	localtls "github.com/Arap919/xkeen-installer/internal/tls"
)

const serverCertPath = "/opt/etc/nginx/ssl/server.crt"
const serverKeyPath = "/opt/etc/nginx/ssl/server.key"

func newUIInit(https bool) []byte {
	enabled, args := "no", "-p 1000"
	if https {
		enabled = "yes"
		args += " --tls-cert " + serverCertPath + " --tls-key " + serverKeyPath
	}
	return []byte("#!/bin/sh\nENABLED=" + enabled + "\nPROCS=xkeen-ui\nARGS=\"" + args + "\"\nPREARGS=\"\"\nDESC=\"$PROCS\"\nPATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin\n. /opt/etc/init.d/rc.func\n")
}

// BuildPlanWithTLS is backend-only. Existing UI flags and data remain untouched;
// existing different/invalid TLS requires manual reconciliation, never overwrite.
func BuildPlanWithTLS(s router.Snapshot, selection Selection, c config.ConfigProposal, tls localtls.TLSProposal) (Plan, error) {
	if !selection.UI {
		return Plan{}, errors.New("TLS требует выбранную панель")
	}
	if tls.ReadyForDeployment() != nil {
		return Plan{}, errors.New("Сначала сохраните CA в закрытом локальном хранилище")
	}
	cert, key, ok := tls.ServerPair()
	if !ok || localtls.ValidatePair(tls.Address(), cert, key, time.Now()) != nil {
		return Plan{}, errors.New("TLS не прошёл проверку")
	}
	oldCert, haveCert := s.Config(serverCertPath)
	oldKey, haveKey := s.Config(serverKeyPath)
	if haveKey {
		for _, f := range s.Files {
			if f.Path == serverKeyPath && f.Mode.Perm() != 0600 {
				return Plan{}, errors.New("Существующий ключ TLS требует закрытых прав0600")
			}
		}
	}
	if (haveCert || haveKey) && (!haveCert || !haveKey || !tls.MatchesExisting(oldCert, oldKey)) {
		return Plan{}, errors.New("Существующий TLS необходимо согласовать вручную; замена не разрешена")
	}
	if init, exists := s.Config("/opt/etc/init.d/S99xkeen-ui"); exists {
		if !knownUIArgs(init) {
			return Plan{}, errors.New("Существующие параметры TLS панели требуют ручного согласования")
		}
	}
	p, e := BuildPlan(s, selection, c)
	if e != nil {
		return Plan{}, e
	}
	p.private.tls = tls
	action := "Создать проверенный TLS"
	if haveCert {
		action = "Сохранить TLS без изменения"
	}
	certMode := "0600"
	for _, f := range s.Files {
		if f.Path == serverCertPath {
			certMode = fmt.Sprintf("%04o", f.Mode.Perm())
		}
	}
	p.Changes = append(p.Changes, FileChange{serverCertPath, action, certMode}, FileChange{serverKeyPath, action, "0600"})
	if !haveCert {
		for i := range p.Changes {
			if p.Changes[i].Path == "/opt/etc/init.d/S99xkeen-ui" {
				p.Changes[i].Action = "Создать init HTTPS и включить после проверки TLS"
			}
		}
	}
	for i, n := range p.Notes {
		if strings.HasPrefix(n, "Новая панель устанавливается без запуска:") {
			p.Notes[i] = "TLS подготовлен; фактическая проверка HTTPS и системного доверия выполняется отдельно"
		}
	}
	tlsStep := Step{"tls", "Перед запуском панели развернуть и проверить серверные TLS-материалы; CA key остаётся на компьютере"}
	for i, step := range p.Steps {
		if step.ID == "ui" {
			p.Steps = append(p.Steps[:i], append([]Step{tlsStep}, p.Steps[i:]...)...)
			break
		}
	}
	p.private.preview = publicPlan(p)
	return p, nil
}

// VerificationFiles is backend-only and returns defensive copies. The separate
// read-only verifier compares installed configs without rerunning native tools,
// which may write caches; native validation remains the reviewed Run stage.
func (p Plan) VerificationFiles() map[string][]byte {
	out := map[string][]byte{}
	if p.private != nil {
		for _, f := range p.private.configs {
			out[f.path] = append([]byte(nil), f.data...)
		}
	}
	if p.private != nil && p.private.selection.UI {
		init, exists := p.private.snapshot.Config("/opt/etc/init.d/S99xkeen-ui")
		if !exists {
			init = newUIInit(p.private.tls.Status() != localtls.Missing)
		}
		out["/opt/etc/init.d/S99xkeen-ui"] = init
	}
	return out
}
func (p Plan) Includes(c catalog.Component) bool {
	if p.private != nil {
		for _, a := range p.private.artifacts {
			if a.Component == c {
				return true
			}
		}
	}
	return false
}
func (p Plan) VerificationTLS() (string, []byte, bool) {
	if p.private == nil || p.private.tls.Status() == localtls.Missing {
		return "", nil, false
	}
	return p.private.tls.Address(), p.private.tls.PublicCA(), true
}

func (p Plan) VerificationActiveCore() catalog.Component {
	if p.private == nil {
		return ""
	}
	return p.private.active
}

var uiArgsLine = regexp.MustCompile(`(?m)^ARGS="([^"\r\n]*)"$`)

func plannedUIPort(s router.Snapshot) (int, bool, error) {
	init, exists := s.Config("/opt/etc/init.d/S99xkeen-ui")
	if !exists {
		return 1000, false, nil
	}
	matches := uiArgsLine.FindAllSubmatch(init, -1)
	if len(matches) != 1 {
		return 0, true, errors.New("Порт существующей панели требует ручной проверки")
	}
	args := strings.Fields(string(matches[0][1]))
	port, count := 0, 0
	for i, arg := range args {
		if strings.ContainsAny(arg, "$`\\;|&<>()") {
			return 0, true, errors.New("Параметры панели требуют ручной проверки")
		}
		if arg == "--port" || strings.HasPrefix(arg, "--port=") || (strings.HasPrefix(arg, "-p") && arg != "-p") {
			return 0, true, errors.New("Порт панели требует ручной проверки")
		}
		if arg != "-p" {
			continue
		}
		count++
		if i+1 >= len(args) {
			break
		}
		port, _ = strconv.Atoi(args[i+1])
	}
	if count != 1 || port < 1 || port > 65535 {
		return 0, true, errors.New("Порт существующей панели требует ручной проверки")
	}
	return port, true, nil
}

func knownUIArgs(init []byte) bool {
	matches := uiArgsLine.FindAllSubmatch(init, -1)
	if len(matches) != 1 {
		return false
	}
	args := strings.Fields(string(matches[0][1]))
	cert, key := 0, 0
	for i, arg := range args {
		if strings.ContainsAny(arg, "$`\\;") {
			return false
		}
		if arg == "--tls-cert" {
			if i+1 >= len(args) || args[i+1] != serverCertPath {
				return false
			}
			cert++
		}
		if arg == "--tls-key" {
			if i+1 >= len(args) || args[i+1] != serverKeyPath {
				return false
			}
			key++
		}
	}
	return cert == 1 && key == 1
}
