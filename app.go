package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/install"
	"github.com/Arap919/xkeen-installer/internal/router"
	localtls "github.com/Arap919/xkeen-installer/internal/tls"
	"github.com/Arap919/xkeen-installer/internal/verify"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func publicError(message string) error { return errors.New(message) }

// Only stable public categories cross the bridge; transport errors can contain
// server-provided text and must never be displayed or logged verbatim.
func connectionFailure(err error) error {
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout() {
		return publicError("[SSH_TIMEOUT] Время ожидания SSH истекло")
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		return publicError("[SSH_AUTH] SSH не принял учётные данные")
	}
	return publicError("[SSH_CONNECT] Не удалось установить SSH-соединение")
}

func inspectionFailure(err error) error {
	if errors.Is(err, router.ErrNotPOSIXShell) {
		return publicError("[SSH_SHELL] Подключение не предоставляет POSIX shell")
	}
	if errors.Is(err, router.ErrUnsupportedCPU) {
		return publicError("[SSH_ARCH] Архитектура роутера не поддерживается")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return publicError("[SSH_TIMEOUT] Проверка не завершилась за отведённое время")
	}
	return publicError("[SSH_INSPECT] SSH подключён, но проверка Entware не завершена")
}
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
func (a *App) invalidate() {
	a.snapshotID = ""
	a.plan = install.Plan{}
	a.proposal = config.ConfigProposal{}
	a.confirmed = false
	a.planSnapshot = ""
	a.trust = localtls.TrustAction{}
}
func (a *App) closeConnection() {
	if c, ok := a.transport.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	a.transport = nil
}

func (a *App) Inspect(c ConnectionRequest) (InspectionView, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy {
		return InspectionView{}, publicError("Дождитесь завершения операции")
	}
	if !a.bootstrapAwait {
		a.closeBootstrap()
	}
	if a.bootstrapAwait && c.Host != a.address {
		return InspectionView{}, publicError("[SSH_INITRC] Сначала завершите проверку Entware исходного роутера или завершите сессию")
	}
	a.invalidate()
	a.closeConnection()
	a.pendingHost = nil
	a.result = ResultView{}
	if c.Host == "" || strings.ContainsAny(c.Host, "/\\\r\n\x00 ") || strings.Contains(c.Host, ":") && net.ParseIP(c.Host) == nil || c.Port < 1 || c.Port > 65535 || c.User == "" || len(c.Password) > 4096 {
		return InspectionView{}, publicError("[SSH_INPUT] Проверьте адрес, порт и имя пользователя")
	}
	address := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	t, err := router.DialSSH(a.ctx, router.SSHConfig{Address: address, User: c.User, Auth: []ssh.AuthMethod{ssh.Password(c.Password)}, HostKeyFingerprint: a.hostKeys[address]})
	c.Password = ""
	if err != nil {
		var key *router.HostKeyError
		if errors.As(err, &key) {
			v := &HostKeyView{string(key.Kind), key.Address, key.Fingerprint, key.Expected, key.Algorithm}
			a.pendingHost = v
			return InspectionView{HostKey: v}, nil
		}
		return InspectionView{}, connectionFailure(err)
	}
	snapshot, err := router.Inspect(a.ctx, t)
	if err != nil {
		_ = t.Close()
		return InspectionView{}, inspectionFailure(err)
	}
	if a.bootstrapAwait {
		bounded, cancel := context.WithTimeout(a.ctx, 30*time.Second)
		err = verifyBootstrapHandoff(bounded, a.firmware, t)
		cancel()
		if !snapshot.Entware || err != nil {
			_ = t.Close()
			return InspectionView{}, publicError("[SSH_INITRC] Дождитесь завершения Entware; нужен Initrc /opt/etc/init.d/rc.unslung и исполняемый файл по этому пути")
		}
		a.closeBootstrap()
	}
	a.transport = t
	a.address = c.Host
	a.snapshot = snapshot
	a.snapshotID = newID()
	a.inspectedAt = time.Now()
	if a.snapshotID == "" {
		a.closeConnection()
		return InspectionView{}, publicError("Не удалось создать сессию проверки")
	}
	return InspectionView{ID: a.snapshotID, Arch: string(snapshot.Arch), Entware: snapshot.Entware, Available: snapshot.Available, ActiveCore: snapshot.ActiveCore, Versions: snapshot.Versions}, nil
}

func (a *App) ConfirmHostKey(address, fingerprint string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.pendingHost
	if a.busy || p == nil || p.Kind != string(router.HostKeyFirstUse) || p.Address != address || p.Fingerprint != fingerprint || a.hostKeys[address] != "" {
		return publicError("Замена известного ключа заблокирована; проверьте роутер вручную")
	}
	a.hostKeys[address] = fingerprint
	a.pendingHost = nil
	return nil
}
func (a *App) current(id string) bool {
	return id != "" && id == a.snapshotID && a.transport != nil && time.Since(a.inspectedAt) < 5*time.Minute
}
func (a *App) PreparePlan(r PlanRequest) (PlanView, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy {
		return PlanView{}, publicError("[PLAN/STATE/BUSY]")
	}
	if !a.current(r.InspectionID) {
		return PlanView{}, publicError("[PLAN/INSPECTION/STALE]")
	}
	a.plan = install.Plan{}
	a.confirmed = false
	a.planSnapshot = ""
	a.trust = localtls.TrustAction{}
	selection := config.Selection{ActiveCore: catalog.Component(r.ActiveCore), Watchdog: r.Watchdog}
	for _, core := range r.Cores {
		selection.Cores = append(selection.Cores, catalog.Component(core))
	}
	if len(r.ImportText) > config.MaxImportBytes {
		return PlanView{}, publicError("[PLAN/INPUT/FILE_SIZE]")
	}
	if r.ImportText != "" && (r.ProviderURL != "" || len(r.MihomoProviderURLs) > 0 || len(r.XrayProviderURLs) > 0) {
		return PlanView{}, publicError("[PLAN/INPUT/MIXED_SOURCES]")
	}
	if r.ProviderURL != "" && len(r.MihomoProviderURLs) > 0 {
		return PlanView{}, publicError("[PLAN/INPUT/DUPLICATE]")
	}

	input := config.Import{}
	if r.ImportText != "" {
		input = config.LocalImport(catalog.Component(r.ImportCore), []byte(r.ImportText))
	} else {
		urls := r.MihomoProviderURLs
		if r.ProviderURL != "" {
			urls = []string{r.ProviderURL}
		}
		var err error
		ctx := a.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		hasMihomo, hasXray := false, false
		for _, c := range selection.Cores {
			hasMihomo = hasMihomo || c == catalog.Mihomo
			hasXray = hasXray || c == catalog.Xray
		}
		if len(urls) > 0 && !hasMihomo {
			return PlanView{}, publicError("[SUBSCRIPTION/MIHOMO/SELECTION/CORE_MISSING/1/0]")
		}
		if len(r.XrayProviderURLs) > 0 && !hasXray {
			return PlanView{}, publicError("[SUBSCRIPTION/XRAY/SELECTION/CORE_MISSING/1/0]")
		}
		input, err = config.ResolveSubscriptions(ctx, urls, r.XrayProviderURLs)
		if err != nil {
			diagnostic := config.PublicSubscriptionError(err)
			if diagnostic == "" {
				diagnostic = "[SUBSCRIPTION/UNKNOWN/INTERNAL/UNEXPECTED/0/0]"
			}
			return PlanView{}, publicError(diagnostic)
		}
	}
	proposal, err := config.Prepare(a.snapshot, selection, input)
	if err != nil {
		if diagnostic := config.PublicSubscriptionError(err); diagnostic != "" {
			return PlanView{}, publicError(diagnostic)
		}
		return PlanView{}, publicError(configurationPlanDiagnostic(err))
	}
	a.proposal = proposal
	chosen := install.Selection{Config: selection, UI: r.UI}
	var plan install.Plan
	if r.UI {
		cert, _ := a.snapshot.Config("/opt/etc/nginx/ssl/server.crt")
		key, _ := a.snapshot.Config("/opt/etc/nginx/ssl/server.key")
		root, e := os.UserConfigDir()
		if e != nil {
			return PlanView{}, publicError("[PLAN/TLS/STORAGE_PATH]")
		}
		tls, dir, e := prepareTLSStore(a.address, cert, key, filepath.Join(root, "xkeen-installer"))
		if e != nil {
			var storage *localtls.StorageError
			if errors.As(e, &storage) {
				return PlanView{}, publicError("[PLAN/TLS/" + storage.Operation + "]")
			}
			return PlanView{}, publicError("[PLAN/TLS/PREPARE]")
		}
		a.tls = tls
		a.tlsDir = dir
		plan, err = install.BuildPlanWithTLS(a.snapshot, chosen, proposal, tls)
	} else {
		a.tls = localtls.TLSProposal{}
		a.tlsDir = ""
		plan, err = install.BuildPlan(a.snapshot, chosen, proposal)
	}
	if err != nil {
		v := a.planView()
		v.Message = err.Error()
		return v, nil
	}
	a.plan = plan
	a.planSnapshot = r.InspectionID
	return a.planView(), nil
}
func (a *App) planView() PlanView {
	p := a.plan
	v := PlanView{ID: p.ID, Steps: p.Steps, Changes: p.Changes, Dependencies: p.Dependencies, Notes: p.Notes, Files: a.proposal.Files}
	for _, conflict := range a.proposal.Conflicts {
		switch {
		case strings.HasPrefix(conflict.Reason, "Import would replace"):
			conflict.Reason = "Импорт заменил бы существующую конфигурацию; согласуйте изменения вручную"
		case strings.HasPrefix(conflict.Reason, "Watchdog requires"):
			conflict.Reason = "Watchdog требует согласованных групп Proxy/BENCHMARK (или прежней PROXY) с provider-backed узлами, API secret и отдельных портов; существующие данные сохранены"
		case strings.HasPrefix(conflict.Reason, "Existing watchdog"):
			conflict.Reason = "Существующие настройки watchdog не соответствуют конфигурации Mihomo"
		case strings.HasPrefix(conflict.Reason, "Add a user proxy outbound"):
			conflict.Reason = "Перед запуском Xray настройте исходящее соединение и маршрутизацию"
		case strings.HasPrefix(conflict.Reason, "A nonempty provider URL"):
			conflict.Reason = "Укажите подписку или локальную конфигурацию Mihomo"
		case strings.HasPrefix(conflict.Reason, "Choose an active core"), strings.HasPrefix(conflict.Reason, "Existing active core"):
			conflict.Reason = "Проверка не позволяет сохранить активное ядро автоматически; выберите его явно"
		default:
			conflict.Reason = "Структура конфигурации требует ручной проверки; существующие данные сохранены"
		}
		if strings.HasPrefix(conflict.NecessaryAddition, "Merge only missing entries") {
			if index := strings.IndexByte(conflict.NecessaryAddition, '\n'); index >= 0 {
				conflict.NecessaryAddition = conflict.NecessaryAddition[index+1:]
			}
		}
		if strings.HasPrefix(conflict.NecessaryAddition, "Replace blocked-until-configured") {
			conflict.NecessaryAddition = "Замените blocked-until-configured своим соединением и направьте transparent-in в него."
		}
		v.Conflicts = append(v.Conflicts, conflict)
	}
	for _, artifact := range p.Artifacts {
		v.Artifacts = append(v.Artifacts, ArtifactView{string(artifact.Component), artifact.Version})
	}
	return v
}
func (a *App) ConfirmPlan(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy || !a.current(a.planSnapshot) || id == "" || id != a.plan.ID {
		return publicError("План устарел; повторите проверку")
	}
	p, err := a.confirm(a.plan, id)
	if err != nil {
		return publicError("План нельзя подтвердить; повторите проверку")
	}
	a.plan = p
	a.confirmed = true
	return nil
}
func (a *App) StartInstall(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy || !a.confirmed || id == "" || id != a.plan.ID || !a.current(a.planSnapshot) {
		return publicError("Для запуска нужен актуальный явно подтверждённый план")
	}
	a.busy = true
	a.confirmed = false
	a.snapshotID = ""
	ctx, cancel := context.WithCancel(a.ctx)
	a.cancel = cancel
	p, t := a.plan, a.transport
	go func() {
		defer cancel()
		report, err := a.run(ctx, p, t, func(e install.Event) {
			a.emit(Progress{e.Step, e.Status, "Выполнение этапа: " + e.Step})
		})
		result := ResultView{Status: "partial", Message: "Установка завершена частично. Повторите проверку перед новым планом", Backup: report.Backup.Root, Completed: report.Completed, Applied: report.Applied, Uncertain: report.Uncertain, Pending: report.Pending, ReinspectRequired: true}
		if message := install.PackageFailureMessage(err); message != "" {
			result.Message = message
		}
		if ctx.Err() != nil {
			result.Status = "cancelled"
			result.Message = "Установка остановлена. Завершённые записи сохранены; требуется новая проверка"
		} else if err == nil && report.Complete {
			result.Status = "installed"
			result.Message = "Запланированные операции выполнены. Проверьте службы и HTTPS отдельно"
			result.ReinspectRequired = false
		}
		a.mu.Lock()
		a.result = result
		a.busy = false
		a.cancel = nil
		a.mu.Unlock()
		a.emit(Progress{"finished", result.Status, result.Message})
	}()
	return nil
}
func (a *App) CancelInstall() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		a.cancel()
	}
	if !a.busy {
		a.closeBootstrap()
	}
	a.snapshotID = ""
	a.confirmed = false
}
func (a *App) GetResult() ResultView { a.mu.Lock(); defer a.mu.Unlock(); return a.result }
func (a *App) PrepareTrust() (TrustView, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy || a.result.Status != "installed" || a.tlsDir == "" {
		return TrustView{Manual: "Установите проверенный публичный CA вручную на нужных устройствах; существующий TLS сохраняется"}, nil
	}
	action, err := a.tls.TrustAction(runtime.GOOS, a.tlsDir)
	if err != nil {
		return TrustView{}, publicError("Автоматическое доверие недоступно; используйте публичный ca.crt из локального хранилища")
	}
	a.trust = action
	return TrustView{action.ID, action.Description, action.Manual}, nil
}
func (a *App) ApplyTrust(id string, approved bool) (localtls.TrustResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy || a.result.Status != "installed" || id == "" || id != a.trust.ID || !approved {
		return localtls.TrustResult{}, publicError("Требуется отдельное подтверждение доверия этому CA")
	}
	return localtls.ApplyTrust(a.ctx, a.trust, id, approved, localtls.ExecRunner{}), nil
}
func (a *App) Verify() (ResultView, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy || a.transport == nil || a.result.Status != "installed" {
		return a.result, publicError("Проверка доступна после завершения установки")
	}
	a.result.PanelURL = ""
	report, err := verify.Verify(a.ctx, a.transport, a.plan)
	a.result.Services = report.Services
	if err != nil {
		a.result.Message = "Проверка не завершена; состояние служб требует ручной проверки"
		return a.result, nil
	}
	a.result.Message = "Проверка выполнена. Неподтверждённые пункты требуют ручных действий"
	for _, service := range report.Services {
		if verifiedPanelReady(service) {
			ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
			init, readErr := a.transport.Read(ctx, "/opt/etc/init.d/S99xkeen-ui")
			cancel()
			if readErr == nil {
				a.result.PanelURL = verifiedPanelAddress(a.address, init)
			}
		}
	}
	return a.result, nil
}
func (a *App) ExportRedactedReport() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := json.MarshalIndent(a.result, "", "  ")
	return string(b), err
}

func verifiedPanelReady(service verify.ServiceReport) bool {
	return service.Component == catalog.UI && service.HTTPS.State == verify.Passed && service.API.State == verify.Passed && service.Trust.State == verify.Passed
}

// Called only after HTTPS, panel API and system trust have passed verification.
func verifiedPanelAddress(address string, init []byte) string {
	var args []string
	count := 0
	for _, line := range strings.Split(string(init), "\n") {
		if strings.HasPrefix(line, "ARGS=\"") && strings.HasSuffix(line, "\"") {
			count++
			args = strings.Fields(strings.TrimSuffix(strings.TrimPrefix(line, "ARGS=\""), "\""))
		}
	}
	if count != 1 {
		return ""
	}
	port := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "-p" || args[i] == "--port" {
			if i+1 >= len(args) {
				return ""
			}
			i++
			port = args[i]
		}
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return ""
	}
	return "https://" + net.JoinHostPort(address, strconv.Itoa(number))
}
func (a *App) EndSession() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy {
		return publicError("Сначала остановите установку и дождитесь результата")
	}
	a.invalidate()
	a.closeBootstrap()
	a.closeConnection()
	a.snapshot = router.Snapshot{}
	a.tls = localtls.TLSProposal{}
	a.pendingHost = nil
	a.address = ""
	a.result = ResultView{}
	return nil
}

// Reuse owned CA material across preparations and app sessions. An invalid local
// store is never replaced; external existing certificates retain manual trust.
func prepareTLSStore(address string, cert, key []byte, base string) (localtls.TLSProposal, string, error) {
	hash := sha256.Sum256([]byte(address))
	dir := filepath.Join(base, hex.EncodeToString(hash[:]))
	if _, err := os.Lstat(dir); err == nil {
		owned, e := localtls.Load(dir, address)
		if e != nil {
			return localtls.TLSProposal{}, "", &localtls.StorageError{Operation: "LOAD_STORE"}
		}
		if len(cert) == 0 && len(key) == 0 || owned.MatchesExisting(cert, key) {
			return owned, dir, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return localtls.TLSProposal{}, "", err
	}
	proposal, err := localtls.PrepareTLS(address, localtls.ExistingTLS(cert, key, nil))
	if err != nil {
		return localtls.TLSProposal{}, "", &localtls.StorageError{Operation: "GENERATE"}
	}
	if proposal.Status() != localtls.Prepared {
		return proposal, "", nil
	}
	if err = os.MkdirAll(base, 0700); err != nil {
		return localtls.TLSProposal{}, "", &localtls.StorageError{Operation: "BASE_DIRECTORY"}
	}
	info, err := os.Lstat(base)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
		return localtls.TLSProposal{}, "", publicError("Закрытое хранилище CA недоступно")
	}
	if err = proposal.Save(dir); err != nil {
		return localtls.TLSProposal{}, "", err
	}
	return proposal, dir, nil
}

func configurationPlanDiagnostic(err error) string {
	reasons := map[string]string{
		"invalid core selection":                               "CORE_SELECTION",
		"select at least one core":                             "NO_CORE",
		"import size limit exceeded":                           "IMPORT_SIZE",
		"import core is not selected":                          "IMPORT_CORE",
		"provider import requires Mihomo without local import": "PROVIDER_SOURCE",
		"invalid Xray subscription input":                      "XRAY_INPUT",
		"active core is not selected":                          "ACTIVE_CORE",
		"snapshot configuration contents unavailable":          "SNAPSHOT",
		"Mihomo configuration size is invalid":                 "MIHOMO_SIZE",
		"invalid Mihomo YAML mapping":                          "MIHOMO_YAML",
		"multiple YAML documents are unsupported":              "YAML_DOCUMENTS",
		"Xray configuration size is invalid":                   "XRAY_SIZE",
		"invalid Xray JSON object":                             "XRAY_JSON",
		"generate API secret":                                  "API_SECRET",
		"missing embedded proxy providers":                     "EMBEDDED_PROVIDERS",
		"missing embedded VPNProvider":                         "EMBEDDED_PROVIDER",
	}
	if err != nil {
		if reason, ok := reasons[err.Error()]; ok {
			return "[PLAN/CONFIGURATION/" + reason + "]"
		}
	}
	return "[PLAN/CONFIGURATION/INTERNAL]"
}
