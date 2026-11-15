package main

import (
	"context"
	"errors"
	"github.com/Arap919/xkeen-installer/internal/bootstrap"
	"github.com/Arap919/xkeen-installer/internal/router"
	"golang.org/x/crypto/ssh"
	"net"
	"strconv"
	"strings"
	"time"
)

type BootstrapDiscovery struct {
	Model    string
	Hardware string
	Arch     string
	Volumes  []bootstrap.Volume
	HostKey  *HostKeyView
}

func (a *App) closeBootstrap() {
	a.bootstrap = nil
	a.bootstrapAwait = false
	if a.firmware != nil {
		_ = a.firmware.Close()
		a.firmware = nil
	}
	if a.closeStore != nil {
		_ = a.closeStore()
		a.closeStore = nil
	}
}
func (a *App) DiscoverBootstrap(c ConnectionRequest) (BootstrapDiscovery, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer func() { c.Password = "" }()
	if a.busy {
		return BootstrapDiscovery{}, publicError("Дождитесь завершения операции")
	}
	a.closeBootstrap()
	a.invalidate()
	a.closeConnection()
	a.pendingHost = nil
	a.result = ResultView{}
	if c.Host == "" || strings.ContainsAny(c.Host, "/\\\r\n\x00 ") || strings.Contains(c.Host, ":") && net.ParseIP(c.Host) == nil || c.Port < 1 || c.Port > 65535 || c.User == "" || len(c.Password) > 4096 {
		return BootstrapDiscovery{}, publicError("[SSH_INPUT] Проверьте адрес, порт и имя пользователя")
	}
	address := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	ctx, cancel := context.WithTimeout(a.ctx, 45*time.Second)
	defer cancel()
	t, e := router.DialSSH(ctx, router.SSHConfig{Address: address, User: c.User, Auth: []ssh.AuthMethod{ssh.Password(c.Password)}, HostKeyFingerprint: a.hostKeys[address]})
	if e != nil {
		var key *router.HostKeyError
		if errors.As(e, &key) {
			v := &HostKeyView{string(key.Kind), key.Address, key.Fingerprint, key.Expected, key.Algorithm}
			a.pendingHost = v
			return BootstrapDiscovery{HostKey: v}, nil
		}
		return BootstrapDiscovery{}, connectionFailure(e)
	}
	snap, e := bootstrap.Inspect(ctx, t)
	if e != nil {
		_ = t.Close()
		return BootstrapDiscovery{}, bootstrapDiscoveryFailure(e)
	}
	if len(snap.EligibleVolumes()) == 0 {
		_ = t.Close()
		return BootstrapDiscovery{}, publicError("[BOOTSTRAP_TARGET] Не найден подходящий EXT4-раздел с корневым SMB-ресурсом и безопасными настройками OPKG")
	}
	store, closeStore, e := bootstrap.DialStore(ctx, c.Host, c.User, c.Password)
	if e != nil {
		_ = t.Close()
		return BootstrapDiscovery{}, publicError("[BOOTSTRAP_SMB] SSH и CLI проверены; не удалось подключиться к SMB с обязательной подписью. Проверьте компонент SMB и права администратора")
	}
	a.firmware = t
	a.closeStore = closeStore
	a.bootstrap = bootstrap.NewSession(t, store)
	a.address = c.Host
	return BootstrapDiscovery{Model: snap.Model, Hardware: snap.Hardware, Arch: string(snap.Arch), Volumes: snap.EligibleVolumes()}, nil
}
func (a *App) PrepareBootstrap(uuid string) (bootstrap.Plan, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy || a.bootstrap == nil {
		return bootstrap.Plan{}, publicError("Повторите подключение к KeeneticOS")
	}
	ctx, cancel := context.WithTimeout(a.ctx, 45*time.Second)
	defer cancel()
	p, e := a.bootstrap.Prepare(ctx, uuid)
	if e != nil {
		return bootstrap.Plan{}, publicError("План Entware заблокирован: нужен однозначный доступный корень EXT4 без существующего Entware, чужого архива, другого OPKG-диска или пользовательского initrc")
	}
	return p, nil
}
func (a *App) StartBootstrap(id string, reviewed bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy || a.bootstrap == nil || id == "" || !reviewed {
		return publicError("Просмотрите и подтвердите актуальный план Entware")
	}
	session := a.bootstrap
	a.busy = true
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Minute)
	a.cancel = cancel
	go func() {
		defer cancel()
		triggered := false
		e := session.Start(ctx, id, reviewed, func(stage string) {
			if stage == "trigger" {
				triggered = true
			}
			a.emit(Progress{stage, "running", "Выполняется этап установки Entware"})
		})
		r := ResultView{Status: "bootstrap-partial", Message: bootstrapStartFailure(e).Error(), ReinspectRequired: true}
		if e == nil {
			r.Status = "waiting-shell"
			r.Message = "Архив проверен и передан; KeeneticOS получил команду OPKG. Дождитесь установки и проверьте SSH Entware"
		} else if ctx.Err() != nil {
			r.Status = "cancelled"
			r.Message = "Операция остановлена; выполненные записи сохраняются. Состояние OPKG требует повторной проверки"
		} else if errors.Is(e, bootstrap.ErrTriggerUncertain) {
			r.Uncertain = "opkg disk"
			r.Message = "Ответ на команду OPKG не подтверждён. Она могла выполниться; проверьте SSH Entware перед повтором"
		}
		a.mu.Lock()
		a.result = r
		a.busy = false
		a.cancel = nil
		if triggered {
			a.bootstrap = nil
			a.bootstrapAwait = true
			if a.closeStore != nil {
				_ = a.closeStore()
				a.closeStore = nil
			}
		} else {
			a.closeBootstrap()
		}
		a.mu.Unlock()
		a.emit(Progress{"bootstrap-finished", r.Status, r.Message})
	}()
	return nil
}

// A successful root shell is necessary, but the native installer must also have
// restored its final firmware init path and produced an executable startup file.
func verifyBootstrapHandoff(ctx context.Context, cli bootstrap.CLI, t router.Transport) error {
	if e := bootstrap.FinalInitrc(ctx, cli); e != nil {
		return e
	}
	entry, e := t.Stat(ctx, "/opt/etc/init.d/rc.unslung")
	if e != nil || !entry.Mode.IsRegular() || entry.Mode.Perm()&0111 == 0 {
		return bootstrap.ErrUnsafe
	}
	return nil
}

func bootstrapDiscoveryFailure(err error) error {
	var stage *bootstrap.DiscoveryError
	if errors.As(err, &stage) {
		switch stage.Stage {
		case "show version":
			return publicError("[BOOTSTRAP_VERSION] SSH принят, но команда show version не завершилась")
		case "show media":
			return publicError("[BOOTSTRAP_MEDIA] SSH принят, но команда show media не завершилась")
		case "show running-config":
			return publicError("[BOOTSTRAP_CONFIG] SSH принят, но команда show running-config не завершилась")
		case "show cifs":
			return publicError("[BOOTSTRAP_CIFS] SSH-команда show cifs не завершилась")
		case "parse cifs":
			message := "[BOOTSTRAP_CIFS_PARSE] Команда show cifs выполнена, но её ответ не прошёл разбор активных SMB-ресурсов"
			var detail *bootstrap.CIFSParseError
			if errors.As(err, &detail) {
				message += " " + detail.Diagnostic()
			}
			return publicError(message)
		}
	}
	return publicError("[BOOTSTRAP_PARSE] SSH и команды CLI выполнены, но не удалось безопасно разобрать модель, разделы или настройки OPKG/SMB")
}

func bootstrapStartFailure(err error) error {
	messages := map[string]string{
		"reinspect":                 "Повторная проверка KeeneticOS перед загрузкой архива не завершилась.",
		"download":                  "Не удалось прочитать и проверить встроенный архив Entware.",
		"pre-transfer-inspect":      "Проверка KeeneticOS после скачивания архива не завершилась; копирование не начато.",
		"store-check":               "Проверка корня SMB перед копированием архива не прошла.",
		"transfer":                  "Передача архива Entware через SMB или его контрольное чтение не завершились. Команды запуска OPKG не отправлены.",
		"post-transfer-inspect":     "Архив передан через SMB; последующая проверка KeeneticOS не прошла. Команды запуска OPKG не отправлены.",
		"post-transfer-store-check": "Архив передан; проверка SMB перед запуском OPKG не прошла. Команды запуска OPKG не отправлены.",
		"trigger":                   "Выполнение команд OPKG не подтверждено. Не повторяйте запуск без проверки состояния.",
	}
	var stage *bootstrap.StartError
	if errors.As(err, &stage) {
		if message, ok := messages[stage.Stage]; ok {
			return publicError("[BOOTSTRAP/" + strings.ToUpper(strings.ReplaceAll(stage.Stage, "-", "_")) + "] " + message)
		}
	}
	return publicError("[BOOTSTRAP/START] Установка Entware остановлена до подтверждения этапа. Повторите проверку состояния.")
}
