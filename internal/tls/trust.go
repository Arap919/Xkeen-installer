package tls

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type CommandRunner interface {
	LookPath(string) (string, error)
	Run(context.Context, string, ...string) error
}

// ExecRunner is only used by an explicit confirmed ApplyTrust call, never PrepareTLS.
type ExecRunner struct{}

func (ExecRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }
func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if cmd.Run() != nil {
		return errors.New("trust command failed")
	}
	return nil
}

type trustCommand struct {
	name string
	args []string
}
type TrustAction struct {
	ID          string
	Description string
	Manual      string
	preview     string
	dir         string
	ca          []byte
	commands    []trustCommand
}

func (a TrustAction) String() string   { b, _ := json.Marshal(a); return string(b) }
func (a TrustAction) GoString() string { return a.String() }

type TrustResult struct {
	Status Trust
	Detail string
}

func (p TLSProposal) TrustAction(platform, dir string) (TrustAction, error) {
	if p.private == nil || p.TrustStatus() == TrustManual || len(p.private.ca) == 0 {
		return TrustAction{}, errors.New("CA unavailable; manual trust required")
	}
	r, e := openStore(dir, false)
	if e != nil {
		return TrustAction{}, e
	}
	ca, e := readPrivate(r, "ca.crt")
	r.Close()
	if e != nil || sha256.Sum256(ca) != sha256.Sum256(p.private.ca) {
		return TrustAction{}, errStorage
	}
	hash := sha256.Sum256(ca)
	id := hex.EncodeToString(hash[:])
	source := filepath.Join(dir, "ca.crt")
	a := TrustAction{ID: id, dir: dir, ca: clone(ca), Manual: "Установите только проверенный публичный ca.crt в доверенные корневые центры; административные права могут потребоваться."}
	switch platform {
	case "darwin":
		a.commands = []trustCommand{{"security", []string{"add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", source}}}
	case "windows":
		a.commands = []trustCommand{{"certutil", []string{"-user", "-addstore", "Root", source}}}
	case "linux":
		dest := "/usr/local/share/ca-certificates/xkeen-" + id + ".crt"
		a.commands = []trustCommand{{"install", []string{"-m", "0644", source, dest}}, {"update-ca-certificates", nil}}
	default:
		return TrustAction{}, errors.New("automatic trust unsupported; manual installation required")
	}
	var lines []string
	for _, c := range a.commands {
		parts := []string{c.name}
		for _, v := range c.args {
			parts = append(parts, `"`+strings.ReplaceAll(v, `"`, `\"`)+`"`)
		}
		lines = append(lines, strings.Join(parts, " "))
	}
	a.Description = "Добавить CA SHA256 " + id + " в хранилище доверия: " + strings.Join(lines, "; ") + ". Требуется отдельное подтверждение; команды выполняются без shell и без sudo."
	a.preview = a.String()
	return a, nil
}

// A missing/refused confirmation cannot invoke even LookPath. ID binds approval
// to the exact CA; fields serialized through the UI cannot mint a private action.
func ApplyTrust(ctx context.Context, a TrustAction, reviewedID string, approved bool, runner CommandRunner) TrustResult {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	pending := TrustResult{TrustPending, "Доверие CA не завершено"}
	if a.preview != a.String() || !approved || reviewedID == "" || a.ID != reviewedID || len(a.ca) == 0 || len(a.commands) == 0 || runner == nil {
		return pending
	}
	r, e := openStore(a.dir, false)
	if e != nil {
		return TrustResult{TrustManual, "Закрытое хранилище CA недоступно"}
	}
	ca, e := readPrivate(r, "ca.crt")
	r.Close()
	if e != nil || sha256.Sum256(ca) != sha256.Sum256(a.ca) {
		return TrustResult{TrustManual, "CA изменён; повторите просмотр"}
	}
	paths := make([]string, len(a.commands))
	for i, c := range a.commands {
		paths[i], e = runner.LookPath(c.name)
		if e != nil {
			return TrustResult{TrustManual, "Системная утилита недоступна; требуется ручная установка CA"}
		}
	}
	for i, c := range a.commands {
		if ctx.Err() != nil || runner.Run(ctx, paths[i], c.args...) != nil {
			return pending
		}
	}
	return TrustResult{TrustInstalled, "Системная команда установки CA выполнена; проверка HTTPS и доверия выполняется отдельно"}
}
