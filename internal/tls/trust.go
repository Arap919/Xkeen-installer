package tls

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type CommandRunner interface {
	LookPath(string) (string, error)
	Run(context.Context, string, ...string) error
}

// ExecRunner is only used by an explicit confirmed ApplyTrust call, never PrepareTLS.
type ExecRunner struct{}

func (ExecRunner) LookPath(name string) (string, error) {
	paths, err := trustedUtilityPaths(name)
	if err != nil {
		return "", err
	}
	return availableTrustUtility(paths)
}

func availableTrustUtility(paths []string) (string, error) {
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			continue
		}
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() && trustUtilityExecutable(info.Mode()) {
			return path, nil
		}
	}
	return "", errors.New("trusted system utility unavailable")
}

func trustExecCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	path, err := (ExecRunner{}).LookPath(name)
	if err != nil || !filepath.IsAbs(name) || path != name {
		return nil, errors.New("untrusted system utility")
	}
	env, err := trustCommandEnvironment()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = env
	return cmd, nil
}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd, err := trustExecCommand(ctx, name, args...)
	if err != nil {
		return err
	}
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
	Code   string
}

// The certificate path is passed as argv and quoted by AppleScript.
const macOSTrustScript = `on run argv
do shell script "/usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " & quoted form of (item 1 of argv) with administrator privileges
end run`

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
		a.commands = []trustCommand{{"/usr/bin/osascript", []string{"-e", macOSTrustScript, source}}}
		a.Description = "Добавить CA SHA256 " + id + " в хранилище System macOS. macOS запросит разрешение администратора в системном окне."
	case "windows":
		a.commands = []trustCommand{{"certutil", []string{"-user", "-addstore", "Root", source}}}
		a.Description = "Добавить CA SHA256 " + id + " в хранилище CurrentUser Root Windows для текущего пользователя. Если Windows покажет системный запрос, подтвердите добавление этого CA."
	case "linux":
		dest := "/usr/local/share/ca-certificates/xkeen-" + id + ".crt"
		a.commands = []trustCommand{{"install", []string{"-m", "0644", source, dest}}, {"update-ca-certificates", nil}}
		a.Description = "Добавить CA SHA256 " + id + " в системное хранилище доверенных центров Linux. Для изменения системного хранилища необходимы соответствующие права."
	default:
		return TrustAction{}, errors.New("automatic trust unsupported; manual installation required")
	}

	a.preview = a.String()
	return a, nil
}

// A missing/refused confirmation cannot invoke even LookPath. ID binds approval
// to the exact CA; fields serialized through the UI cannot mint a private action.
func ApplyTrust(ctx context.Context, a TrustAction, reviewedID string, approved bool, runner CommandRunner) TrustResult {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	pending := TrustResult{Status: TrustPending, Detail: "Доверие CA не завершено", Code: "approval_required"}
	if a.preview != a.String() || !approved || reviewedID == "" || a.ID != reviewedID || len(a.ca) == 0 || len(a.commands) == 0 || runner == nil {
		return pending
	}
	r, e := openStore(a.dir, false)
	if e != nil {
		return TrustResult{Status: TrustManual, Detail: "Закрытое хранилище CA недоступно", Code: "storage_unavailable"}
	}
	ca, e := readPrivate(r, "ca.crt")
	r.Close()
	if e != nil || sha256.Sum256(ca) != sha256.Sum256(a.ca) {
		return TrustResult{Status: TrustManual, Detail: "CA изменён; повторите просмотр", Code: "ca_changed"}
	}
	paths := make([]string, len(a.commands))
	for i, c := range a.commands {
		paths[i], e = runner.LookPath(c.name)
		if e != nil {
			return TrustResult{Status: TrustManual, Detail: "Системная утилита недоступна; требуется ручная установка CA", Code: "utility_unavailable"}
		}
	}
	for i, c := range a.commands {
		err := ctx.Err()
		if err == nil {
			err = runner.Run(ctx, paths[i], c.args...)
		}
		if err != nil {
			switch ctx.Err() {
			case context.Canceled:
				return TrustResult{Status: TrustPending, Detail: "[CA/IMPORT/CANCELLED] Установка CA отменена.", Code: "cancelled"}
			case context.DeadlineExceeded:
				return TrustResult{Status: TrustPending, Detail: "[CA/IMPORT/TIMEOUT] Истекло время ожидания установки CA.", Code: "timeout"}
			default:
				return TrustResult{Status: TrustPending, Detail: "[CA/IMPORT/COMMAND_FAILED] Системная команда установки CA не выполнена.", Code: "command_failed"}
			}
		}
	}
	return TrustResult{Status: TrustInstalled, Detail: "Системная команда установки CA выполнена; проверка HTTPS и доверия ещё не завершена", Code: "verification_pending"}
}
