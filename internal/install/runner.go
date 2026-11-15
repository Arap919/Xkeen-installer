package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/router"
	localtls "github.com/Arap919/xkeen-installer/internal/tls"
)

type loader func(context.Context, []catalog.Artifact) ([]payload, error)

func Run(ctx context.Context, p Plan, t router.Transport, emit func(Event)) (Report, error) {
	return run(ctx, p, t, emit, loadArtifacts)
}
func run(ctx context.Context, p Plan, t router.Transport, emit func(Event), load loader) (Report, error) {
	ctx, cancelRun := context.WithTimeout(ctx, 20*time.Minute)
	defer cancelRun()
	r := Report{ReinspectRequired: true}
	d := p.private
	if d == nil || !p.confirmed || d.preview != publicPlan(p) {
		return r, ErrUnconfirmed
	}
	if !d.used.CompareAndSwap(false, true) {
		return r, ErrConsumed
	}
	if d.tls.Status() != localtls.Missing && d.tls.ReadyForDeployment() != nil {
		return r, errors.New("Закрытое локальное хранилище CA недоступно; повторите подготовку TLS")
	}
	r.Pending = append([]string(nil), d.pending...)
	step := "download"
	mutating := false
	fail := func() (Report, error) {
		if mutating {
			r.Uncertain = step
		}
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		return r, fmt.Errorf("Этап %s не завершён; повторите проверку состояния", step)
	}
	write := func(f payload) error {
		r.UncertainPath = f.path
		if err := writeChecked(ctx, t, f); err != nil {
			return err
		}
		r.Applied = append(r.Applied, f.path)
		r.UncertainPath = ""
		return nil
	}
	begin := func(id string) {
		step = id
		mutating = false
		if emit != nil {
			emit(Event{step, "running"})
		}
	}
	done := func() {
		r.Completed = append(r.Completed, step)
		mutating = false
		if emit != nil {
			emit(Event{step, "completed"})
		}
	}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	begin("download")
	files, err := load(ctx, d.artifacts)
	if err == nil {
		required := map[catalog.Component]string{catalog.XKeen: "/opt/sbin/xkeen", catalog.Xray: "/opt/sbin/xray", catalog.Mihomo: "/opt/sbin/mihomo", catalog.Yq: "/opt/sbin/yq", catalog.UI: "/opt/sbin/xkeen-ui", catalog.Watchdog: "/opt/.xkeen-installer-packages/router-watchdog_1.0.16-1_all.ipk"}
		for _, a := range d.artifacts {
			found := false
			for _, f := range files {
				if f.component == a.Component && f.path == required[a.Component] {
					found = true
				}
			}
			if !found {
				err = errors.New("component payload missing")
			}
		}
	}
	if err != nil {
		return fail()
	}
	if d.subscriptions {
		for _, name := range []string{"geoip.dat", "geosite.dat"} {
			p := "/opt/etc/xray/dat/" + name
			_, existing := d.snapshot.Config(p)
			found := existing
			for _, f := range files {
				if f.path == p {
					found = true
				}
			}
			if !found {
				return fail()
			}
		}
	}
	done()
	begin("reinspect")
	fresh, err := router.Inspect(ctx, t)
	if err != nil {
		return fail()
	}
	fp, err := fingerprint(fresh)
	if err != nil {
		return fail()
	}
	if fp != d.fingerprint {
		return r, ErrStale
	}
	if d.selection.UI {
		_, existing := fresh.Config("/opt/etc/init.d/S99xkeen-ui")
		if err = fresh.CheckUIPort(d.uiPort, existing); err != nil {
			return fail()
		}
	}
	if _, e := command(ctx, t, cronPreflightCommand); e != nil {
		return fail()
	}
	// Upstream init resolves a bare core through /opt/bin before /opt/sbin.
	// Never validate one executable and subsequently launch a shadowing one.
	if _, e := t.Stat(ctx, "/opt/bin/"+string(d.active)); !errors.Is(e, fs.ErrNotExist) {
		return fail()
	}
	for _, a := range d.artifacts {
		if a.Component == catalog.Yq {
			if _, e := t.Stat(ctx, "/opt/bin/yq"); !errors.Is(e, fs.ErrNotExist) {
				return fail()
			}
		}
	}
	for _, f := range files {
		if !safeTarget(f.path) {
			return fail()
		}
	}
	var need uint64 = 32 << 20
	for _, f := range files {
		need += uint64(len(f.data)) * 2
	}
	for _, f := range fresh.Files {
		need += uint64(f.Size) + 4096
	}
	if fresh.Available < need {
		return fail()
	}
	done()
	begin("backup")
	mutating = true
	r.Backup, err = router.Backup(ctx, t, fresh)
	if err != nil || !r.Backup.Verified() {
		return fail()
	}
	done()
	// No package, installed-file or service mutation is allowed above this point.
	begin("dependencies")
	mutating = true
	if _, err = command(ctx, t, "/opt/bin/opkg update"); err != nil {
		return fail()
	}
	args := "/opt/bin/opkg install"
	for _, name := range p.Dependencies {
		args += " " + quote(name)
	}
	if _, err = command(ctx, t, args); err != nil {
		return fail()
	}
	done()
	begin("stop")
	mutating = true
	if len(d.existingInit) > 0 {
		if _, err = command(ctx, t, "/opt/etc/init.d/S05xkeen stop"); err != nil {
			return fail()
		}
	}
	if d.selection.UI {
		if _, ok := fresh.Config("/opt/etc/init.d/S99xkeen-ui"); ok {
			if _, err = command(ctx, t, "/opt/etc/init.d/S99xkeen-ui stop"); err != nil {
				return fail()
			}
		}
	}
	done()
	begin("install")
	mutating = true
	var newInit []byte
	for _, f := range files {
		if f.component == catalog.Watchdog {
			continue
		}
		if f.path == "/opt/sbin/.xkeen/02_install/07_install_register/04_register_init.sh" {
			newInit = append([]byte(nil), f.data...)
		}
		if strings.HasPrefix(f.path, "/opt/etc/xray/dat/") {
			if _, exists := fresh.Config(f.path); exists {
				continue
			}
			if _, e := t.Stat(ctx, f.path); !errors.Is(e, fs.ErrNotExist) {
				return fail()
			}
		}
		if err = write(f); err != nil {
			return fail()
		}
	}
	init := append([]byte(nil), d.existingInit...)
	if len(init) == 0 {
		init = newInit
		if len(init) == 0 {
			return fail()
		}
		if bytes.Count(init, []byte("name_client=\"xray\"")) != 1 {
			return fail()
		}
		init = bytes.Replace(init, []byte("name_client=\"xray\""), []byte("name_client=\""+string(d.active)+"\""), 1)
	} else if d.active != d.configuredCore {
		init = bytes.Replace(init, []byte("name_client=\""+string(d.configuredCore)+"\""), []byte("name_client=\""+string(d.active)+"\""), 1)
	}
	if len(d.existingInit) == 0 || !bytes.Equal(init, d.existingInit) {
		if err = write(payload{path: "/opt/etc/init.d/S05xkeen", data: init, mode: d.existingInitMode}); err != nil {
			return fail()
		}
	}
	done()
	begin("configure")
	mutating = true
	for _, f := range d.configs {
		if f.path == config.XraySchedulePath {
			continue
		}
		if f.preserve {
			actual, e := t.Read(ctx, f.path)
			if e != nil || !bytes.Equal(actual, f.data) {
				return fail()
			}
			continue
		}
		if _, e := t.Stat(ctx, f.path); !errors.Is(e, fs.ErrNotExist) {
			return fail()
		}
		if err = write(f); err != nil {
			return fail()
		}
	}
	done()
	begin("validate")
	for _, a := range d.artifacts {
		var out []byte
		switch a.Component {
		case catalog.Mihomo:
			out, err = command(ctx, t, "/opt/sbin/mihomo -v")
		case catalog.Xray:
			out, err = command(ctx, t, "/opt/sbin/xray version")
		case catalog.Yq:
			out, err = command(ctx, t, "/opt/sbin/yq --version")
		default:
			continue
		}
		if err != nil || !hasVersion(out, runtimeVersion(a)) {
			return fail()
		}
	}
	// Private configuration is materialized in an isolated directory. Neither stdout
	// nor stderr from a core validator is included in events, errors or reports.
	stage := "/opt/.xkeen-installer-stage/" + p.ID
	for _, f := range d.configs {
		if f.path == config.WatchdogPath || f.path == config.XraySourcesPath || f.path == config.XrayUpdaterPath || f.path == config.XraySchedulePath {
			continue
		}
		copy := f
		copy.path = stage + f.path
		copy.mode = 0600
		if err = write(copy); err != nil {
			mutating = true
			return fail()
		}
	}
	var validation string
	if d.active == catalog.Mihomo {
		validation = "/opt/sbin/mihomo -t -d " + quote(stage+"/opt/etc/mihomo") + " -f " + quote(stage+config.MihomoPath)
	} else {
		validation = "XRAY_LOCATION_ASSET=/opt/etc/xray/dat /opt/sbin/xray run -test -confdir " + quote(stage+"/opt/etc/xray/configs")
	}
	if _, err = command(ctx, t, validation); err != nil {
		return fail()
	}
	// Check the actual installed config as well: relative providers/assets can differ.
	if d.active == catalog.Mihomo {
		validation = "/opt/sbin/mihomo -t -d /opt/etc/mihomo -f /opt/etc/mihomo/config.yaml"
	} else {
		validation = "XRAY_LOCATION_ASSET=/opt/etc/xray/dat /opt/sbin/xray run -test -confdir /opt/etc/xray/configs"
	}
	if _, err = command(ctx, t, validation); err != nil {
		return fail()
	}
	if d.subscriptions && d.active != catalog.Xray {
		if _, err = command(ctx, t, "XRAY_LOCATION_ASSET=/opt/etc/xray/dat /opt/sbin/xray run -test -confdir "+quote(stage+"/opt/etc/xray/configs")); err != nil {
			return fail()
		}
		if _, err = command(ctx, t, "XRAY_LOCATION_ASSET=/opt/etc/xray/dat /opt/sbin/xray run -test -confdir /opt/etc/xray/configs"); err != nil {
			return fail()
		}
	}
	done()
	begin("activate")
	mutating = true
	// Calling the standalone init avoids xkeen's implicit self-healing opkg writes
	// and its detach behavior. 'on' requests a synchronous, explicit user start.
	if _, err = command(ctx, t, serviceLaunch("XRAY_LOCATION_ASSET=/opt/etc/xray/dat /opt/etc/init.d/S05xkeen start on")); err != nil {
		return fail()
	}
	if _, err = command(ctx, t, "/opt/etc/init.d/S05xkeen status"); err != nil {
		return fail()
	}
	actual, err := router.Inspect(ctx, t)
	if err != nil || actual.ActiveCore != string(d.active) {
		return fail()
	}
	done()
	begin("cron")
	mutating = true
	if _, err = command(ctx, t, cronPreflightCommand); err != nil {
		return fail()
	}
	if _, err = command(ctx, t, serviceLaunch("/opt/etc/init.d/S10cron start")); err != nil {
		return fail()
	}
	if _, err = command(ctx, t, cronVerifyCommand); err != nil {
		return fail()
	}
	done()
	if d.subscriptions {
		begin("subscriptions")
		mutating = true
		for _, f := range d.configs {
			if f.path == config.XraySchedulePath {
				if f.preserve {
					old, e := t.Read(ctx, f.path)
					if e != nil || !bytes.Equal(old, f.data) {
						return fail()
					}
				} else {
					if _, e := t.Stat(ctx, f.path); !errors.Is(e, fs.ErrNotExist) {
						return fail()
					}
					if err = write(f); err != nil {
						return fail()
					}
				}
			}
		}
		done()
	}
	if d.selection.Config.Watchdog {
		begin("watchdog")
		mutating = true
		for _, f := range files {
			if f.component == catalog.Watchdog {
				if err = write(f); err != nil {
					return fail()
				}
				if _, err = command(ctx, t, "/opt/bin/opkg install "+quote(f.path)); err != nil {
					return fail()
				}
			}
		}
		// Package hooks can merge defaults. Restore the reviewed exact bytes before
		// an explicit sync, rather than silently accepting a rewritten configuration.
		for _, f := range d.configs {
			if f.path == config.WatchdogPath {
				if err = write(f); err != nil {
					return fail()
				}
			}
		}
		if _, err = command(ctx, t, "/opt/bin/router-watchdog --sync-cron"); err != nil {
			return fail()
		}
		if _, err = command(ctx, t, cronVerifyCommand); err != nil {
			return fail()
		}
		check, e := router.Inspect(ctx, t)
		a, _ := catalog.Resolve(catalog.Watchdog, fresh.Arch)
		if e != nil || check.Versions["router-watchdog"] != a.Version {
			return fail()
		}
		done()
	}
	if d.selection.UI && d.tls.Status() != localtls.Missing {
		begin("tls")
		cert, key, ok := d.tls.ServerPair()
		if !ok || localtls.ValidatePair(d.tls.Address(), cert, key, time.Now()) != nil {
			return fail()
		}
		for _, f := range []payload{{path: serverCertPath, data: cert, mode: 0600}, {path: serverKeyPath, data: key, mode: 0600}} {
			if existing, exists := fresh.Config(f.path); exists {
				if !bytes.Equal(existing, f.data) {
					return fail()
				}
				continue
			}
			if _, e := t.Stat(ctx, f.path); !errors.Is(e, fs.ErrNotExist) {
				return fail()
			}
			mutating = true
			if err = write(f); err != nil {
				return fail()
			}
		}
		actualCert, ce := t.Read(ctx, serverCertPath)
		actualKey, ke := t.Read(ctx, serverKeyPath)
		if ce != nil || ke != nil || localtls.ValidatePair(d.tls.Address(), actualCert, actualKey, time.Now()) != nil {
			return fail()
		}
		r.Pending = append(r.Pending, "Проверьте фактический HTTPS API и системное доверие CA отдельно; готовность PWA ещё не подтверждена")
		done()
	}
	if d.selection.UI {
		begin("ui")
		mutating = true
		if _, ok := fresh.Config("/opt/etc/init.d/S99xkeen-ui"); ok {
			if _, err = command(ctx, t, serviceLaunch("/opt/etc/init.d/S99xkeen-ui start")); err != nil {
				return fail()
			}
			if _, err = command(ctx, t, "/opt/etc/init.d/S99xkeen-ui status"); err != nil {
				return fail()
			}
		} else {
			init := newUIInit(d.tls.Status() != localtls.Missing)
			if err = write(payload{path: "/opt/etc/init.d/S99xkeen-ui", data: init, mode: 0755}); err != nil {
				return fail()
			}
			if d.tls.Status() == localtls.Missing {
				r.Pending = append(r.Pending, "Панель установлена без запуска; настройка TLS и проверка HTTPS/PWA ещё не выполнены")
			} else {
				if _, err = command(ctx, t, serviceLaunch("/opt/etc/init.d/S99xkeen-ui start")); err != nil {
					return fail()
				}
				if _, err = command(ctx, t, "/opt/etc/init.d/S99xkeen-ui status"); err != nil {
					return fail()
				}
			}
		}
		done()
	}
	for _, f := range d.configs {
		b, e := t.Read(ctx, f.path)
		if e != nil || !bytes.Equal(b, f.data) {
			begin("preservation")
			return fail()
		}
	}
	for _, original := range fresh.Files {
		protected := strings.HasPrefix(original.Path, "/opt/etc/xkeen/") || strings.HasPrefix(original.Path, "/opt/etc/xkeen-ui/") || strings.HasPrefix(original.Path, "/opt/etc/nginx/ssl/") || strings.HasPrefix(original.Path, "/opt/etc/mihomo/") || strings.HasPrefix(original.Path, "/opt/etc/xray/")
		if !protected {
			continue
		}
		expected, _ := fresh.Config(original.Path)
		actual, e := t.Read(ctx, original.Path)
		stat, se := t.Stat(ctx, original.Path)
		if e != nil || se != nil || !bytes.Equal(expected, actual) || stat.Mode.Perm() != original.Mode.Perm() {
			begin("preservation")
			return fail()
		}
	}
	// Cron dependency hooks must retain all pre-existing user schedules.
	for _, original := range fresh.Files {
		if original.Path != "/opt/etc/crontab" && !strings.HasPrefix(original.Path, "/opt/etc/cron.d/") && !strings.HasPrefix(original.Path, "/opt/var/spool/cron/") && !strings.HasPrefix(original.Path, "/opt/etc/cron.1min/") {
			continue
		}
		if d.selection.Config.Watchdog && original.Path == "/opt/etc/cron.1min/router-watchdog" {
			continue
		}
		expected, _ := fresh.Config(original.Path)
		actual, e := t.Read(ctx, original.Path)
		if e != nil {
			begin("preservation")
			return fail()
		}
		if d.selection.Config.Watchdog && original.Path == "/opt/etc/crontab" {
			for _, line := range strings.Split(string(expected), "\n") {
				if strings.Contains(line, "/opt/bin/router-watchdog") {
					continue
				}
				if !strings.Contains("\n"+string(actual)+"\n", "\n"+line+"\n") {
					begin("preservation")
					return fail()
				}
			}
		} else if !bytes.Equal(expected, actual) {
			begin("preservation")
			return fail()
		}
	}
	r.Complete = true
	r.ReinspectRequired = false
	return r, nil
}
func command(ctx context.Context, t router.Transport, c string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	r, e := t.Run(bounded, c)
	if e != nil || r.ExitCode != 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("remote operation failed")
	}
	return r.Stdout, nil
}
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func writeChecked(ctx context.Context, t router.Transport, f payload) error {
	if !safeTarget(f.path) || f.mode&^fs.FileMode(0777) != 0 {
		return errors.New("unsafe payload")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.MkdirAll(ctx, path.Dir(f.path), 0700); err != nil {
		return err
	}
	for _, privateRoot := range []string{"/opt/.xkeen-installer-stage", "/opt/.xkeen-installer-packages"} {
		if strings.HasPrefix(f.path, privateRoot+"/") {
			e, err := t.Stat(ctx, privateRoot)
			if err != nil || !e.Mode.IsDir() || e.Mode.Perm() != 0700 {
				return errors.New("staging directory is not private")
			}
		}
	}
	if e, err := t.Stat(ctx, f.path); err == nil && !e.Mode.IsRegular() {
		return errors.New("unsafe destination")
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.New("destination unavailable")
	}
	if err := t.WriteAtomic(ctx, f.path, f.data, f.mode); err != nil {
		return err
	}
	b, err := t.Read(ctx, f.path)
	if err != nil {
		return err
	}
	e, err := t.Stat(ctx, f.path)
	if err != nil {
		return err
	}
	if sha256.Sum256(b) != sha256.Sum256(f.data) || e.Mode.Perm() != f.mode.Perm() {
		return errors.New("installed bytes or mode differ")
	}
	return nil
}

func hasVersion(out []byte, version string) bool {
	for _, token := range strings.Fields(string(out)) {
		if strings.TrimPrefix(token, "v") == strings.TrimPrefix(version, "v") {
			return true
		}
	}
	return false
}

func runtimeVersion(a catalog.Artifact) string {
	if a.Component == catalog.Yq && a.Version == "260527" {
		return "v4.53.2"
	}
	return a.Version
}

// Redirect before entering init: a successfully backgrounded daemon must not
// inherit SSH streams and keep Session.Run waiting after init returns. There is
// no extra '&' or detach wrapper; the foreground init exit status is preserved.
func serviceLaunch(fixedCommand string) string { return fixedCommand + " </dev/null >/dev/null 2>&1" }

// Entware's cron package uses /opt/sbin/cron, not BusyBox crond.
const cronPreflightCommand = `for name in cron crond; do for pid in $(pidof "$name" 2>/dev/null); do exe=$(readlink "/proc/$pid/exe") || exit 1; [ "$name" = cron ] && [ "$exe" = /opt/sbin/cron ] || exit 1; done; done`
const cronVerifyCommand = `test -x /opt/etc/init.d/S10cron && test -x /opt/sbin/cron || exit 1; count=0; for pid in $(pidof cron 2>/dev/null); do [ "$(readlink "/proc/$pid/exe")" = /opt/sbin/cron ] || exit 1; count=$((count+1)); done; [ "$count" -gt 0 ] || exit 1; for pid in $(pidof crond 2>/dev/null); do exit 1; done`
