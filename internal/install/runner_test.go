package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"strings"
	"testing"

	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/router"
)

const validXray = `{"inbounds":[{"tag":"in","protocol":"socks","port":1080,"settings":{}}],"outbounds":[{"tag":"out","protocol":"freedom","settings":{}}]}`

type fakeRouter struct {
	files    map[string][]byte
	modes    map[string]fs.FileMode
	commands []string
	active   string
	packages string
	writes   int
	fail     string
	cancel   context.CancelFunc
}

func fixture() *fakeRouter {
	return &fakeRouter{files: map[string][]byte{"/opt/bin/opkg": []byte("opkg"), config.XrayPath: []byte(validXray), "/opt/etc/init.d/S05xkeen": []byte("#!/bin/sh\nname_client=\"xray\"\nproxy_start() { :; }\nproxy_stop() { :; }\ncase \"$1\" in esac\n"), "/opt/etc/xkeen/xkeen-ui.json": []byte("private-secret"), "/opt/etc/xkeen/watchdog-push.json": []byte("vapid-secret")}, modes: map[string]fs.FileMode{}, active: "xray", packages: "opkg - 1\n"}
}
func (f *fakeRouter) Run(ctx context.Context, c string) (router.Result, error) {
	if e := ctx.Err(); e != nil {
		return router.Result{}, e
	}
	f.commands = append(f.commands, c)
	switch c {
	case "printf 'XKEEN_SHELL_OK\\n'":
		return router.Result{Stdout: []byte("XKEEN_SHELL_OK\n")}, nil
	case "pidof crond":
		return router.Result{Stdout: []byte("123")}, nil
	case "uname -m":
		return router.Result{Stdout: []byte("aarch64")}, nil
	case "ps w":
		return router.Result{Stdout: []byte("PID USER COMMAND\n1 root /opt/sbin/" + f.active)}, nil
	case "/opt/bin/opkg list-installed":
		return router.Result{Stdout: []byte(f.packages)}, nil
	}
	if strings.Contains(c, f.fail) && f.fail != "" {
		return router.Result{Stderr: []byte("secret-provider-url")}, errors.New("password=secret")
	}
	if strings.HasPrefix(c, "/opt/bin/opkg install '") && strings.Contains(c, "router-watchdog_1.0.16-1_all.ipk") {
		f.packages += "router-watchdog - 1.0.16-1\n"
		f.files[config.WatchdogPath] = append(f.files[config.WatchdogPath], ' ')
	}
	if c == "/opt/etc/init.d/S05xkeen stop" {
		f.active = ""
	}
	if strings.HasPrefix(c, "/opt/etc/init.d/S05xkeen start on") {
		b := string(f.files["/opt/etc/init.d/S05xkeen"])
		f.active = "xray"
		if strings.Contains(b, `name_client="mihomo"`) {
			f.active = "mihomo"
		}
	}
	if strings.Contains(c, "yq --version") {
		return router.Result{Stdout: []byte("yq v4.54.1")}, nil
	}
	if strings.Contains(c, " version") {
		return router.Result{Stdout: []byte("Xray 26.10.31")}, nil
	}
	if strings.Contains(c, " -v") {
		return router.Result{Stdout: []byte("Mihomo v1.19.33")}, nil
	}
	if strings.Contains(c, " start on") && f.cancel != nil {
		f.cancel()
	}
	return router.Result{}, nil
}
func (f *fakeRouter) Read(_ context.Context, p string) ([]byte, error) {
	b, ok := f.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}
func (f *fakeRouter) Stat(_ context.Context, p string) (router.Entry, error) {
	if m, ok := f.modes[p]; ok && m.IsDir() {
		return router.Entry{Path: p, Mode: m}, nil
	}
	if b, ok := f.files[p]; ok {
		m := f.modes[p]
		if m == 0 {
			m = 0600
		}
		return router.Entry{Path: p, Size: int64(len(b)), Mode: m}, nil
	}
	for q := range f.files {
		if strings.HasPrefix(q, p+"/") {
			return router.Entry{Path: p, Mode: fs.ModeDir | 0700}, nil
		}
	}
	return router.Entry{}, fs.ErrNotExist
}
func (f *fakeRouter) ReadDir(ctx context.Context, p string) ([]router.Entry, error) {
	seen := map[string]bool{}
	var out []router.Entry
	for q := range f.files {
		if strings.HasPrefix(q, p+"/") {
			n := strings.Split(strings.TrimPrefix(q, p+"/"), "/")[0]
			if !seen[n] {
				seen[n] = true
				e, _ := f.Stat(ctx, path.Join(p, n))
				out = append(out, e)
			}
		}
	}
	return out, nil
}
func (f *fakeRouter) WriteAtomic(_ context.Context, p string, b []byte, m fs.FileMode) error {
	f.writes++
	f.files[p] = append([]byte(nil), b...)
	f.modes[p] = m
	if f.fail == p {
		return errors.New("disconnect password=secret")
	}
	return nil
}
func (f *fakeRouter) MkdirAll(_ context.Context, p string, m fs.FileMode) error {
	f.writes++
	for p != "/opt" && p != "/" {
		if _, ok := f.modes[p]; !ok {
			f.modes[p] = fs.ModeDir | m
		}
		p = path.Dir(p)
	}
	return nil
}
func (f *fakeRouter) AvailableBytes(context.Context, string) (uint64, error) { return 1 << 30, nil }
func planFor(t *testing.T, f *fakeRouter) Plan {
	t.Helper()
	s, e := router.Inspect(context.Background(), f)
	if e != nil {
		t.Fatal(e)
	}
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}}}
	if f.active == "" {
		sel.Config.ActiveCore = catalog.Xray
	}
	p, e := config.Prepare(s, sel.Config, config.Import{})
	if e != nil {
		t.Fatal(e)
	}
	plan, e := BuildPlan(s, sel, p)
	if e != nil {
		t.Fatal(e)
	}
	return plan
}
func confirm(t *testing.T, p Plan) Plan {
	t.Helper()
	q, e := ConfirmPlan(p, p.ID)
	if e != nil {
		t.Fatal(e)
	}
	return q
}
func fakeLoad(context.Context, []catalog.Artifact) ([]payload, error) {
	return []payload{{path: "/opt/sbin/xray", data: []byte("checked-binary"), mode: 0755, component: catalog.Xray}, {path: "/opt/sbin/xkeen", data: []byte("#!/bin/sh\n"), mode: 0755, component: catalog.XKeen}, {path: "/opt/sbin/.xkeen/02_install/07_install_register/04_register_init.sh", data: []byte("#!/bin/sh\nname_client=\"xray\"\n"), mode: 0755, component: catalog.XKeen}}, nil
}
func TestReviewAndProvenance(t *testing.T) {
	f := fixture()
	p := planFor(t, f)
	if _, e := run(context.Background(), p, f, nil, fakeLoad); !errors.Is(e, ErrUnconfirmed) {
		t.Fatal(e)
	}
	if f.writes != 0 {
		t.Fatal("unconfirmed mutation")
	}
	b, _ := json.Marshal(p)
	var forged Plan
	_ = json.Unmarshal(b, &forged)
	if _, e := ConfirmPlan(forged, forged.ID); e == nil {
		t.Fatal("serialized plan confirmed")
	}
	if _, e := ConfirmPlan(p, "other"); e == nil {
		t.Fatal("wrong review ID accepted")
	}
	if strings.Contains(string(b), "secret") {
		t.Fatal("plan leaked secret")
	}
}
func TestBackupInstallValidateActivateAndPreserve(t *testing.T) {
	f := fixture()
	p := confirm(t, planFor(t, f))
	var events []Event
	r, e := run(context.Background(), p, f, func(e Event) { events = append(events, e) }, fakeLoad)
	if e != nil {
		t.Fatal(e)
	}
	if !r.Backup.Verified() || !r.Complete {
		t.Fatalf("report %+v", r)
	}
	if string(f.files[config.XrayPath]) != validXray || string(f.files["/opt/etc/xkeen/watchdog-push.json"]) != "vapid-secret" {
		t.Fatal("settings overwritten")
	}
	joined := strings.Join(f.commands, "\n")
	if strings.Index(joined, "run -test") > strings.Index(joined, " start on") {
		t.Fatal(joined)
	}
	if len(events) == 0 {
		t.Fatal("no events")
	}
	if _, e := run(context.Background(), p, f, nil, fakeLoad); !errors.Is(e, ErrConsumed) {
		t.Fatal("plan reused", e)
	}
}
func TestStaleAndCancellationDoNotMutate(t *testing.T) {
	for _, kind := range []string{"config", "package", "active", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture()
			p := confirm(t, planFor(t, f))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "config":
				f.files[config.XrayPath] = []byte(validXray + " ")
			case "package":
				f.packages += "curl - 1\n"
			case "active":
				f.active = "mihomo"
			case "cancel":
				cancel()
			}
			_, e := run(ctx, p, f, nil, fakeLoad)
			if e == nil || f.writes != 0 {
				t.Fatalf("err=%v writes=%d", e, f.writes)
			}
		})
	}
}
func TestDisconnectAndRetryRequiresFreshPlan(t *testing.T) {
	f := fixture()
	p := confirm(t, planFor(t, f))
	f.fail = "/opt/sbin/xray"
	r, e := run(context.Background(), p, f, nil, fakeLoad)
	if e == nil || r.Complete || r.Uncertain == "" || !r.Backup.Verified() {
		t.Fatalf("%+v %v", r, e)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "password") || strings.Contains(e.Error(), "secret") {
		t.Fatal("secret leaked")
	}
	if _, e = run(context.Background(), p, f, nil, fakeLoad); !errors.Is(e, ErrConsumed) {
		t.Fatal(e)
	}
	f.fail = ""
	q := confirm(t, planFor(t, f))
	if _, e = run(context.Background(), q, f, nil, fakeLoad); e != nil {
		t.Fatal(e)
	}
}
func TestNativeValidationFailureNeverActivates(t *testing.T) {
	f := fixture()
	p := confirm(t, planFor(t, f))
	f.fail = "run -test"
	r, e := run(context.Background(), p, f, nil, fakeLoad)
	if e == nil || r.Complete {
		t.Fatal("native failure accepted")
	}
	for _, c := range f.commands {
		if strings.Contains(c, " start on") {
			t.Fatal("activated after native failure")
		}
	}
}

func TestCleanBothWithInactiveXrayAndActiveMihomo(t *testing.T) {
	f := fixture()
	delete(f.files, config.XrayPath)
	delete(f.files, "/opt/etc/init.d/S05xkeen")
	f.active = ""
	s, e := router.Inspect(context.Background(), f)
	if e != nil {
		t.Fatal(e)
	}
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Mihomo, catalog.Xray}, ActiveCore: catalog.Mihomo}, UI: true}
	proposal, e := config.Prepare(s, sel.Config, config.ProviderImport("https://example.test/private-subscription"))
	if e != nil {
		t.Fatal(e)
	}
	p, e := BuildPlan(s, sel, proposal)
	if e != nil {
		t.Fatal(e)
	}
	load := func(context.Context, []catalog.Artifact) ([]payload, error) {
		return []payload{
			{path: "/opt/sbin/xray", data: []byte("checked-xray"), mode: 0755, component: catalog.Xray},
			{path: "/opt/sbin/xkeen", data: []byte("#!/bin/sh\n"), mode: 0755, component: catalog.XKeen},
			{path: "/opt/sbin/yq", data: []byte("checked-yq"), mode: 0755, component: catalog.Yq},
			{path: "/opt/sbin/mihomo", data: []byte("checked-mihomo"), mode: 0755, component: catalog.Mihomo},
			{path: "/opt/sbin/.xkeen/02_install/07_install_register/04_register_init.sh", data: []byte("#!/bin/sh\nname_client=\"xray\"\n"), mode: 0755, component: catalog.XKeen},
			{path: "/opt/sbin/xkeen-ui", data: []byte("checked-ui"), mode: 0755, component: catalog.UI}}, nil
	}
	r, e := run(context.Background(), confirm(t, p), f, nil, load)
	if e != nil {
		t.Fatal(e)
	}
	if !r.Complete || len(r.Pending) != 2 || f.active != "mihomo" {
		t.Fatalf("%+v active=%s", r, f.active)
	}
	if _, ok := f.files[config.XrayPath]; !ok {
		t.Fatal("inactive Xray not installed")
	}
	for _, c := range f.commands {
		if strings.Contains(c, "xray run -test") || strings.Contains(c, "-i auto") || strings.Contains(c, "opkg upgrade") {
			t.Fatal("unexpected command", c)
		}
	}
	if !strings.Contains(string(f.files["/opt/etc/init.d/S99xkeen-ui"]), "ENABLED=no") {
		t.Fatal("new UI activated prematurely")
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "private-subscription") {
		t.Fatal("subscription leaked")
	}
}
func TestCleanXrayAndCancellationAfterInstall(t *testing.T) {
	f := fixture()
	delete(f.files, "/opt/etc/init.d/S05xkeen")
	f.active = ""
	p := confirm(t, planFor(t, f))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	load := func(ctx context.Context, a []catalog.Artifact) ([]payload, error) {
		out, _ := fakeLoad(ctx, a)
		return append(out, payload{path: "/opt/sbin/.xkeen/02_install/07_install_register/04_register_init.sh", data: []byte("#!/bin/sh\nname_client=\"xray\"\n"), mode: 0755, component: catalog.XKeen}), nil
	}
	r, e := run(ctx, p, f, func(e Event) {
		if e.Step == "install" && e.Status == "completed" {
			cancel()
		}
	}, load)
	if !errors.Is(e, context.Canceled) || r.Complete || !r.Backup.Verified() {
		t.Fatalf("%+v %v", r, e)
	}
	if string(f.files["/opt/sbin/xray"]) != "checked-binary" {
		t.Fatal("completed change lost")
	}
	for _, c := range f.commands {
		if strings.Contains(c, " start on") {
			t.Fatal("started after cancel")
		}
	}
}
func TestPlanBlocksConflictsAndUnsafeCron(t *testing.T) {
	f := fixture()
	s, _ := router.Inspect(context.Background(), f)
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}, Watchdog: true}}
	p, _ := config.Prepare(s, sel.Config, config.Import{})
	p.Conflicts = nil
	p.ActivationReady = true
	if _, e := BuildPlan(s, sel, p); e == nil {
		t.Fatal("watchdog enabled for Xray")
	}
	delete(f.files, "/opt/bin/opkg")
	s, _ = router.Inspect(context.Background(), f)
	if _, e := BuildPlan(s, sel, p); e == nil {
		t.Fatal("Entware manual gate bypassed")
	}
}
func TestPublicPlanTamperingAndSnapshotFreshness(t *testing.T) {
	f := fixture()
	p := confirm(t, planFor(t, f))
	p.Dependencies[0] = "evil; secret"
	if _, e := run(context.Background(), p, f, nil, fakeLoad); !errors.Is(e, ErrUnconfirmed) || f.writes != 0 {
		t.Fatal(e)
	}
	f = fixture()
	p = confirm(t, planFor(t, f))
	load := func(ctx context.Context, a []catalog.Artifact) ([]payload, error) {
		f.files[config.XrayPath] = []byte(validXray + " ")
		return fakeLoad(ctx, a)
	}
	if _, e := run(context.Background(), p, f, nil, load); !errors.Is(e, ErrStale) || f.writes != 0 {
		t.Fatal("did not reinspect after download", e)
	}
}

func TestDownloadFailureAndBackupFailureStopMutations(t *testing.T) {
	f := fixture()
	p := confirm(t, planFor(t, f))
	load := func(context.Context, []catalog.Artifact) ([]payload, error) { return nil, errors.New("private-token") }
	r, e := run(context.Background(), p, f, nil, load)
	if e == nil || f.writes != 0 || r.Complete || strings.Contains(e.Error(), "private-token") {
		t.Fatal(r, e)
	}
	f = fixture()
	p = confirm(t, planFor(t, f))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, e = run(ctx, p, f, func(e Event) {
		if e.Step == "backup" && e.Status == "running" {
			cancel()
		}
	}, fakeLoad)
	if e == nil || r.Complete {
		t.Fatal(r, e)
	}
	for _, c := range f.commands {
		if strings.Contains(c, "opkg install") || strings.Contains(c, " stop") {
			t.Fatal("mutation after failed backup")
		}
	}
}
func TestPublicReadinessCannotBypassPrivateConfig(t *testing.T) {
	f := fixture()
	delete(f.files, config.XrayPath)
	delete(f.files, "/opt/etc/init.d/S05xkeen")
	f.active = ""
	s, _ := router.Inspect(context.Background(), f)
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}, ActiveCore: catalog.Xray}}
	proposal, _ := config.Prepare(s, sel.Config, config.Import{})
	proposal.ActivationReady = true
	proposal.Conflicts = nil
	if _, e := BuildPlan(s, sel, proposal); e == nil {
		t.Fatal("unconfigured active base accepted")
	}
}
func TestExactVersionToken(t *testing.T) {
	if hasVersion([]byte("Xray 26.10.310"), "v26.10.31") {
		t.Fatal("prefix version accepted")
	}
	if !hasVersion([]byte("Mihomo v1.19.33 linux arm64"), "v1.19.33") {
		t.Fatal("expected version rejected")
	}
}

func fixtureLoader(_ context.Context, artifacts []catalog.Artifact) ([]payload, error) {
	var out []payload
	for _, a := range artifacts {
		target := map[catalog.Component]string{catalog.XKeen: "/opt/sbin/xkeen", catalog.Mihomo: "/opt/sbin/mihomo", catalog.Xray: "/opt/sbin/xray", catalog.Yq: "/opt/sbin/yq", catalog.UI: "/opt/sbin/xkeen-ui", catalog.Watchdog: "/opt/.xkeen-installer-packages/router-watchdog_1.0.16-1_all.ipk"}[a.Component]
		mode := fs.FileMode(0755)
		if a.Component == catalog.Watchdog {
			mode = 0600
		}
		out = append(out, payload{path: target, data: []byte("verified-fixture-" + string(a.Component)), mode: mode, component: a.Component})
		if a.Component == catalog.XKeen {
			out = append(out, payload{path: "/opt/sbin/.xkeen/02_install/07_install_register/04_register_init.sh", data: []byte("#!/bin/sh\nname_client=\"xray\"\n"), mode: 0755, component: a.Component})
		}
	}
	return out, nil
}
func TestWatchdogIPKAfterNativeActivationAndPreservesExactConfig(t *testing.T) {
	f := fixture()
	delete(f.files, config.XrayPath)
	f.active = "mihomo"
	f.files["/opt/etc/init.d/S05xkeen"] = bytes.Replace(f.files["/opt/etc/init.d/S05xkeen"], []byte("xray"), []byte("mihomo"), 1)
	f.files["/opt/etc/init.d/S10cron"] = []byte("cron")
	f.modes["/opt/etc/init.d/S10cron"] = 0755
	s, _ := router.Inspect(context.Background(), f)
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Mihomo}, Watchdog: true}}
	proposal, e := config.Prepare(s, sel.Config, config.ProviderImport("https://example.test/private"))
	if e != nil {
		t.Fatal(e)
	}
	p, e := BuildPlan(s, sel, proposal)
	if e != nil {
		t.Fatal(e)
	}
	want, _ := proposal.File(config.WatchdogPath)
	r, e := run(context.Background(), confirm(t, p), f, nil, fixtureLoader)
	if e != nil {
		t.Fatal(e)
	}
	if !r.Complete || !bytes.Equal(f.files[config.WatchdogPath], want) {
		t.Fatal("package hooks changed reviewed config")
	}
	joined := strings.Join(f.commands, "\n")
	native := strings.Index(joined, "mihomo -t")
	start := strings.Index(joined, "S05xkeen start on")
	ipk := strings.Index(joined, "router-watchdog_1.0.16-1_all.ipk")
	if native < 0 || start < native || ipk < start {
		t.Fatal(joined)
	}
}
func TestExistingUISettingsAndTLSArePreserved(t *testing.T) {
	f := fixture()
	init := []byte("#!/bin/sh\nPROCS=xkeen-ui\nARGS=\"-p 1000 --tls-cert /opt/etc/nginx/ssl/server.crt --tls-key /opt/etc/nginx/ssl/server.key\"\n. /opt/etc/init.d/rc.func\n")
	f.files["/opt/etc/init.d/S99xkeen-ui"] = init
	f.files["/opt/etc/nginx/ssl/server.key"] = []byte("tls-secret")
	f.files["/opt/etc/nginx/ssl/server.crt"] = []byte("certificate")
	s, _ := router.Inspect(context.Background(), f)
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}}, UI: true}
	proposal, _ := config.Prepare(s, sel.Config, config.Import{})
	p, e := BuildPlan(s, sel, proposal)
	if e != nil {
		t.Fatal(e)
	}
	r, e := run(context.Background(), confirm(t, p), f, nil, fixtureLoader)
	if e != nil {
		t.Fatal(e)
	}
	if !r.Complete || !bytes.Equal(f.files["/opt/etc/init.d/S99xkeen-ui"], init) || string(f.files["/opt/etc/nginx/ssl/server.key"]) != "tls-secret" {
		t.Fatal("existing UI state altered")
	}
	for _, c := range f.commands {
		if strings.Contains(c, "setup.sh") || strings.Contains(c, "uninstall") {
			t.Fatal(c)
		}
	}
}
func TestCancellationAfterStartIsUncertainWithoutRollbackClaim(t *testing.T) {
	f := fixture()
	p := confirm(t, planFor(t, f))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.cancel = cancel
	r, e := run(ctx, p, f, nil, fakeLoad)
	if !errors.Is(e, context.Canceled) || r.Uncertain != "activate" || r.Complete || !r.ReinspectRequired {
		t.Fatal(r, e)
	}
	if f.active != "xray" {
		t.Fatal("did not model applied remote mutation")
	}
}

func TestExistingWatchdogScheduleBlocksXrayBeforeMutation(t *testing.T) {
	f := fixture()
	f.files["/opt/etc/crontab"] = []byte("* * * * * root /opt/bin/router-watchdog\n")
	s, _ := router.Inspect(context.Background(), f)
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}}}
	proposal, _ := config.Prepare(s, sel.Config, config.Import{})
	if _, e := BuildPlan(s, sel, proposal); e == nil || f.writes != 0 {
		t.Fatal("unsafe existing watchdog schedule accepted")
	}
}

func TestPartialFileWritesReportVerifiedAndUncertainPaths(t *testing.T) {
	f := fixture()
	p := confirm(t, planFor(t, f))
	f.fail = "/opt/sbin/xkeen"
	r, e := run(context.Background(), p, f, nil, fakeLoad)
	if e == nil || r.Uncertain != "install" || r.UncertainPath != "/opt/sbin/xkeen" {
		t.Fatal(r, e)
	}
	if len(r.Applied) != 1 || r.Applied[0] != "/opt/sbin/xray" {
		t.Fatal("known installed file omitted", r.Applied)
	}
}
