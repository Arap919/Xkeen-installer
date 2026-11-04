package config

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"testing"

	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/router"
)

type fixtureTransport struct {
	files  map[string][]byte
	active string
}

func (f fixtureTransport) Run(_ context.Context, c string) (router.Result, error) {
	switch c {
	case "printf 'XKEEN_SHELL_OK\\n'":
		return router.Result{Stdout: []byte("XKEEN_SHELL_OK\n")}, nil
	case "uname -m":
		return router.Result{Stdout: []byte("aarch64")}, nil
	case "ps w":
		return router.Result{Stdout: []byte("PID USER COMMAND\n1 root /opt/bin/" + f.active)}, nil
	}
	return router.Result{}, fmt.Errorf("unexpected probe")
}
func (f fixtureTransport) Read(_ context.Context, p string) ([]byte, error) { return f.files[p], nil }
func (f fixtureTransport) Stat(_ context.Context, p string) (router.Entry, error) {
	if b, ok := f.files[p]; ok {
		return router.Entry{Path: p, Mode: 0600, Size: int64(len(b))}, nil
	}
	for q := range f.files {
		if strings.HasPrefix(q, p+"/") {
			return router.Entry{Path: p, Mode: fs.ModeDir | 0700}, nil
		}
	}
	return router.Entry{}, fs.ErrNotExist
}
func (f fixtureTransport) ReadDir(ctx context.Context, p string) ([]router.Entry, error) {
	var out []router.Entry
	seen := map[string]bool{}
	for q := range f.files {
		if strings.HasPrefix(q, p+"/") {
			v := path.Join(p, strings.Split(strings.TrimPrefix(q, p+"/"), "/")[0])
			if !seen[v] {
				e, _ := f.Stat(ctx, v)
				out = append(out, e)
				seen[v] = true
			}
		}
	}
	return out, nil
}
func (f fixtureTransport) AvailableBytes(context.Context, string) (uint64, error) {
	return 1 << 30, nil
}
func (f fixtureTransport) WriteAtomic(context.Context, string, []byte, fs.FileMode) error {
	panic("unexpected write")
}
func (f fixtureTransport) MkdirAll(context.Context, string, fs.FileMode) error {
	panic("unexpected write")
}
func snapshot(t *testing.T, active string, files map[string][]byte) router.Snapshot {
	t.Helper()
	s, e := router.Inspect(context.Background(), fixtureTransport{files, active})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func both() Selection {
	return Selection{Cores: []catalog.Component{catalog.Mihomo, catalog.Xray}, Watchdog: true}
}
func TestNewProviderBackedConfiguration(t *testing.T) {
	s := Selection{Cores: []catalog.Component{catalog.Mihomo}, Watchdog: true, ActiveCore: catalog.Mihomo}
	p, e := Prepare(snapshot(t, "", nil), s, ProviderImport("https://example.invalid/sub?token=TOPSECRET"))
	if e != nil {
		t.Fatal(e)
	}
	if !p.WatchdogEnabled || p.ActiveCore != catalog.Mihomo || len(p.Conflicts) != 0 {
		t.Fatalf("%+v", p)
	}
	b, _ := p.File(MihomoPath)
	for _, v := range []string{"17890", "BENCHMARK", "proxy-providers:", "TOPSECRET"} {
		if !strings.Contains(string(b), v) {
			t.Fatalf("missing %s", v)
		}
	}
	w, _ := p.File(WatchdogPath)
	var m map[string]any
	if json.Unmarshal(w, &m) != nil || m["target_group"] != "PROXY" || m["secret"] == "" {
		t.Fatal("incompatible watchdog")
	}
	for _, v := range []string{fmt.Sprintf("%+v", p), fmt.Sprintf("%#v", p), string(mustJSON(t, p))} {
		if strings.Contains(v, "TOPSECRET") || strings.Contains(v, m["secret"].(string)) {
			t.Fatal("proposal leaks secret")
		}
	}
	b[0] = '!'
	again, _ := p.File(MihomoPath)
	if again[0] == '!' {
		t.Fatal("mutable proposal")
	}
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestExistingFilesPreservedAndActiveCoreRetained(t *testing.T) {
	for _, active := range []string{"xray", "mihomo"} {
		t.Run(active, func(t *testing.T) {
			raw := []byte("# custom anchor\nproxy-providers: {}\nproxy-groups: &groups []\nlisteners: []\n")
			x := []byte("{ \"outbounds\": [{\"protocol\":\"freedom\"}] }\n")
			p, e := Prepare(snapshot(t, active, map[string][]byte{MihomoPath: raw, XrayPath: x}), both(), Import{})
			if e != nil {
				t.Fatal(e)
			}
			a, _ := p.File(MihomoPath)
			b, _ := p.File(XrayPath)
			if string(a) != string(raw) || string(b) != string(x) || string(p.ActiveCore) != active || p.WatchdogEnabled {
				t.Fatalf("preservation failed: %+v", p)
			}
			if len(p.Conflicts) == 0 {
				t.Fatal("missing manual additions")
			}
			if p.Conflicts[0].NecessaryAddition == "" {
				t.Fatal("missing exact addition")
			}
		})
	}
}
func TestUnknownActiveNeverSilentlySwitches(t *testing.T) {
	p, e := Prepare(snapshot(t, "", nil), both(), Import{})
	if e != nil {
		t.Fatal(e)
	}
	if p.ActiveCore != "" || p.WatchdogEnabled || len(p.Conflicts) == 0 {
		t.Fatal(p)
	}
}
func TestXrayBaseRequiresConnection(t *testing.T) {
	p, e := Prepare(snapshot(t, "", nil), Selection{Cores: []catalog.Component{catalog.Xray}, ActiveCore: catalog.Xray}, Import{})
	if e != nil {
		t.Fatal(e)
	}
	if p.ActivationReady || p.WatchdogEnabled {
		t.Fatal("base activated without connection")
	}
	b, _ := p.File(XrayPath)
	if !json.Valid(b) || !strings.Contains(string(b), "dokodemo-door") {
		t.Fatal("missing transparent base")
	}
}
func TestImportBoundariesAndSafeErrors(t *testing.T) {
	for _, in := range []Import{LocalImport(catalog.Mihomo, []byte("bad: [ TOPSECRET")), LocalImport(catalog.Xray, []byte("{TOPSECRET")), LocalImport(catalog.Mihomo, make([]byte, MaxImportBytes+1)), ProviderImport(" "), ProviderImport("file:///TOPSECRET"), ProviderImport("https://user:TOPSECRET@example.invalid")} {
		_, e := Prepare(snapshot(t, "", nil), Selection{Cores: []catalog.Component{catalog.Mihomo}, ActiveCore: catalog.Mihomo}, in)
		if e == nil || strings.Contains(e.Error(), "TOPSECRET") {
			t.Fatalf("unsafe error: %v", e)
		}
	}
}
func TestEmptyProviderAndConflictingPortBlockWatchdog(t *testing.T) {
	for _, raw := range []string{"proxy-providers: {}\nproxy-groups: []\n", "port: 17890\nproxy-providers: {}\nproxy-groups: [{name: CUSTOM, type: select, proxies: [DIRECT]}]\nlisteners: [{name: custom, type: http, port: 17890}]\n"} {
		p, e := Prepare(snapshot(t, "mihomo", map[string][]byte{MihomoPath: []byte(raw)}), Selection{Cores: []catalog.Component{catalog.Mihomo}, Watchdog: true}, Import{})
		if e != nil {
			t.Fatal(e)
		}
		if p.WatchdogEnabled || len(p.Conflicts) == 0 {
			t.Fatal("unsafe watchdog")
		}
		b, _ := p.File(MihomoPath)
		if string(b) != raw {
			t.Fatal("rewritten custom config")
		}
	}
}

func TestCompatibleAnchorsEnableWatchdogWithoutRewriting(t *testing.T) {
	raw := []byte("external-controller: 127.0.0.1:9090\nsecret: PRIVATE_API_SECRET\nproxy-providers:\n  source: {type: http, url: 'https://example.invalid/PRIVATE_URL'}\nproxy-groups:\n  - {name: PROXY, type: select, use: &sources [source]}\n  - {name: BENCHMARK, type: select, use: *sources}\nlisteners:\n  - {name: benchmark-in, type: http, listen: 127.0.0.1, port: 17890, proxy: BENCHMARK, users: []}\n")
	p, e := Prepare(snapshot(t, "mihomo", map[string][]byte{MihomoPath: raw}), Selection{Cores: []catalog.Component{catalog.Mihomo}, Watchdog: true}, Import{})
	if e != nil || !p.WatchdogEnabled {
		t.Fatalf("contract failed: %v %+v", e, p)
	}
	b, _ := p.File(MihomoPath)
	if string(b) != string(raw) {
		t.Fatal("anchors rewritten")
	}
	for _, v := range []string{fmt.Sprintf("%v", p), fmt.Sprintf("%+v", ProviderImport("PRIVATE_URL")), string(mustJSON(t, LocalImport(catalog.Mihomo, raw)))} {
		if strings.Contains(v, "PRIVATE_") {
			t.Fatal("input/proposal leak")
		}
	}
}
func TestEmptyProviderImportIsAnError(t *testing.T) {
	_, e := Prepare(snapshot(t, "", nil), Selection{Cores: []catalog.Component{catalog.Mihomo}, ActiveCore: catalog.Mihomo}, ProviderImport(""))
	if e == nil {
		t.Fatal("empty provider import accepted")
	}
}
func TestWatchdogNotEnabledWithAuthenticatedBenchmark(t *testing.T) {
	p, e := Prepare(snapshot(t, "", nil), Selection{Cores: []catalog.Component{catalog.Mihomo}, ActiveCore: catalog.Mihomo}, ProviderImport("https://example.invalid/sub"))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := p.File(MihomoPath)
	raw = []byte(strings.Replace(string(raw), "users: []", "users: [{username: private, password: private}]", 1))
	q, e := Prepare(snapshot(t, "mihomo", map[string][]byte{MihomoPath: raw}), Selection{Cores: []catalog.Component{catalog.Mihomo}, Watchdog: true}, Import{})
	if e != nil || q.WatchdogEnabled {
		t.Fatal("authenticated benchmark accepted")
	}
}

func TestMalformedExistingWatchdogReturnsConflict(t *testing.T) {
	p, e := Prepare(snapshot(t, "", nil), Selection{Cores: []catalog.Component{catalog.Mihomo}, ActiveCore: catalog.Mihomo}, ProviderImport("https://example.invalid/sub"))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := p.File(MihomoPath)
	q, e := Prepare(snapshot(t, "mihomo", map[string][]byte{MihomoPath: raw, WatchdogPath: []byte(`{"controller":{},"secret":[]}`)}), Selection{Cores: []catalog.Component{catalog.Mihomo}, Watchdog: true}, Import{})
	if e != nil || q.WatchdogEnabled || len(q.Conflicts) == 0 {
		t.Fatal("invalid watchdog accepted")
	}
}
func TestEmptyLocalImportRejected(t *testing.T) {
	_, e := Prepare(snapshot(t, "", nil), Selection{Cores: []catalog.Component{catalog.Mihomo}, ActiveCore: catalog.Mihomo}, LocalImport(catalog.Mihomo, nil))
	if e == nil {
		t.Fatal("empty local import accepted")
	}
}
