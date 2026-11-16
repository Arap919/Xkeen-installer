package install

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/router"
)

// These scenarios use the real inspector, config preparation, planner and runner.
// Transport and verified payload loading remain fixtures; no router is contacted.
func TestFixtureCleanEntwareCoreMatrix(t *testing.T) {
	for _, core := range []catalog.Component{catalog.Xray, catalog.Mihomo} {
		t.Run(string(core), func(t *testing.T) {
			f := fixture()
			f.files = map[string][]byte{"/opt/lib/opkg/status": []byte("Package: opkg\nVersion: 1\nStatus: install user installed\n\n"), "/opt/etc/opkg.conf": []byte("src/gz entware https://bin.entware.net/aarch64-k3.10\n"), "/opt/bin/opkg": []byte("opkg")}
			f.active = ""
			s, err := router.Inspect(context.Background(), f)
			if err != nil || !s.Entware {
				t.Fatal("clean Entware inspection", err)
			}
			sel := Selection{Config: config.Selection{Cores: []catalog.Component{core}, ActiveCore: core}}
			input := config.LocalImport(core, []byte(validXray))
			target := config.XrayPath
			if core == catalog.Mihomo {
				input = config.ProviderImport("https://example.test/fixture")
				target = config.MihomoPath
			}
			proposal, err := config.Prepare(s, sel.Config, input)
			if err != nil {
				t.Fatal(err)
			}
			want, ok := proposal.File(target)
			if !ok {
				t.Fatal("missing prepared config")
			}
			p, err := BuildPlan(s, sel, proposal)
			if err != nil {
				t.Fatal(err)
			}
			r, err := run(context.Background(), confirm(t, p), f, nil, reviewedFixtureLoader)
			if err != nil || !r.Complete || !r.Backup.Verified() || f.active != string(core) {
				t.Fatalf("result=%+v active=%s err=%v", r, f.active, err)
			}
			if !bytes.Equal(f.files[target], want) {
				t.Fatal("reviewed config differs from installed bytes")
			}
			commands := strings.Join(f.commands, "\n")
			validation := "xray run -test"
			if core == catalog.Mihomo {
				validation = "mihomo -t"
			}
			if v, a := strings.Index(commands, validation), strings.Index(commands, "S05xkeen start on"); v < 0 || a < v {
				t.Fatal("native validation did not precede activation", commands)
			}
		})
	}
}

func TestFixtureCustomMihomoPreservesAnchorsListenersAndBackup(t *testing.T) {
	f := fixture()
	delete(f.files, config.XrayPath)
	f.active = "mihomo"
	f.files["/opt/etc/init.d/S05xkeen"] = bytes.Replace(f.files["/opt/etc/init.d/S05xkeen"], []byte("xray"), []byte("mihomo"), 1)
	raw := []byte("# custom configuration\nport: 7890\nproxy-providers:\n  source: {type: http, url: 'https://example.test/private'}\nproxy-groups:\n  - {name: PROXY, type: select, use: &sources [source]}\n  - {name: BENCHMARK, type: select, use: *sources}\nlisteners:\n  - {name: custom-http, type: http, listen: 127.0.0.1, port: 17891, proxy: PROXY}\nrules: [\"MATCH,PROXY\"]\n")
	f.files[config.MihomoPath] = raw
	f.modes[config.MihomoPath] = 0640
	s, err := router.Inspect(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Mihomo}}}
	proposal, err := config.Prepare(s, sel.Config, config.Import{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildPlan(s, sel, proposal)
	if err != nil {
		t.Fatal(err)
	}
	r, err := run(context.Background(), confirm(t, p), f, nil, fixtureLoader)
	if err != nil || !r.Complete || !r.Backup.Verified() || f.active != "mihomo" {
		t.Fatal(r, err)
	}
	for _, p := range []string{config.MihomoPath, r.Backup.Root + config.MihomoPath} {
		if !bytes.Equal(f.files[p], raw) || f.modes[p] != 0640 {
			t.Fatal("custom bytes or permissions lost", p)
		}
	}
}

func TestFixtureRepeatProviderCachePlanAndBackup(t *testing.T) {
	f := fixture()
	delete(f.files, config.XrayPath)
	f.active = "mihomo"
	f.files["/opt/etc/init.d/S05xkeen"] = bytes.Replace(f.files["/opt/etc/init.d/S05xkeen"], []byte("xray"), []byte("mihomo"), 1)
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Mihomo}, ActiveCore: catalog.Mihomo}}
	initial, err := config.Prepare(router.Snapshot{}, sel.Config, config.ProviderImport("https://example.invalid/sub"))
	if err != nil {
		t.Fatal(err)
	}
	main, _ := initial.File(config.MihomoPath)
	cachePath := "/opt/etc/mihomo/providers/subscription.yaml"
	cache := []byte("# existing cache\nproxies: [{name: node, type: ss, server: example.invalid, port: 443, cipher: aes-128-gcm, password: private}]\n")
	f.files[config.MihomoPath], f.files[cachePath] = main, cache
	f.modes[config.MihomoPath], f.modes[cachePath] = 0640, 0600
	s, err := router.Inspect(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := config.Prepare(s, sel.Config, config.Import{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildPlan(s, sel, proposal)
	if err != nil {
		t.Fatal(err)
	}
	report, err := run(context.Background(), confirm(t, p), f, nil, fixtureLoader)
	if err != nil || !report.Complete || !report.Backup.Verified() {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	for name, want := range map[string][]byte{config.MihomoPath: main, cachePath: cache} {
		for _, target := range []string{name, report.Backup.Root + name} {
			if !bytes.Equal(f.files[target], want) || (name == config.MihomoPath && f.modes[target] != 0640) || (name == cachePath && f.modes[target] != 0600) {
				t.Fatalf("bytes or mode changed: %s", target)
			}
		}
	}
}

type scenarioSpace struct {
	*fakeRouter
	available uint64
}

func (f *scenarioSpace) AvailableBytes(context.Context, string) (uint64, error) {
	return f.available, nil
}

func TestFixtureManualEntwareAndNoSpaceGates(t *testing.T) {
	for _, scenario := range []string{"missing-entware", "no-space", "space-lost-before-run"} {
		t.Run(scenario, func(t *testing.T) {
			f := &scenarioSpace{fakeRouter: fixture(), available: 1 << 30}
			if scenario == "missing-entware" {
				delete(f.files, "/opt/bin/opkg")
			}
			if scenario == "no-space" {
				f.available = 0
			}
			s, err := router.Inspect(context.Background(), f)
			if err != nil {
				t.Fatal(err)
			}
			sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}}}
			proposal, err := config.Prepare(s, sel.Config, config.Import{})
			if err != nil {
				t.Fatal(err)
			}
			p, err := BuildPlan(s, sel, proposal)
			if scenario == "space-lost-before-run" {
				if err != nil {
					t.Fatal(err)
				}
				f.available = 0
				r, runErr := run(context.Background(), confirm(t, p), f, nil, fixtureLoader)
				if runErr == nil || r.Complete || r.Backup.Verified() {
					t.Fatal("space loss accepted", r, runErr)
				}
			} else if err == nil {
				t.Fatal("unsafe plan accepted")
			} else if scenario == "missing-entware" && !strings.Contains(err.Error(), "ручную") {
				t.Fatal("manual fallback not explained", err)
			}
			if f.writes != 0 {
				t.Fatal("gate allowed writes")
			}
			for _, command := range f.commands {
				if (strings.Contains(command, "/opt/bin/opkg") && strings.Contains(command, " install ")) || strings.Contains(command, "S05xkeen stop") || strings.Contains(command, "start on") {
					t.Fatal("gate allowed package or service mutation", command)
				}
			}
		})
	}
}
