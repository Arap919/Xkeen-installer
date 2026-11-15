package config

import (
	"context"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"gopkg.in/yaml.v3"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEmbeddedMihomoIsUserBase(t *testing.T) {
	b, e := templates.ReadFile("templates/mihomo.yaml")
	if e != nil {
		t.Fatal(e)
	}
	m, e := mihomoDocument(b)
	if e != nil {
		t.Fatal(e)
	}
	for k, want := range map[string]int{"port": 7890, "socks-port": 7891, "mixed-port": 1080, "redir-port": 1182, "tproxy-port": 1181} {
		if m[k] != want {
			t.Errorf("%s: got %v", k, m[k])
		}
	}
	for _, name := range []string{"Proxy", "Global", "Russia", "AI", "Google", "GitHub", "Microsoft", "Apple", "Telegram", "Discord", "YouTube", "Steam", "Media", "Social", "Speedtest", "IP Check", "Other", "Adult", "Ads", "BENCHMARK"} {
		if group(m, name) == nil {
			t.Errorf("missing user group %s", name)
		}
	}
	providers, _ := m["proxy-providers"].(map[string]any)
	if len(providers) != 1 || providers["VPNProvider"] == nil || strings.Contains(string(b), "BlancVPN") || strings.Contains(string(b), "PaperVPN") {
		t.Fatal("embedded base must contain only VPNProvider")
	}
	provider := providers["VPNProvider"].(map[string]any)
	wantProvider := map[string]any{
		"type": "http", "url": "YOUR_URL", "interval": 43200,
		"health-check": map[string]any{"enable": true, "url": "https://www.gstatic.com/generate_204", "interval": 300, "expected-status": 204},
		"header":       map[string]any{"User-Agent": []any{"ClashMeta/1.19.24; mihomo/1.19.24"}, "x-hwid": []any{"322ABB229131"}},
		"override":     map[string]any{"udp": true, "tfo": true},
	}
	if !reflect.DeepEqual(provider, wantProvider) {
		t.Fatal("embedded VPNProvider settings differ from the requested block")
	}
	for _, name := range []string{"Proxy", "BENCHMARK"} {
		if !reflect.DeepEqual(group(m, name)["use"], []any{"VPNProvider"}) {
			t.Fatalf("%s must use VPNProvider", name)
		}
	}
	dns, _ := m["dns"].(map[string]any)
	if dns["enhanced-mode"] != "fake-ip" || dns["listen"] != "0.0.0.0:7874" {
		t.Fatal("user DNS missing")
	}
	rules, ok := stringList(m["rules"])
	if !ok || len(rules) < 65 || rules[len(rules)-1] != "MATCH,Other" {
		t.Fatal("user routing missing")
	}
	for _, r := range []string{"DOMAIN-SUFFIX,myteamspeak.ru,Global", "GEOSITE,category-ads-all,Ads", "RULE-SET,discord,Discord", "GEOIP,RU,Russia,no-resolve", "GEOSITE,category-speedtest,Global", "GEOIP,LAN,DIRECT,no-resolve"} {
		found := false
		for _, v := range rules {
			found = found || v == r
		}
		if !found {
			t.Errorf("missing user rule %s", r)
		}
	}
}

func TestUserMihomoSingleSubscriptionAndWatchdog(t *testing.T) {
	p, e := Prepare(snapshot(t, "", nil), Selection{Cores: []catalog.Component{catalog.Mihomo}, ActiveCore: catalog.Mihomo, Watchdog: true}, ProviderImport("https://example.invalid/private-subscription"))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := p.File(MihomoPath)
	if strings.Contains(string(b), "YOUR_URL") {
		t.Fatal("unconfigured provider in working config")
	}
	m, e := mihomoDocument(b)
	if e != nil {
		t.Fatal(e)
	}
	if !p.WatchdogEnabled || len(p.Conflicts) != 0 {
		t.Fatal("generated user base incompatible with watchdog")
	}
	if group(m, "Proxy") == nil || group(m, "AI") == nil {
		t.Fatal("generator still uses old template")
	}
	c, s, target, ok := watchdogContract(m)
	if !ok || c != "http://127.0.0.1:9090" || s == "" || target != "Proxy" {
		t.Fatal("wrong watchdog contract")
	}
	providers := m["proxy-providers"].(map[string]any)
	if len(providers) != 1 || providers["VPNProvider"] == nil {
		t.Fatal("single subscription must not be sent to two provider endpoints")
	}
	if !p.ActivationReady {
		t.Fatal("configured template not ready")
	}
}

// Opt-in native validation uses only a public fixture URL and local geodata.
func TestNativeUserMihomoBase(t *testing.T) {
	binary := os.Getenv("XKEEN_TEST_MIHOMO")
	assets := os.Getenv("XKEEN_TEST_GEODATA")
	if binary == "" || assets == "" {
		t.Skip("set native Mihomo binary and local geodata directory")
	}
	dir := t.TempDir()
	for target, source := range map[string]string{"GeoIP.dat": "geoip.dat", "GeoSite.dat": "geosite.dat"} {
		b, e := os.ReadFile(filepath.Join(assets, source))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, target), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	b, e := newMihomo("https://example.invalid/public-test-subscription#Моя подписка")
	if e != nil {
		t.Fatal(e)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if e = os.WriteFile(cfg, b, 0600); e != nil {
		t.Fatal(e)
	}
	out, e := exec.Command(binary, "-t", "-d", dir, "-f", cfg).CombinedOutput()
	if e != nil {
		t.Fatalf("native configuration validation: %v\n%s", e, out)
	}
	t.Log(string(out))
}

func TestUserBaseWatchdogHintUsesExistingProxyName(t *testing.T) {
	m, e := mihomoDocument(validMihomo(t))
	if e != nil {
		t.Fatal(e)
	}
	group(m, "BENCHMARK")["filter"] = "one-node"
	b, e := yaml.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	p, e := Prepare(snapshot(t, "mihomo", map[string][]byte{MihomoPath: b}), Selection{Cores: []catalog.Component{catalog.Mihomo}, Watchdog: true}, Import{})
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Conflicts) == 0 {
		t.Fatal("missing conflict")
	}
	hint := p.Conflicts[0].NecessaryAddition
	if !strings.Contains(hint, "name: Proxy") || strings.Contains(hint, "name: PROXY") {
		t.Fatal("hint creates ambiguous target group")
	}
}

func TestMihomoSubscriptionFragments(t *testing.T) {
	for _, label := range []string{"label", "Моя подписка"} {
		t.Run(label, func(t *testing.T) {
			urls := []string{"https://example.invalid/first", "https://example.invalid/second#" + label}
			input, err := ResolveSubscriptions(context.Background(), urls, nil)
			if err != nil {
				t.Fatal(err)
			}
			p, err := Prepare(snapshot(t, "", nil), Selection{Cores: []catalog.Component{catalog.Mihomo}, ActiveCore: catalog.Mihomo, Watchdog: true}, input)
			if err != nil {
				t.Fatal(err)
			}
			if !p.ActivationReady || !p.WatchdogEnabled || len(p.Conflicts) != 0 {
				t.Fatal("fragment subscription blocks activation or watchdog")
			}
			b, ok := p.File(MihomoPath)
			if !ok {
				t.Fatal("missing Mihomo configuration")
			}
			m, err := mihomoDocument(b)
			if err != nil {
				t.Fatal(err)
			}
			providers := m["proxy-providers"].(map[string]any)
			if len(providers) != 2 {
				t.Fatal("wrong provider count")
			}
			for i, name := range []string{"VPNProvider", "VPNProvider1"} {
				provider := providers[name].(map[string]any)
				if provider["url"] != urls[i] {
					t.Fatalf("%s: URL changed", name)
				}
			}
			for _, name := range []string{"Proxy", "BENCHMARK"} {
				if !reflect.DeepEqual(group(m, name)["use"], []any{"VPNProvider", "VPNProvider1"}) {
					t.Fatalf("%s: wrong provider membership", name)
				}
			}
			controller, secret, target, valid := watchdogContract(m)
			if !valid || controller != "http://127.0.0.1:9090" || secret == "" || target != "Proxy" {
				t.Fatal("invalid watchdog contract")
			}
		})
	}
}
