package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Arap919/xkeen-installer/internal/catalog"
)

func TestInsufficientCoreStructureBlocksActivation(t *testing.T) {
	cases := []struct {
		core catalog.Component
		data string
	}{
		{catalog.Xray, `{"log":{}}`},
		{catalog.Xray, `{"inbounds":[{"protocol":"dokodemo-door","port":50080}],"outbounds":[{"protocol":"not-a-protocol"}]}`},
		{catalog.Xray, `{"inbounds":"wrong","outbounds":[{"protocol":"freedom"}]}`},
		{catalog.Mihomo, "mode: rule\n"},
		{catalog.Mihomo, "mode: rule\nport: bad\nrules: [MATCH,DIRECT]\n"},
		{catalog.Mihomo, "mode: rule\nport: 7890\nrules: ['MATCH,MISSING']\n"},
		{catalog.Mihomo, "mode: rule\nport: 7890\nproxy-groups: [{name: CUSTOM, type: select, proxies: [MISSING]}]\nrules: ['MATCH,CUSTOM']\n"},
	}
	for _, tc := range cases {
		t.Run(string(tc.core)+tc.data, func(t *testing.T) {
			selection := Selection{Cores: []catalog.Component{tc.core}, ActiveCore: tc.core}
			for _, existing := range []bool{false, true} {
				var files map[string][]byte
				input := LocalImport(tc.core, []byte(tc.data))
				pname := MihomoPath
				if tc.core == catalog.Xray {
					pname = XrayPath
				}
				if existing {
					files = map[string][]byte{pname: []byte(tc.data)}
					input = Import{}
				}
				p, e := Prepare(snapshot(t, string(tc.core), files), selection, input)
				if e != nil {
					t.Fatal(e)
				}
				if p.ActivationReady || len(p.Conflicts) == 0 {
					t.Fatalf("unusable configuration ready: %+v", p)
				}
				b, _ := p.File(pname)
				if string(b) != tc.data {
					t.Fatal("changed bytes")
				}
			}
		})
	}
}
func validMihomo(t *testing.T) []byte {
	t.Helper()
	p, e := Prepare(snapshot(t, "", nil), Selection{Cores: []catalog.Component{catalog.Mihomo}, ActiveCore: catalog.Mihomo}, ProviderImport("https://example.invalid/sub"))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := p.File(MihomoPath)
	return b
}
func TestWatchdogRejectsUnverifiableGroupMembership(t *testing.T) {
	raw := string(validMihomo(t))
	for name, data := range map[string]string{
		"filtered benchmark": strings.Replace(raw, "    hidden: true", "    hidden: true\n    filter: ONLY_ONE_NODE", 1),
		"duplicate target":   strings.Replace(raw, "listeners:", "  - name: PROXY\n    type: select\n    use: [subscription]\nlisteners:", 1),
		"filtered target":    strings.Replace(raw, "  - name: PROXY\n", "  - name: PROXY\n    exclude-filter: PRIVATE\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			p, e := Prepare(snapshot(t, "mihomo", map[string][]byte{MihomoPath: []byte(data)}), Selection{Cores: []catalog.Component{catalog.Mihomo}, Watchdog: true}, Import{})
			if e != nil || p.WatchdogEnabled || len(p.Conflicts) == 0 {
				t.Fatalf("unverifiable membership accepted: %v %+v", e, p)
			}
		})
	}
}
func TestExistingWatchdogParametersValidated(t *testing.T) {
	raw := validMihomo(t)
	p, e := Prepare(snapshot(t, "mihomo", map[string][]byte{MihomoPath: raw}), Selection{Cores: []catalog.Component{catalog.Mihomo}, Watchdog: true}, Import{})
	if e != nil || !p.WatchdogEnabled {
		t.Fatal("known template rejected")
	}
	defaults, _ := p.File(WatchdogPath)
	for name, change := range map[string]map[string]any{
		"zero candidates": {"top_n": 0}, "unknown provider": {"speed_test_provider": "unknown"}, "bad schedule": {"schedule": map[string]any{"windows": []any{map[string]any{"start": "25:00", "end": "07:00", "every_minutes": 1}}}}, "fractional integer": {"multi_rounds": 1.5}, "wrong integer type": {"parallel_streams": true}, "negative wait": {"switch_wait_seconds": -1}, "unknown schedule key": {"schedule": map[string]any{"windows": []any{}, "extra": true}},
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			_ = json.Unmarshal(defaults, &m)
			for k, v := range change {
				m[k] = v
			}
			bad, _ := json.Marshal(m)
			q, e := Prepare(snapshot(t, "mihomo", map[string][]byte{MihomoPath: raw, WatchdogPath: bad}), Selection{Cores: []catalog.Component{catalog.Mihomo}, Watchdog: true}, Import{})
			if e != nil || q.WatchdogEnabled || q.ActivationReady || len(q.Conflicts) == 0 {
				t.Fatalf("bad watchdog ready: %v %+v", e, q)
			}
			b, _ := q.File(WatchdogPath)
			if string(b) != string(bad) {
				t.Fatal("watchdog rewritten")
			}
		})
	}
}
func TestKnownCoreStructuresStillReady(t *testing.T) {
	for _, tc := range []struct {
		core catalog.Component
		data []byte
	}{{catalog.Mihomo, validMihomo(t)}, {catalog.Xray, []byte(`{"inbounds":[{"protocol":"dokodemo-door","port":50080,"settings":{"network":"tcp,udp","followRedirect":true}}],"outbounds":[{"protocol":"freedom","settings":{}}]}`)}} {
		p, e := Prepare(snapshot(t, "", nil), Selection{Cores: []catalog.Component{tc.core}, ActiveCore: tc.core}, LocalImport(tc.core, tc.data))
		if e != nil || !p.ActivationReady {
			t.Fatalf("known core structure rejected: %v %+v", e, p)
		}
	}
}
