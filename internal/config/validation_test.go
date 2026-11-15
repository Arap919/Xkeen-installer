package config

import (
	"encoding/json"
	"testing"

	"github.com/Arap919/xkeen-installer/internal/catalog"
	"gopkg.in/yaml.v3"
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
	for name, change := range map[string]func(map[string]any){
		"filtered benchmark": func(m map[string]any) { group(m, "BENCHMARK")["filter"] = "ONLY_ONE_NODE" },
		"duplicate target":   func(m map[string]any) { m["proxy-groups"] = append(m["proxy-groups"].([]any), group(m, "Proxy")) },
		"filtered target":    func(m map[string]any) { group(m, "Proxy")["exclude-filter"] = "PRIVATE" },
	} {
		t.Run(name, func(t *testing.T) {
			m, e := mihomoDocument(validMihomo(t))
			if e != nil {
				t.Fatal(e)
			}
			change(m)
			data, e := yaml.Marshal(m)
			if e != nil {
				t.Fatal(e)
			}
			p, e := Prepare(snapshot(t, "mihomo", map[string][]byte{MihomoPath: data}), Selection{Cores: []catalog.Component{catalog.Mihomo}, Watchdog: true}, Import{})
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

func TestXrayServerObjectsAndRoutingReferences(t *testing.T) {
	inbound := `"inbounds":[{"tag":"transparent","protocol":"dokodemo-door","port":50080,"settings":{"network":"tcp,udp","followRedirect":true}}]`
	for _, tc := range []struct {
		name, outbound, routing string
		ready                   bool
	}{
		{"null vnext", `{"protocol":"vless","settings":{"vnext":[null]}}`, "", false},
		{"empty vnext object", `{"protocol":"vless","settings":{"vnext":[{}]}}`, "", false},
		{"null vnext user", `{"protocol":"vless","settings":{"vnext":[{"address":"example.invalid","port":443,"users":[null]}]}}`, "", false},
		{"invalid server port", `{"protocol":"http","settings":{"servers":[{"address":"example.invalid","port":0}]}}`, "", false},
		{"missing trojan password", `{"protocol":"trojan","settings":{"servers":[{"address":"example.invalid","port":443}]}}`, "", false},
		{"missing outbound tag", `{"tag":"direct","protocol":"freedom","settings":{}}`, `,"routing":{"rules":[{"type":"field","outboundTag":"MISSING"}]}`, false},
		{"missing inbound tag", `{"tag":"direct","protocol":"freedom","settings":{}}`, `,"routing":{"rules":[{"type":"field","inboundTag":["MISSING"],"outboundTag":"direct"}]}`, false},
		{"unsupported balancer", `{"tag":"direct","protocol":"freedom","settings":{}}`, `,"routing":{"rules":[{"type":"field","balancerTag":"MISSING"}]}`, false},
		{"valid server", `{"protocol":"vless","settings":{"vnext":[{"address":"example.invalid","port":443,"users":[{"id":"00000000-0000-4000-8000-000000000001","encryption":"none"}]}]}}`, "", true},
		{"valid routing", `{"tag":"direct","protocol":"freedom","settings":{}}`, `,"routing":{"rules":[{"type":"field","inboundTag":["transparent"],"outboundTag":"direct"}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{` + inbound + `,"outbounds":[` + tc.outbound + `]` + tc.routing + `}`)
			p, e := Prepare(snapshot(t, "", nil), Selection{Cores: []catalog.Component{catalog.Xray}, ActiveCore: catalog.Xray}, LocalImport(catalog.Xray, data))
			if e != nil {
				t.Fatal(e)
			}
			if p.ActivationReady != tc.ready {
				t.Fatalf("ready=%v want %v: %+v", p.ActivationReady, tc.ready, p)
			}
			b, _ := p.File(XrayPath)
			if string(b) != string(data) {
				t.Fatal("config rewritten")
			}
			if !tc.ready && len(p.Conflicts) == 0 {
				t.Fatal("missing conflict")
			}
		})
	}
}
func TestMihomoRuleProviderReferences(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		ready       bool
	}{
		{"missing provider", "", false},
		{"wrong provider type", "rule-providers: {MISSING: null}\n", false},
		{"incomplete provider", "rule-providers: {MISSING: {type: http}}\n", false},
		{"valid provider", "rule-providers:\n  MISSING: {type: http, behavior: domain, url: 'https://example.invalid/rules', path: './rules/domain.yaml'}\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("port: 7890\nrules: ['RULE-SET,MISSING,DIRECT', 'MATCH,DIRECT']\n" + tc.extra)
			p, e := Prepare(snapshot(t, "mihomo", map[string][]byte{MihomoPath: data}), Selection{Cores: []catalog.Component{catalog.Mihomo}}, Import{})
			if e != nil || p.ActivationReady != tc.ready {
				t.Fatalf("ready=%v want %v: %v %+v", p.ActivationReady, tc.ready, e, p)
			}
			b, _ := p.File(MihomoPath)
			if string(b) != string(data) {
				t.Fatal("config rewritten")
			}
		})
	}
}
