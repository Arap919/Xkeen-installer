package config

import (
	"encoding/json"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"testing"
)

func TestEmbeddedXrayBaseFromMihomo(t *testing.T) {
	p, e := Prepare(snapshot(t, "", nil), Selection{Cores: []catalog.Component{catalog.Xray}, ActiveCore: catalog.Xray}, Import{})
	if e != nil {
		t.Fatal(e)
	}
	b, ok := p.File(XrayPath)
	if !ok {
		t.Fatal("missing embedded Xray template")
	}
	if p.ActivationReady {
		t.Fatal("missing user proxy must prevent activation")
	}
	if !coreStructure("xray", b) {
		t.Fatal("invalid base structure")
	}
	var m map[string]any
	if e = json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	routing, _ := m["routing"].(map[string]any)
	if routing["domainStrategy"] != "AsIs" {
		t.Fatal("routing must not resolve domains solely for GEOIP")
	}
	rules, _ := routing["rules"].([]any)
	got := map[string]string{}
	for _, v := range rules {
		r := v.(map[string]any)
		name, _ := r["ruleTag"].(string)
		out, _ := r["outboundTag"].(string)
		got[name] = out
	}
	for name, out := range map[string]string{"Personal": "blocked-until-configured", "Ads": "block", "LAN": "direct", "Russia": "direct", "Steam": "direct", "Other": "direct", "Google": "blocked-until-configured", "AI": "blocked-until-configured", "YouTube": "blocked-until-configured", "GitHub": "blocked-until-configured", "Telegram": "blocked-until-configured", "Discord voice": "blocked-until-configured", "Speedtest": "blocked-until-configured", "IP Check": "blocked-until-configured", "Adult": "blocked-until-configured"} {
		if got[name] != out {
			t.Errorf("%s: got %s want %s", name, got[name], out)
		}
	}
	inbounds, _ := m["inbounds"].([]any)
	ports := map[string]float64{}
	for _, v := range inbounds {
		in := v.(map[string]any)
		ports[in["tag"].(string)] = in["port"].(float64)
	}
	for name, port := range map[string]float64{"transparent-in": 50080, "http-in": 7890, "socks-in": 7891, "benchmark-in": 17890, "dns-in": 7874} {
		if ports[name] != port {
			t.Errorf("%s port got %v", name, ports[name])
		}
	}
	dns, _ := m["dns"].(map[string]any)
	if dns["queryStrategy"] != "UseIPv4" {
		t.Fatal("DNS must use IPv4")
	}
}
