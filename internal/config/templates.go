// Package config prepares configuration proposals without router access or writes.
package config

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Arap919/xkeen-installer/internal/catalog"
	"gopkg.in/yaml.v3"
)

//go:embed templates/*
var templates embed.FS

const (
	MihomoPath     = "/opt/etc/mihomo/config.yaml"
	XrayPath       = "/opt/etc/xray/configs/00-installer.json"
	WatchdogPath   = "/opt/etc/router-watchdog.json"
	MaxImportBytes = 2 << 20
)

type Selection struct {
	Cores []catalog.Component
	// Empty retains the inspected active core. Unknown evidence requires an explicit choice.
	ActiveCore catalog.Component
	Watchdog   bool
}

// Import holds backend-only input. Constructors copy local data; no input is serialized.
type Import struct {
	core         catalog.Component
	localSet     bool
	data         []byte
	providerURL  string
	providerURLs []string
	xrayURLs     []string
	xrayData     []byte
	providerSet  bool
}

func LocalImport(core catalog.Component, data []byte) Import {
	return Import{core: core, data: append([]byte(nil), data...), localSet: true}
}
func ProviderImport(url string) Import { return Import{providerURL: url, providerSet: true} }
func (Import) String() string          { return "Import{redacted}" }
func (i Import) GoString() string      { return i.String() }

type FilePreview struct {
	Path    string
	Action  string
	Preview string
}
type Conflict struct {
	Path              string
	Reason            string
	NecessaryAddition string
}
type ConfigProposal struct {
	Files           []FilePreview
	Conflicts       []Conflict
	ActiveCore      catalog.Component
	WatchdogEnabled bool
	// ActivationReady is structural readiness only; native core validation remains mandatory.
	ActivationReady bool
	files           map[string][]byte
}

func (p ConfigProposal) File(path string) ([]byte, bool) {
	b, ok := p.files[path]
	return append([]byte(nil), b...), ok
}
func (p ConfigProposal) String() string   { b, _ := json.Marshal(p); return string(b) }
func (p ConfigProposal) GoString() string { return p.String() }
func (p *ConfigProposal) add(path string, b []byte, action string) {
	p.files[path] = append([]byte(nil), b...)
	p.Files = append(p.Files, FilePreview{path, action, "[configuration contents redacted]"})
}
func (p *ConfigProposal) conflict(path, reason, addition string) {
	p.Conflicts = append(p.Conflicts, Conflict{path, reason, addition})
	p.ActivationReady = false
}
func newMihomo(url string) ([]byte, error) { return newMihomoURLs([]string{url}) }
func newMihomoURLs(urls []string) ([]byte, error) {
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return nil, fmt.Errorf("generate API secret")
	}
	b, err := templates.ReadFile("templates/mihomo.yaml")
	if err != nil {
		return nil, err
	}
	m, err := mihomoDocument(b)
	if err != nil {
		return nil, err
	}
	baseProviders, ok := m["proxy-providers"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing embedded proxy providers")
	}
	prototype, ok := baseProviders["VPNProvider"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing embedded VPNProvider")
	}
	providers := map[string]any{}
	names := []any{}
	for i, raw := range urls {
		name := "VPNProvider"
		if i > 0 {
			name = fmt.Sprintf("VPNProvider%d", i)
		}
		names = append(names, name)
		cachePath := fmt.Sprintf("./providers/subscription-%d.yaml", i)
		if i == 0 {
			cachePath = "./providers/subscription.yaml"
		}
		provider := make(map[string]any, len(prototype)+1)
		for key, value := range prototype {
			provider[key] = value
		}
		provider["url"] = raw
		provider["path"] = cachePath
		providers[name] = provider
	}
	m["proxy-providers"] = providers
	group(m, "Proxy")["use"] = names
	group(m, "BENCHMARK")["use"] = names
	m["external-controller"] = "127.0.0.1:9090"
	m["secret"] = hex.EncodeToString(key)
	listeners := m["listeners"].([]any)
	for _, value := range listeners {
		listener := value.(map[string]any)
		if listener["name"] == "benchmark-in" {
			listener["listen"] = "127.0.0.1"
		}
	}
	return yaml.Marshal(m)
}
func newWatchdog(controller, secret, target string) []byte {
	b, _ := templates.ReadFile("templates/watchdog.json")
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["controller"] = controller
	m["secret"] = secret
	m["target_group"] = target
	b, _ = json.MarshalIndent(m, "", "  ")
	return append(b, '\n')
}
