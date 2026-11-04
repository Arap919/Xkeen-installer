// Package config prepares configuration proposals without router access or writes.
package config

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/Arap919/xkeen-installer/internal/catalog"
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
	core        catalog.Component
	localSet    bool
	data        []byte
	providerURL string
	providerSet bool
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
func newMihomo(url string) ([]byte, error) {
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return nil, fmt.Errorf("generate API secret")
	}
	b, _ := templates.ReadFile("templates/mihomo.yaml")
	return []byte(fmt.Sprintf(string(b), strconv.Quote(hex.EncodeToString(key)), strconv.Quote(url))), nil
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
