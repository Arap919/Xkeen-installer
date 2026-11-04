package config

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/router"
)

// Prepare never opens an input path, fetches a URL, or writes to a transport.
// Existing files take precedence over imports and are never reserialized.
func Prepare(s router.Snapshot, selection Selection, input Import) (ConfigProposal, error) {
	p := ConfigProposal{files: map[string][]byte{}, ActivationReady: true}
	cores := map[catalog.Component]bool{}
	for _, c := range selection.Cores {
		if (c != catalog.Mihomo && c != catalog.Xray) || cores[c] {
			return p, errors.New("invalid core selection")
		}
		cores[c] = true
	}
	if len(cores) == 0 {
		return p, errors.New("select at least one core")
	}
	if len(input.data) > MaxImportBytes {
		return p, errors.New("import size limit exceeded")
	}
	if input.localSet {
		if !cores[input.core] {
			return p, errors.New("import core is not selected")
		}
		switch input.core {
		case catalog.Mihomo:
			if _, e := mihomoDocument(input.data); e != nil {
				return p, e
			}
		case catalog.Xray:
			if e := xrayDocument(input.data); e != nil {
				return p, e
			}
		}
	}
	if input.providerSet {
		if !cores[catalog.Mihomo] || input.localSet {
			return p, errors.New("provider import requires Mihomo without local import")
		}
		if e := providerURL(input.providerURL); e != nil {
			return p, e
		}
	}
	if selection.ActiveCore != "" {
		if !cores[selection.ActiveCore] {
			return p, errors.New("active core is not selected")
		}
		p.ActiveCore = selection.ActiveCore
	} else if s.ActiveCore == "mihomo" || s.ActiveCore == "xray" {
		p.ActiveCore = catalog.Component(s.ActiveCore)
	} else {
		p.conflict("", "Choose an active core explicitly; inspection is inconclusive.", "")
	}
	if p.ActiveCore != "" && !cores[p.ActiveCore] {
		p.conflict("", "Existing active core is excluded; choose a switch explicitly.", "")
	}
	for _, core := range []catalog.Component{catalog.Mihomo, catalog.Xray} {
		if !cores[core] {
			continue
		}
		existing := false
		for _, f := range s.Files {
			isConfig := core == catalog.Mihomo && strings.HasPrefix(f.Path, "/opt/etc/mihomo/") && (strings.HasSuffix(f.Path, ".yaml") || strings.HasSuffix(f.Path, ".yml"))
			isConfig = isConfig || core == catalog.Xray && strings.HasPrefix(f.Path, "/opt/etc/xray/") && strings.HasSuffix(f.Path, ".json")
			if !isConfig {
				continue
			}
			b, ok := s.Config(f.Path)
			if !ok {
				return p, errors.New("snapshot configuration contents unavailable")
			}
			p.add(f.Path, b, "preserve")
			existing = true
			if core == catalog.Mihomo {
				if _, e := mihomoDocument(b); e != nil {
					p.conflict(f.Path, "Existing YAML needs manual validation.", "")
				}
			} else if xrayDocument(b) != nil {
				p.conflict(f.Path, "Existing JSON needs manual validation.", "")
			}
		}
		if existing {
			if input.core == core && input.localSet || core == catalog.Mihomo && input.providerSet {
				p.conflict("", "Import would replace existing configuration; resolve manually.", "")
			}
			continue
		}
		if core == catalog.Mihomo {
			var b []byte
			var e error
			if input.core == core && input.localSet {
				b = input.data
			} else if input.providerSet {
				b, e = newMihomo(input.providerURL)
			} else {
				p.conflict(MihomoPath, "A nonempty provider URL or local Mihomo configuration is required.", "")
				continue
			}
			if e != nil {
				return p, e
			}
			p.add(MihomoPath, b, "create")
		} else {
			b, _ := templates.ReadFile("templates/xray.json")
			if input.core == core && input.localSet {
				b = input.data
			} else {
				p.conflict(XrayPath, "Add a user proxy outbound and routing before activation.", "Replace blocked-until-configured with the user connection and route transparent-in to it.")
			}
			p.add(XrayPath, b, "create")
		}
	}
	if selection.Watchdog {
		b, ok := p.File(MihomoPath)
		var m map[string]any
		if ok {
			m, _ = mihomoDocument(b)
		}
		controller, secret, target, compatible := watchdogContract(m)
		if !compatible {
			p.conflict(MihomoPath, "Watchdog requires compatible provider-backed PROXY/BENCHMARK groups, API secret and dedicated ports; existing bytes preserved.", watchdogAddition())
		} else {
			desired := newWatchdog(controller, secret, target)
			if old, ok := s.Config(WatchdogPath); ok {
				p.add(WatchdogPath, old, "preserve")
				var a, w map[string]any
				_ = json.Unmarshal(old, &a)
				_ = json.Unmarshal(desired, &w)
				compatible = true
				for _, k := range []string{"controller", "secret", "target_group", "benchmark_group", "benchmark_proxy"} {
					if a[k] != w[k] {
						compatible = false
					}
				}
				if !compatible {
					p.conflict(WatchdogPath, "Existing watchdog settings differ from the required Mihomo contract.", "controller: http://127.0.0.1:9090; secret: <Mihomo API secret>; target_group: PROXY; benchmark_group: BENCHMARK; benchmark_proxy: http://127.0.0.1:17890")
				}
			} else {
				p.add(WatchdogPath, desired, "create")
			}
			p.WatchdogEnabled = compatible && p.ActiveCore == catalog.Mihomo && len(p.Conflicts) == 0
		}
	}
	return p, nil
}
func watchdogAddition() string {
	return "Merge only missing entries into the corresponding sections; resolve occupied ports first:\nexternal-controller: 127.0.0.1:9090\nsecret: <private generated API secret>\nproxy-groups:\n  - name: PROXY\n    type: select\n    use: [<existing provider names>]\n  - name: BENCHMARK\n    type: select\n    use: [<same provider names>]\nlisteners:\n  - name: benchmark-in\n    type: http\n    listen: 127.0.0.1\n    port: 17890\n    proxy: BENCHMARK\n    users: []"
}
