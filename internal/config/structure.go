package config

import (
	"encoding/json"
	"strings"
)

// These conservative checks reject known unusable structures, not replace native validation.
func coreStructure(core string, b []byte) bool {
	if core == "mihomo" {
		m, e := mihomoDocument(b)
		return e == nil && mihomoStructure(m)
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	for _, section := range []string{"inbounds", "outbounds"} {
		entries, ok := m[section].([]any)
		if !ok || len(entries) == 0 {
			return false
		}
		tags := map[string]bool{}
		for _, entry := range entries {
			v, ok := entry.(map[string]any)
			if !ok {
				return false
			}
			proto, _ := v["protocol"].(string)
			if tag, exists := v["tag"]; exists {
				s, ok := tag.(string)
				if !ok || s == "" || tags[s] {
					return false
				}
				tags[s] = true
			}
			settings, ok := v["settings"].(map[string]any)
			if !ok {
				return false
			}
			if section == "inbounds" {
				switch proto {
				case "dokodemo-door", "http", "socks", "vless", "vmess", "trojan", "shadowsocks":
				default:
					return false
				}
				if !validPort(v["port"]) {
					return false
				}
				if listen, exists := v["listen"]; exists {
					if _, ok := listen.(string); !ok {
						return false
					}
				}
			} else {
				switch proto {
				case "freedom", "blackhole", "dns":
				case "vless", "vmess":
					if a, ok := settings["vnext"].([]any); !ok || len(a) == 0 {
						return false
					}
				case "trojan", "shadowsocks", "socks", "http":
					if a, ok := settings["servers"].([]any); !ok || len(a) == 0 {
						return false
					}
				default:
					return false
				}
			}
		}
	}
	for _, key := range []string{"log", "routing", "dns", "policy"} {
		if v, exists := m[key]; exists {
			if _, ok := v.(map[string]any); !ok {
				return false
			}
		}
	}
	return true
}
func validPort(v any) bool {
	switch n := v.(type) {
	case int:
		return n >= 1 && n <= 65535
	case float64:
		return n >= 1 && n <= 65535 && n == float64(int(n))
	}
	return false
}
func stringList(v any) ([]string, bool) {
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(a))
	for _, v := range a {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}
func mihomoStructure(m map[string]any) bool {
	mode := "rule"
	if v, exists := m["mode"]; exists {
		var ok bool
		mode, ok = v.(string)
		if !ok || (mode != "rule" && mode != "global" && mode != "direct") {
			return false
		}
	}
	for _, key := range []string{"external-controller", "secret", "log-level"} {
		if v, exists := m[key]; exists {
			if _, ok := v.(string); !ok {
				return false
			}
		}
	}
	hasInbound := false
	for _, key := range []string{"port", "socks-port", "mixed-port", "redir-port", "tproxy-port"} {
		if v, exists := m[key]; exists {
			if !validPort(v) {
				return false
			}
			hasInbound = true
		}
	}
	refs := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "GLOBAL": true}
	groups, groupsOK := m["proxy-groups"].([]any)
	if _, exists := m["proxy-groups"]; exists && !groupsOK {
		return false
	}
	for _, section := range []string{"proxies", "proxy-groups"} {
		if a, exists := m[section]; exists {
			list, ok := a.([]any)
			if !ok {
				return false
			}
			for _, v := range list {
				item, ok := v.(map[string]any)
				if !ok {
					return false
				}
				name, ok := item["name"].(string)
				if !ok || name == "" || refs[name] {
					return false
				}
				refs[name] = true
				if section == "proxies" {
					typ, ok := item["type"].(string)
					if !ok || typ == "" {
						return false
					}
				}
			}
		}
	}
	if v, exists := m["proxy-providers"]; exists {
		defs, ok := v.(map[string]any)
		if !ok {
			return false
		}
		for name := range defs {
			if _, ok := providerNames(m, map[string]any{"use": []any{name}}); !ok {
				return false
			}
		}
	}
	for _, v := range groups {
		g := v.(map[string]any)
		switch g["type"] {
		case "select", "url-test", "fallback", "load-balance", "relay":
		default:
			return false
		}
		hasMember := false
		if use, exists := g["use"]; exists {
			if _, ok := stringList(use); !ok {
				return false
			}
			if _, ok := providerNames(m, g); !ok {
				return false
			}
			hasMember = true
		}
		if proxies, exists := g["proxies"]; exists {
			names, ok := stringList(proxies)
			if !ok {
				return false
			}
			for _, n := range names {
				if !refs[n] || n == g["name"] {
					return false
				}
			}
			hasMember = hasMember || len(names) > 0
		}
		if !hasMember {
			return false
		}
	}
	if v, exists := m["listeners"]; exists {
		a, ok := v.([]any)
		if !ok {
			return false
		}
		for _, entry := range a {
			l, ok := entry.(map[string]any)
			if !ok || !validPort(l["port"]) {
				return false
			}
			switch l["type"] {
			case "http", "socks", "mixed", "redir", "tproxy":
			default:
				return false
			}
			if listen, exists := l["listen"]; exists {
				if _, ok := listen.(string); !ok {
					return false
				}
			}
			if proxy, exists := l["proxy"]; exists {
				name, ok := proxy.(string)
				if !ok || !refs[name] {
					return false
				}
			}
			hasInbound = true
		}
	}
	if !hasInbound {
		return false
	}
	if mode == "rule" {
		rules, ok := stringList(m["rules"])
		if !ok || len(rules) == 0 {
			return false
		}
		for _, rule := range rules {
			parts := strings.Split(rule, ",")
			if len(parts) < 2 {
				return false
			}
			i := len(parts) - 1
			if parts[i] == "no-resolve" {
				i--
			}
			if i < 1 || !refs[parts[i]] {
				return false
			}
		}
	}
	return true
}
