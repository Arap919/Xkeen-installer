package config

import "strings"

// Unsupported server/routing forms require native/manual validation rather than inferred readiness.
func nonemptyString(v any) bool { s, ok := v.(string); return ok && strings.TrimSpace(s) != "" }
func xrayServers(settings map[string]any, protocol string) bool {
	key := "servers"
	if protocol == "vless" || protocol == "vmess" {
		key = "vnext"
	}
	servers, ok := settings[key].([]any)
	if !ok || len(servers) == 0 {
		return false
	}
	for _, entry := range servers {
		server, ok := entry.(map[string]any)
		if !ok || !nonemptyString(server["address"]) || !validPort(server["port"]) {
			return false
		}
		switch protocol {
		case "vless", "vmess":
			users, ok := server["users"].([]any)
			if !ok || len(users) == 0 {
				return false
			}
			for _, entry := range users {
				user, ok := entry.(map[string]any)
				if !ok || !nonemptyString(user["id"]) {
					return false
				}
			}
		case "trojan":
			if !nonemptyString(server["password"]) {
				return false
			}
		case "shadowsocks":
			if !nonemptyString(server["method"]) || !nonemptyString(server["password"]) {
				return false
			}
		case "socks", "http":
			if v, exists := server["users"]; exists {
				users, ok := v.([]any)
				if !ok {
					return false
				}
				for _, entry := range users {
					user, ok := entry.(map[string]any)
					if !ok || !nonemptyString(user["user"]) || !nonemptyString(user["pass"]) {
						return false
					}
				}
			}
		}
	}
	return true
}
func xrayRouting(m map[string]any) bool {
	routing, exists := m["routing"]
	if !exists {
		return true
	}
	r, ok := routing.(map[string]any)
	if !ok {
		return false
	}
	if _, exists := r["balancers"]; exists {
		return false
	}
	inbound, outbound := map[string]bool{}, map[string]bool{}
	for section, refs := range map[string]map[string]bool{"inbounds": inbound, "outbounds": outbound} {
		entries, _ := m[section].([]any)
		for _, entry := range entries {
			v, _ := entry.(map[string]any)
			if tag, ok := v["tag"].(string); ok {
				refs[tag] = true
			}
		}
	}
	if v, exists := r["rules"]; exists {
		rules, ok := v.([]any)
		if !ok {
			return false
		}
		for _, entry := range rules {
			rule, ok := entry.(map[string]any)
			if !ok || rule["type"] != "field" {
				return false
			}
			if _, exists := rule["balancerTag"]; exists {
				return false
			}
			tag, ok := rule["outboundTag"].(string)
			if !ok || !outbound[tag] {
				return false
			}
			if v, exists := rule["inboundTag"]; exists {
				names, ok := stringList(v)
				if !ok {
					return false
				}
				for _, name := range names {
					if !inbound[name] {
						return false
					}
				}
			}
		}
	}
	return true
}
func mihomoRuleProvider(m map[string]any, name string) bool {
	definitions, ok := m["rule-providers"].(map[string]any)
	if !ok {
		return false
	}
	provider, ok := definitions[name].(map[string]any)
	if !ok {
		return false
	}
	switch provider["behavior"] {
	case "domain", "ipcidr", "classical":
	default:
		return false
	}
	switch provider["type"] {
	case "inline":
		payload, ok := stringList(provider["payload"])
		return ok && len(payload) > 0
	case "http":
		u, ok := provider["url"].(string)
		if !ok || providerURL(u) != nil {
			return false
		}
	case "file":
	default:
		return false
	}
	return nonemptyString(provider["path"])
}
