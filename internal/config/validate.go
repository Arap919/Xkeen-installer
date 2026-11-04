package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"

	"gopkg.in/yaml.v3"
)

func mihomoDocument(b []byte) (map[string]any, error) {
	if len(b) == 0 || len(b) > MaxImportBytes {
		return nil, errors.New("Mihomo configuration size is invalid")
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	var m map[string]any
	if d.Decode(&m) != nil || len(m) == 0 {
		return nil, errors.New("invalid Mihomo YAML mapping")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, errors.New("multiple YAML documents are unsupported")
	}
	return m, nil
}
func xrayDocument(b []byte) error {
	if len(b) == 0 || len(b) > MaxImportBytes {
		return errors.New("Xray configuration size is invalid")
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil || len(m) == 0 {
		return errors.New("invalid Xray JSON object")
	}
	return nil
}
func providerURL(raw string) error {
	if len(raw) > 8192 {
		return errors.New("provider URL too long")
	}
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Fragment != "" {
		return errors.New("invalid HTTP provider URL")
	}
	return nil
}
func group(m map[string]any, name string) map[string]any {
	a, _ := m["proxy-groups"].([]any)
	for _, v := range a {
		g, _ := v.(map[string]any)
		if g["name"] == name {
			return g
		}
	}
	return nil
}
func providerNames(m map[string]any, g map[string]any) ([]string, bool) {
	a, _ := g["use"].([]any)
	providers, _ := m["proxy-providers"].(map[string]any)
	var names []string
	for _, v := range a {
		n, ok := v.(string)
		p, _ := providers[n].(map[string]any)
		if !ok || n == "" || p == nil {
			return nil, false
		}
		switch p["type"] {
		case "http":
			u, _ := p["url"].(string)
			if providerURL(u) != nil {
				return nil, false
			}
		case "file":
			v, _ := p["path"].(string)
			if v == "" {
				return nil, false
			}
		default:
			return nil, false
		}
		names = append(names, n)
	}
	return names, len(names) > 0
}
func watchdogContract(m map[string]any) (string, string, string, bool) {
	controller, _ := m["external-controller"].(string)
	secret, _ := m["secret"].(string)
	if controller != "127.0.0.1:9090" || secret == "" {
		return "", "", "", false
	}
	target := group(m, "PROXY")
	bench := group(m, "BENCHMARK")
	if target["type"] != "select" || bench["type"] != "select" {
		return "", "", "", false
	}
	a, ok := providerNames(m, target)
	b, bok := providerNames(m, bench)
	if !ok || !bok {
		return "", "", "", false
	}
	seen := map[string]bool{}
	for _, n := range b {
		seen[n] = true
	}
	for _, n := range a {
		if !seen[n] {
			return "", "", "", false
		}
	}
	// Every use of a reserved port must match the intended dedicated listener.
	for _, key := range []string{"port", "socks-port", "mixed-port", "redir-port", "tproxy-port"} {
		if m[key] == 17890 || m[key] == 9090 {
			return "", "", "", false
		}
	}
	found := false
	ls, _ := m["listeners"].([]any)
	for _, v := range ls {
		l, _ := v.(map[string]any)
		if l["port"] == 9090 {
			return "", "", "", false
		}
		if l["port"] == 17890 {
			users, _ := l["users"].([]any)
			if len(users) != 0 {
				return "", "", "", false
			}
			if found || l["type"] != "http" || l["listen"] != "127.0.0.1" || l["proxy"] != "BENCHMARK" {
				return "", "", "", false
			}
			found = true
		}
	}
	return "http://" + controller, secret, "PROXY", found
}
