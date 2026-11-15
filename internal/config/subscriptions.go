package config

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	XraySourcesPath  = "/opt/etc/xkeen-subscriptions/sources.json"
	XrayUpdaterPath  = "/opt/libexec/xkeen-subscriptions/update.py"
	XraySchedulePath = "/opt/etc/cron.d/xkeen-subscriptions"
	MaxSubscriptions = 10
)

func validateURLs(urls []string) error { return validateSubscriptionURLs("MIHOMO", urls) }

// ResolveSubscriptions downloads private Xray sources before the router plan is reviewed.
func ResolveSubscriptions(ctx context.Context, mihomo, xray []string) (Import, error) {
	i := Import{providerURLs: append([]string(nil), mihomo...), xrayURLs: append([]string(nil), xray...), providerSet: len(mihomo) > 0}
	if err := validateSubscriptionURLs("MIHOMO", mihomo); err != nil {
		return Import{}, err
	}
	if err := validateSubscriptionURLs("XRAY", xray); err != nil {
		return Import{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return resolveSubscriptions(ctx, subscriptionClient(), i)
}
func resolveSubscriptions(ctx context.Context, client *http.Client, i Import) (Import, error) {
	var sources [][]byte
	for index, raw := range i.xrayURLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return Import{}, subscriptionFailure("XRAY", "FETCH", "REQUEST", index+1)
		}
		req.Header.Set("Accept", "application/json")
		res, err := client.Do(req)
		if err != nil {
			return Import{}, subscriptionFetchFailure(err, index+1)
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			diagnostic := subscriptionFailure("XRAY", "FETCH", "HTTP_STATUS", index+1)
			diagnostic.status = res.StatusCode
			return Import{}, diagnostic
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, MaxImportBytes+1))
		res.Body.Close()
		if err != nil {
			return Import{}, subscriptionFailure("XRAY", "FETCH", "BODY_READ", index+1)
		}
		if len(body) > MaxImportBytes {
			return Import{}, subscriptionFailure("XRAY", "FETCH", "SIZE", index+1)
		}
		sources = append(sources, body)
	}
	if len(sources) > 0 {
		var err error
		i.xrayData, err = mergeXraySubscriptions(sources)
		if err != nil {
			return Import{}, err
		}
	}
	return i, nil
}
func mergeXraySubscriptions(sources [][]byte) ([]byte, error) {
	var proxies []any
	for sourceIndex, b := range sources {
		var value any
		if len(b) > MaxImportBytes {
			return nil, subscriptionFailure("XRAY", "JSON", "SIZE", sourceIndex+1)
		}
		if json.Unmarshal(b, &value) != nil {
			return nil, subscriptionFailure("XRAY", "JSON", "SYNTAX", sourceIndex+1)
		}
		documents, ok := value.([]any)
		if !ok {
			documents = []any{value}
		}
		before := len(proxies)
		for _, v := range documents {
			m, ok := v.(map[string]any)
			if !ok {
				return nil, subscriptionFailure("XRAY", "JSON", "DOCUMENT", sourceIndex+1)
			}
			outs, ok := m["outbounds"].([]any)
			if !ok {
				return nil, subscriptionFailure("XRAY", "JSON", "OUTBOUNDS", sourceIndex+1)
			}
			for _, v := range outs {
				out, ok := v.(map[string]any)
				if !ok {
					return nil, subscriptionFailure("XRAY", "JSON", "OUTBOUND", sourceIndex+1)
				}
				protocol, _ := out["protocol"].(string)
				switch protocol {
				case "vless", "vmess", "trojan", "shadowsocks", "socks", "http":
				default:
					continue
				}
				if _, ok := out["settings"].(map[string]any); !ok {
					return nil, subscriptionFailure("XRAY", "JSON", "SETTINGS", sourceIndex+1)
				}
				if _, ok := out["proxySettings"]; ok {
					return nil, subscriptionFailure("XRAY", "MERGE", "DEPENDENCY", sourceIndex+1)
				}
				if stream, ok := out["streamSettings"].(map[string]any); ok {
					if sock, ok := stream["sockopt"].(map[string]any); ok {
						if _, ok := sock["dialerProxy"]; ok {
							return nil, subscriptionFailure("XRAY", "MERGE", "DEPENDENCY", sourceIndex+1)
						}
					}
				}
				out["tag"] = fmt.Sprintf("subscription-node-%d", len(proxies)+1)
				proxies = append(proxies, out)
			}
		}
		if len(proxies) == before {
			return nil, subscriptionFailure("XRAY", "MERGE", "NO_PROXY", sourceIndex+1)
		}
	}
	if len(proxies) == 0 {
		return nil, subscriptionFailure("XRAY", "MERGE", "NO_PROXY", 0)
	}
	b, _ := templates.ReadFile("templates/xray.json")
	var base map[string]any
	_ = json.Unmarshal(b, &base)
	outbounds := []any{proxies[0]}
	for _, v := range base["outbounds"].([]any) {
		m := v.(map[string]any)
		if m["tag"] != "blocked-until-configured" {
			outbounds = append(outbounds, m)
		}
	}
	outbounds = append(outbounds, proxies[1:]...)
	base["outbounds"] = outbounds
	routing := base["routing"].(map[string]any)
	for _, v := range routing["rules"].([]any) {
		m := v.(map[string]any)
		if m["outboundTag"] == "blocked-until-configured" {
			m["outboundTag"] = "subscription-node-1"
		}
	}
	b, e := json.MarshalIndent(base, "", "  ")
	if e != nil || len(b)+1 > MaxImportBytes {
		return nil, subscriptionFailure("XRAY", "MERGE", "OUTPUT_LIMIT", 0)
	}
	return append(b, '\n'), nil
}

type subscriptionSources struct {
	URLs         []string `json:"urls"`
	ConfigSHA256 string   `json:"config_sha256"`
}

// ManagedSubscriptionFiles returns fixed updater payloads, never caller-selected paths.
func ManagedSubscriptionFiles(sources []byte) (map[string][]byte, error) {
	var meta subscriptionSources
	if json.Unmarshal(sources, &meta) != nil || len(meta.URLs) == 0 || validateURLs(meta.URLs) != nil {
		return nil, errors.New("invalid private subscription sources")
	}
	hash, e := hex.DecodeString(meta.ConfigSHA256)
	if e != nil || len(hash) != 32 {
		return nil, errors.New("invalid subscription configuration hash")
	}
	updater, e := templates.ReadFile("templates/update.py")
	if e != nil {
		return nil, e
	}
	base, _ := templates.ReadFile("templates/xray.json")
	encoded, _ := json.Marshal(string(base))
	updater = []byte(strings.Replace(string(updater), "__XRAY_BASE__", "json.loads("+string(encoded)+")", 1))
	return map[string][]byte{XraySourcesPath: sources, XrayUpdaterPath: updater, XraySchedulePath: []byte("0 */12 * * * root /opt/bin/python3 /opt/libexec/xkeen-subscriptions/update.py >/dev/null 2>&1\n")}, nil
}
