package config

import (
	"bytes"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
)

// Match the checked-in watchdog validate_config/cron_entries contract, without normalizing bytes.
func watchdogSettings(b []byte) bool {
	decode := func(b []byte) (map[string]any, bool) {
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		var m map[string]any
		e := d.Decode(&m)
		return m, e == nil && m != nil
	}
	defaults, _ := templates.ReadFile("templates/watchdog.json")
	m, _ := decode(defaults)
	given, ok := decode(b)
	if !ok {
		return false
	}
	for k, v := range given {
		m[k] = v
	}
	provider, ok := m["speed_test_provider"].(string)
	if !ok || (provider != "cloudflare" && provider != "speedtest") {
		return false
	}
	for _, key := range []string{"controller", "benchmark_proxy"} {
		s, ok := m[key].(string)
		if !ok || providerURL(s) != nil {
			return false
		}
	}
	for _, key := range []string{"target_group", "benchmark_group"} {
		s, ok := m[key].(string)
		if !ok || len(bytes.TrimSpace([]byte(s))) == 0 {
			return false
		}
	}
	if m["target_group"] == m["benchmark_group"] {
		return false
	}
	if _, ok := m["secret"].(string); !ok {
		return false
	}
	for _, r := range []struct {
		key       string
		low, high int64
	}{{"top_n", 1, 50}, {"healthcheck_parallelism", 1, 32}, {"healthcheck_timeout_ms", 250, 10000}, {"speed_connect_timeout_seconds", 1, 30}, {"download_bytes", 1000000, 200000000}, {"parallel_streams", 1, 8}, {"multi_rounds", 1, 4}, {"log_cleanup_days", 1, 3650}} {
		if !integerRange(m[r.key], r.low, r.high) {
			return false
		}
	}
	wait, ok := m["switch_wait_seconds"].(json.Number)
	if !ok {
		return false
	}
	f, e := strconv.ParseFloat(string(wait), 64)
	if e != nil || math.IsInf(f, 0) || math.IsNaN(f) || f < 0 {
		return false
	}
	schedule, ok := m["schedule"].(map[string]any)
	if !ok || len(schedule) != 1 {
		return false
	}
	windows, ok := schedule["windows"].([]any)
	if !ok {
		return false
	}
	for _, entry := range windows {
		w, ok := entry.(map[string]any)
		if !ok || len(w) != 3 {
			return false
		}
		for _, k := range []string{"start", "end"} {
			s, ok := w[k].(string)
			if !ok || !watchdogTime.MatchString(s) {
				return false
			}
		}
		if !integerRange(w["every_minutes"], 1, 1440) {
			return false
		}
	}
	return true
}

var watchdogTime = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)

func integerRange(v any, low, high int64) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	i, e := n.Int64()
	return e == nil && i >= low && i <= high
}
