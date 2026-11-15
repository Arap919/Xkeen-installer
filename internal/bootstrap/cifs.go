package bootstrap

import "strings"

// withCIFS replaces configuration hints with fresh firmware runtime evidence.
// Raw command output is never retained or included in errors.
func withCIFS(s Snapshot, output string) (Snapshot, error) {
	s.Volumes = append([]Volume(nil), s.Volumes...)
	for i := range s.Volumes {
		s.Volumes[i].Share = ""
	}
	lineNumber := 0
	fail := func(reason, field string) (Snapshot, error) {
		return s, &CIFSParseError{Reason: reason, Field: field, Line: lineNumber}
	}
	type runtimeShare struct {
		mount, label string
		active       bool
		line         int
		seen         map[string]bool
	}
	var shares []runtimeShare
	var current *runtimeShare
	globals := map[string]bool{}
	enabled := false
	flush := func() bool {
		if current == nil {
			return true
		}
		if !current.seen["mount"] || !current.seen["label"] || !current.seen["active"] {
			return false
		}
		shares = append(shares, *current)
		current = nil
		return true
	}
	firstLine := true
	for index, line := range strings.Split(output, "\n") {
		lineNumber = index + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if firstLine {
			firstLine = false
			// Firmware may echo its command even when the requested PTY has ECHO=0.
			// Accept only this exact initial echo; all subsequent input is schema-checked.
			if trimmed == "show cifs" || trimmed == "(config)> show cifs" {
				continue
			}
		}
		key, value, ok := keyValue(line)
		if !ok {
			return fail("TEXT", "none")
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return fail("CONTROL", key)
		}
		if key == "share" {
			if value != "" {
				return fail("VALUE", "share")
			}
			if !flush() {
				return fail("MISSING", "share")
			}
			current = &runtimeShare{seen: map[string]bool{}, line: lineNumber}
			continue
		}
		switch key {
		case "enabled", "automount", "permissive", "map-hidden", "master":
			if !flush() {
				return fail("MISSING", "share")
			}
			if globals[key] {
				return fail("DUPLICATE", key)
			}
			if value != "yes" && value != "no" {
				return fail("VALUE", key)
			}
			globals[key] = true
			if key == "enabled" {
				enabled = value == "yes"
			}
		case "mount", "label", "active", "description":
			if current == nil {
				return fail("CONTEXT", key)
			}
			if current.seen[key] {
				return fail("DUPLICATE", key)
			}
			current.seen[key] = true
			switch key {
			case "mount":
				if value == "" || strings.ContainsAny(value, "\t\\") {
					return fail("VALUE", key)
				}
				current.mount = value
			case "label":
				if !validSMBShare(value) {
					return fail("VALUE", key)
				}
				current.label = value
			case "active":
				if value != "yes" && value != "no" {
					return fail("VALUE", key)
				}
				current.active = value == "yes"
			case "description":
				// Descriptions do not identify a partition or an SMB root.
			}
		default:
			return fail("UNKNOWN_FIELD", "unknown")
		}
	}
	if !flush() {
		return fail("MISSING", "share")
	}
	if !globals["enabled"] {
		return fail("MISSING", "enabled")
	}
	if !enabled {
		return s, nil
	}
	// SMB names are case-insensitive. Include every active target in collision
	// checks, including subdirectories and stale partitions.
	names := map[string]bool{}
	roots := map[string]string{}
	for _, share := range shares {
		lineNumber = share.line
		if !share.active {
			continue
		}
		name := strings.ToLower(share.label)
		if names[name] {
			return fail("NAME_CONFLICT", "label")
		}
		names[name] = true
		uuid, ok := s.rootVolumeID(share.mount)
		if !ok {
			continue
		}
		if _, exists := roots[uuid]; exists {
			return fail("ROOT_CONFLICT", "mount")
		}
		roots[uuid] = share.label
	}
	for i := range s.Volumes {
		s.Volumes[i].Share = roots[s.Volumes[i].UUID]
	}
	return s, nil
}
