package bootstrap

import "strings"

// Only the narrow OPKG/CIFS evidence enters tokenization. Unrelated configuration
// (including credentials and interface settings) is discarded without logging.
func configurationTokens(config string) ([][]string, error) {
	var out [][]string
	group := ""
	for _, raw := range strings.Split(config, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if line == "!" || line == "exit" {
			group = ""
			continue
		}
		if line == "cifs" || line == "opkg" {
			group = line
			continue
		}
		indented := len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t')
		if group != "" && indented {
			line = group + " " + line
		} else {
			group = ""
		}
		head := strings.Fields(line)
		relevant := len(head) >= 2 && (head[0] == "cifs" && head[1] == "share" || head[0] == "opkg" && (head[1] == "disk" || head[1] == "initrc"))
		if !relevant {
			continue
		}
		tokens, e := quotedTokens(line)
		if e != nil {
			return nil, e
		}
		out = append(out, tokens)
	}
	return out, nil
}
func quotedTokens(line string) ([]string, error) {
	var out []string
	var word strings.Builder
	quoted, started := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' || c == 0 || c == '\r' || c == '\n' {
			return nil, ErrUnsafe
		}
		if c == '"' {
			quoted = !quoted
			started = true
			continue
		}
		if !quoted && (c == ' ' || c == '\t') {
			if started {
				out = append(out, word.String())
				word.Reset()
				started = false
			}
			continue
		}
		started = true
		word.WriteByte(c)
	}
	if quoted {
		return nil, ErrUnsafe
	}
	if started {
		out = append(out, word.String())
	}
	return out, nil
}
