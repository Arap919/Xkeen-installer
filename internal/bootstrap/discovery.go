// Package bootstrap prepares and executes reviewed firmware-native Entware bootstrap.
package bootstrap

import (
	"errors"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"regexp"
	"strconv"
	"strings"
)

var ErrUnsafe = errors.New("bootstrap evidence is missing, ambiguous or unsafe")
var ext4UUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,79}$`)

type Volume struct {
	UUID    string
	Label   string
	Free    uint64
	Share   string
	MediaID string
}
type Snapshot struct {
	Model       string
	Hardware    string
	Arch        catalog.RouterArch
	Volumes     []Volume
	disk        string
	initrc      string
	identifiers map[string]string
}

func Architecture(id, cpu string) (catalog.RouterArch, error) {
	id = strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(id)), "-", "")
	if strings.HasPrefix(id, "NC") {
		id = "KN" + strings.TrimPrefix(id, "NC")
	}
	var arch catalog.RouterArch
	for _, group := range []struct {
		a   catalog.RouterArch
		ids string
	}{
		{catalog.ARM64, "4210 2710 1811 1812 1012 1013 3811 3812 2312 4110"},
		{catalog.MIPSel, "1010 1011 1810 1910 1912 1913 2610 2310 2311 3810 2910 2012 2113 3611 1212 1711 1713"},
		{catalog.MIPS, "2510 2410 2010 2112 2110 3610"},
	} {
		for _, n := range strings.Fields(group.ids) {
			if id == "KN"+n {
				arch = group.a
			}
		}
	}
	cpu = strings.ToLower(strings.TrimSpace(cpu))
	if arch == "" || arch == catalog.ARM64 && (cpu != "aarch64" && cpu != "arm64") || arch != catalog.ARM64 && (cpu != "mips" && cpu != "mipsel" && cpu != "mipsle") {
		return "", ErrUnsafe
	}
	if arch == catalog.MIPS && (cpu == "mipsel" || cpu == "mipsle") {
		return "", ErrUnsafe
	}
	return arch, nil
}
func keyValue(line string) (string, string, bool) {
	k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
	return strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"`), ok
}
func Parse(version, media, config string) (Snapshot, error) {
	s := Snapshot{identifiers: map[string]string{}}
	var cpu string
	for _, line := range strings.Split(version, "\n") {
		k, v, ok := keyValue(line)
		if !ok {
			continue
		}
		switch k {
		case "hw_id":
			if s.Hardware != "" {
				return s, ErrUnsafe
			}
			s.Hardware = v
		case "model":
			s.Model = v
		case "arch":
			cpu = v
		}
	}
	var err error
	s.Arch, err = Architecture(s.Hardware, cpu)
	if err != nil {
		return Snapshot{}, err
	}
	type partition struct {
		uuid, label, fs, state string
		free                   uint64
		freeOK                 bool
	}
	var current *partition
	seen := map[string]bool{}
	mediaID := ""
	flush := func() error {
		if current == nil {
			return nil
		}
		p := current
		if !safeID.MatchString(p.uuid) || seen[p.uuid] {
			return ErrUnsafe
		}
		seen[p.uuid] = true
		for _, identifier := range []string{p.uuid, p.label} {
			if identifier == "" {
				continue
			}
			if old, exists := s.identifiers[identifier]; exists {
				if old != p.uuid {
					s.identifiers[identifier] = ""
				}
			} else {
				s.identifiers[identifier] = p.uuid
			}
		}
		if strings.EqualFold(p.fs, "ext4") && p.state == "MOUNTED" {
			if !p.freeOK || mediaID == "" || !ext4UUID.MatchString(p.uuid) {
				return ErrUnsafe
			}
			s.Volumes = append(s.Volumes, Volume{UUID: p.uuid, Label: p.label, Free: p.free, MediaID: mediaID})
		}
		return nil
	}
	for _, line := range strings.Split(media, "\n") {
		k, v, ok := keyValue(line)
		if !ok {
			continue
		}
		if k == "partition" || k == "media" {
			if err = flush(); err != nil {
				return Snapshot{}, err
			}
			current = nil
			if k == "partition" {
				current = &partition{}
			} else {
				mediaID = ""
			}
			continue
		}
		if current == nil {
			switch k {
			case "name", "serial", "port", "device", "model":
				mediaID += k + "=" + v + ";"
			}
			continue
		}
		switch k {
		case "uuid":
			current.uuid = v
		case "label":
			current.label = v
		case "fstype":
			current.fs = v
		case "state":
			current.state = v
		case "free":
			current.free, err = strconv.ParseUint(v, 10, 64)
			current.freeOK = err == nil
		}
	}
	if err = flush(); err != nil {
		return Snapshot{}, err
	}
	shares := map[string]string{}
	ambiguous := map[string]bool{}
	// The complete running configuration never leaves this parser or enters a DTO.
	commands, err := configurationTokens(config)
	if err != nil {
		return Snapshot{}, err
	}
	for _, f := range commands {
		if len(f) == 0 {
			continue
		}
		switch {
		case len(f) >= 2 && f[0] == "opkg" && f[1] == "disk":
			if len(f) != 3 || s.disk != "" {
				return Snapshot{}, ErrUnsafe
			}
			s.disk = f[2]
		case len(f) >= 2 && f[0] == "opkg" && f[1] == "initrc":
			if len(f) != 3 || s.initrc != "" {
				return Snapshot{}, ErrUnsafe
			}
			s.initrc = f[2]
		case len(f) >= 2 && f[0] == "cifs" && f[1] == "share":
			if len(f) < 4 || len(f) > 5 {
				return Snapshot{}, ErrUnsafe
			}
			target := f[3]
			uuid, ok := s.rootVolumeID(target)
			if !ok {
				continue
			}
			name := f[2]
			if name == "" || strings.ContainsAny(name, "/\\\r\n\x00") {
				continue
			}
			if shares[uuid] != "" {
				ambiguous[uuid] = true
			}
			for other, owner := range shares {
				if owner == name && other != uuid {
					ambiguous[other] = true
					ambiguous[uuid] = true
				}
			}
			shares[uuid] = name
		}
	}
	if s.initrc != "" && s.initrc != "/opt/etc/initrc" && s.initrc != "/opt/etc/init.d" && s.initrc != "/opt/etc/init.d/rc.unslung" {
		return Snapshot{}, ErrUnsafe
	}
	for i := range s.Volumes {
		if !ambiguous[s.Volumes[i].UUID] {
			s.Volumes[i].Share = shares[s.Volumes[i].UUID]
		}
	}
	return s, nil
}
func (s Snapshot) Select(uuid string) (Volume, error) {
	if uuid == "" {
		eligible := s.EligibleVolumes()
		if len(eligible) != 1 {
			return Volume{}, ErrUnsafe
		}
		uuid = eligible[0].UUID
	}
	for _, v := range s.Volumes {
		if v.UUID == uuid && v.Share != "" && v.Free >= 64<<20 {
			// Switching an unrelated OPKG disk is never part of bootstrap.
			if s.disk != "" {
				selected, ok := s.rootVolumeID(s.disk)
				if !ok || selected != v.UUID {
					return Volume{}, ErrUnsafe
				}
			}
			return v, nil
		}
	}
	return Volume{}, ErrUnsafe
}
func (s Snapshot) EligibleVolumes() []Volume {
	out := []Volume{}
	for _, v := range s.Volumes {
		if _, err := s.Select(v.UUID); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// A root mount may be serialized as ID, ID: or ID:/. Labels resolve only when
// unique across all partitions, so an unrelated disk can never be detached.
func (s Snapshot) rootVolumeID(target string) (string, bool) {
	identifier, suffix, hasColon := strings.Cut(target, ":")
	if hasColon && suffix != "" && suffix != "/" {
		return "", false
	}
	if identifier == "" || strings.ContainsAny(identifier, "/\\\r\n\x00") {
		return "", false
	}
	id, ok := s.identifiers[identifier]
	return id, ok && id != ""
}
