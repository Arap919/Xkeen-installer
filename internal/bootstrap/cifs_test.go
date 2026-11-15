package bootstrap

import (
	"errors"
	"strings"
	"testing"
)

const cifsUUID = "a48bca5d-5c3e-4a5f-a2fc-5087d910e6b7"
const cifsRuntimeFixture = `enabled: yes
automount: yes
permissive: yes
map-hidden: no
share:
 mount: 29f680ff-11d2-4b34-6f04-1f6fe0129d88:
 label: NEW VOLUME
 description:
 active: no
share:
 mount: 919c87eb-1084-463b-8ed3-f750095b2ac5:
 label: Untitled
 description:
 active: no
share:
 mount: a48bca5d-5c3e-4a5f-a2fc-5087d910e6b7:
 label: EXT4-NEOC9GHh
 description:
 active: yes
`

func cifsSnapshot(t *testing.T) Snapshot {
	t.Helper()
	s, err := Parse("hw_id: KN-2410\narch: mips\n", strings.ReplaceAll(mediaFixture, "12345678-abcd-1234-abcd-123456789abc", cifsUUID), "cifs share STATIC "+cifsUUID+":/")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRuntimeCIFSActualAutomaticRoot(t *testing.T) {
	original := cifsSnapshot(t)
	s, err := withCIFS(original, cifsRuntimeFixture)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Select("")
	if err != nil || v.UUID != cifsUUID || v.Share != "EXT4-NEOC9GHh" {
		t.Fatalf("%+v %v", v, err)
	}
	if original.Volumes[0].Share != "STATIC" {
		t.Fatal("runtime binding mutated original snapshot")
	}
}

func TestRuntimeCIFSRequiresFreshUniqueActiveRoot(t *testing.T) {
	for name, output := range map[string]string{
		"disabled":                 strings.Replace(cifsRuntimeFixture, "enabled: yes", "enabled: no", 1),
		"inactive":                 strings.ReplaceAll(cifsRuntimeFixture, "active: yes", "active: no"),
		"subfolder":                strings.ReplaceAll(cifsRuntimeFixture, cifsUUID+":", cifsUUID+":/folder"),
		"unknown":                  strings.ReplaceAll(cifsRuntimeFixture, cifsUUID, "11111111-1111-1111-1111-111111111111"),
		"duplicate root":           cifsRuntimeFixture + "share:\n mount: " + cifsUUID + ":/\n label: SECOND\n active: yes\n",
		"same name different root": cifsRuntimeFixture + "share:\n mount: 99999999-abcd:\n label: EXT4-NEOC9GHh\n active: yes\n",
		"same name subfolder":      cifsRuntimeFixture + "share:\n mount: " + cifsUUID + ":/folder\n label: ext4-neoc9ghh\n active: yes\n",
	} {
		t.Run(name, func(t *testing.T) {
			s, err := withCIFS(cifsSnapshot(t), output)
			if err == nil && len(s.EligibleVolumes()) != 0 {
				t.Fatalf("unsafe runtime accepted: %+v", s.Volumes)
			}
		})
	}
}

func TestRuntimeCIFSRejectsMalformedEvidence(t *testing.T) {
	for _, output := range []string{
		"", "enabled: maybe\n", "enabled: yes\nenabled: yes\n",
		strings.Replace(cifsRuntimeFixture, "enabled: yes\n", "", 1),
		strings.Replace(cifsRuntimeFixture, " active: yes\n", "", 1),
		strings.Replace(cifsRuntimeFixture, " active: yes", " active: invalid", 1),
		strings.Replace(cifsRuntimeFixture, " label: EXT4-NEOC9GHh\n", "", 1),
		strings.Replace(cifsRuntimeFixture, " mount: "+cifsUUID+":\n", "", 1),
		strings.Replace(cifsRuntimeFixture, " mount: "+cifsUUID+":", " mount:", 1),
		strings.Replace(cifsRuntimeFixture, " label: EXT4-NEOC9GHh", " label: invalid/share", 1),
		cifsRuntimeFixture + " label: SECOND\n",
		cifsRuntimeFixture + " mount: " + cifsUUID + ":\n",
		cifsRuntimeFixture + " active: yes\n",
	} {
		s, err := withCIFS(cifsSnapshot(t), output)
		if !errors.Is(err, ErrUnsafe) || len(s.EligibleVolumes()) != 0 {
			t.Fatalf("malformed evidence accepted: %+v %v", s.Volumes, err)
		}
	}
}

func TestRuntimeCIFSRootFormsAndLabel(t *testing.T) {
	for _, target := range []string{cifsUUID, cifsUUID + ":", cifsUUID + ":/", "ENTWARE:", "ENTWARE:/"} {
		s, err := withCIFS(cifsSnapshot(t), "enabled: yes\nshare:\n mount: "+target+"\n label: Exact SMB Name\n active: yes\n")
		if err != nil || len(s.Volumes) != 1 || s.Volumes[0].Share != "Exact SMB Name" {
			t.Fatalf("%q: %+v %v", target, s.Volumes, err)
		}
	}
}

func TestRuntimeCIFSKnownOptionalFields(t *testing.T) {
	s, err := withCIFS(cifsSnapshot(t), "master: no\n"+strings.ReplaceAll(cifsRuntimeFixture, " description:", " description: USB disk"))
	if err != nil || s.Volumes[0].Share != "EXT4-NEOC9GHh" {
		t.Fatalf("documented optional fields rejected: %+v %v", s.Volumes, err)
	}
	for _, output := range []string{
		"master: maybe\n" + cifsRuntimeFixture,
		"master: no\nmaster: no\n" + cifsRuntimeFixture,
		cifsRuntimeFixture + " description: duplicate\n",
	} {
		if _, err := withCIFS(cifsSnapshot(t), output); !errors.Is(err, ErrUnsafe) {
			t.Fatal("invalid or repeated optional evidence accepted")
		}
	}
}

func TestRuntimeCIFSAcceptsOnlyExpectedInitialCommandEcho(t *testing.T) {
	for _, echo := range []string{"show cifs\n", " show cifs\r\n", "(config)> show cifs\r\n"} {
		s, e := withCIFS(cifsSnapshot(t), echo+cifsRuntimeFixture)
		if e != nil {
			t.Fatalf("interactive command echo rejected: %v", e)
		}
		v, e := s.Select("")
		if e != nil || v.Share != "EXT4-NEOC9GHh" {
			t.Fatal("actual active root missing", e)
		}
	}
	for _, prefix := range []string{"unknown text\n", "show running-config\n", "show cifs\nshow cifs\n"} {
		_, e := withCIFS(cifsSnapshot(t), prefix+cifsRuntimeFixture)
		if e == nil {
			t.Fatal("unexpected terminal text accepted")
		}
	}
}

func TestCIFSParserDiagnosticsAreStructuredAndRedacted(t *testing.T) {
	cases := []struct {
		input, reason, field string
		line                 int
	}{
		{"private-password\n", "TEXT", "none", 1},
		{"enabled: yes\nprivate-password: private-value\n", "UNKNOWN_FIELD", "unknown", 2},
		{"enabled: yes\nenabled: yes\n", "DUPLICATE", "enabled", 2},
		{"enabled: private-value\n", "VALUE", "enabled", 1},
	}
	for _, tc := range cases {
		_, err := withCIFS(cifsSnapshot(t), tc.input)
		var detail *CIFSParseError
		if !errors.As(err, &detail) || detail.Reason != tc.reason || detail.Line != tc.line {
			t.Fatalf("missing safe diagnostic: %v", err)
		}
		got := detail.Diagnostic()
		if !strings.HasSuffix(got, "/"+tc.field) || strings.Contains(got, "private") || strings.Contains(err.Error(), "private") {
			t.Fatal("unsafe diagnostic", got)
		}
	}
	got := (&CIFSParseError{Reason: "private-password", Field: "private-value", Line: -1}).Diagnostic()
	if strings.Contains(got, "private") {
		t.Fatal("arbitrary diagnostic fields exposed", got)
	}
}
