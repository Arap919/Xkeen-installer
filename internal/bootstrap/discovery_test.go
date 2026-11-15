package bootstrap

import (
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"strings"
	"testing"
)

func TestExactHardwareEndian(t *testing.T) {
	for _, tc := range []struct {
		id, cpu string
		want    catalog.RouterArch
	}{{"KN-2410", "mips", catalog.MIPS}, {"NC-1810", "mips", catalog.MIPSel}, {"KN-1812", "aarch64", catalog.ARM64}} {
		got, err := Architecture(tc.id, tc.cpu)
		if err != nil || got != tc.want {
			t.Fatalf("%s: %s %v", tc.id, got, err)
		}
	}
	for _, tc := range [][2]string{{"KN-9999", "mips"}, {"KN-2410", "aarch64"}, {"KN-1812", "mips"}} {
		if _, err := Architecture(tc[0], tc[1]); err == nil {
			t.Fatalf("accepted ambiguous hardware %v", tc)
		}
	}
}

const mediaFixture = `media:
 name: USB
 partition:
  uuid: 12345678-abcd-1234-abcd-123456789abc
  label: ENTWARE
  fstype: EXT4
  state: MOUNTED
  total: 1000000000
  free: 900000000
 partition:
  uuid: 99999999-abcd
  label: DATA
  fstype: NTFS
  state: MOUNTED
  total: 1000000000
  free: 900000000
`

func TestDiscoveryRequiresExplicitRootShareAndSelectedVolume(t *testing.T) {
	version := "hw_id: KN-2410\nmodel: Keenetic Ultra\narch: mips\n"
	s, err := Parse(version, mediaFixture, "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/\nopkg initrc /opt/etc/init.d/rc.unslung\n")
	if err != nil || len(s.Volumes) != 1 || s.Arch != catalog.MIPS {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err = s.Select(""); err != nil {
		t.Fatal(err)
	}
	for _, config := range []string{"cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/Video", "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/\nopkg disk other-uuid:/", "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/\nopkg initrc /opt/custom.sh"} {
		v, e := Parse(version, mediaFixture, config)
		if e == nil {
			_, e = v.Select("")
		}
		if e == nil {
			t.Fatalf("accepted unsafe settings %q", config)
		}
	}
	second := "media:\n name: USB2\n partition:\n  uuid: 22222222-abcd-1234-abcd-123456789abc\n  label: SECOND\n  fstype: EXT4\n  state: MOUNTED\n  free: 900000000\n"
	two, e := Parse(version, mediaFixture+second, "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/\ncifs share SECOND 22222222-abcd-1234-abcd-123456789abc:/")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = two.Select(""); e == nil {
		t.Fatal("multiple volumes auto-selected")
	}
	if _, e = two.Select("22222222-abcd-1234-abcd-123456789abc"); e != nil {
		t.Fatal(e)
	}
	if _, e = Parse(version, mediaFixture+strings.ReplaceAll(second, "22222222-abcd-1234-abcd-123456789abc", "12345678-abcd-1234-abcd-123456789abc"), ""); e == nil {
		t.Fatal("duplicate UUID accepted")
	}
	low := strings.ReplaceAll(mediaFixture, "900000000", "1000")
	v, e := Parse(version, low, "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = v.Select(""); e == nil {
		t.Fatal("insufficient space accepted")
	}
}
func TestGroupedOpkgCannotHideForeignDiskOrCustomInit(t *testing.T) {
	for _, setting := range []string{" disk other-uuid:/", " initrc /opt/custom.sh"} {
		s, e := Parse("hw_id: KN-2410\narch: mips\n", mediaFixture, "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/\nopkg\n"+setting+"\n!\n")
		if e == nil {
			_, e = s.Select("")
		}
		if e == nil {
			t.Fatal("grouped OPKG unsafe settings ignored")
		}
	}
}
func TestDocumentedCifsShareDescriptionAndGroupForms(t *testing.T) {
	for _, config := range []string{"cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/ \"Entware disk\"", "cifs\n share \"Entware disk\" 12345678-abcd-1234-abcd-123456789abc:/\n!\n"} {
		s, e := Parse("hw_id: KN-2410\narch: mips\n", mediaFixture, config)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Select(""); e != nil {
			t.Fatalf("documented CIFS command rejected: %v", e)
		}
	}
}
func TestMalformedExt4UUIDNeverProducesPlanTarget(t *testing.T) {
	malformed := "media:\n name: USB\n partition:\n  uuid: short-uuid\n  fstype: ext4\n  state: MOUNTED\n  free: 900000000\n"
	s, e := Parse("hw_id: KN-2410\narch: mips\n", malformed, "cifs share ENTWARE short-uuid:/")
	if e == nil {
		_, e = s.Select("")
	}
	if e == nil {
		t.Fatal("noncanonical EXT4 UUID accepted")
	}
}

func TestRootMountFormsAndSelectedOPKGLabel(t *testing.T) {
	const uuid = "12345678-abcd-1234-abcd-123456789abc"
	for _, disk := range []string{uuid, uuid + ":", uuid + ":/", "ENTWARE", "ENTWARE:", "ENTWARE:/"} {
		s, e := Parse("hw_id: KN-2610\narch: mips\n", mediaFixture, "cifs share ENTWARE "+uuid+":\nopkg disk "+disk+"\n")
		if e != nil {
			t.Fatalf("%s: %v", disk, e)
		}
		v, e := s.Select("")
		if e != nil || v.UUID != uuid || v.Share != "ENTWARE" {
			t.Fatalf("same selected disk %s rejected: %v", disk, e)
		}
	}
	for _, disk := range []string{"DATA:/", "other-uuid:/", "ENTWARE:/subdir"} {
		s, e := Parse("hw_id: KN-2610\narch: mips\n", mediaFixture, "cifs share ENTWARE "+uuid+":/\nopkg disk "+disk+"\n")
		if e == nil {
			_, e = s.Select("")
		}
		if e == nil {
			t.Fatalf("foreign or partial OPKG disk accepted: %s", disk)
		}
	}
	// Labels must be unique across all discovered partitions, including non-EXT4.
	duplicate := strings.Replace(mediaFixture, "label: DATA", "label: ENTWARE", 1)
	s, e := Parse("hw_id: KN-2610\narch: mips\n", duplicate, "cifs share ENTWARE "+uuid+":/\nopkg disk ENTWARE:/\n")
	if e == nil {
		_, e = s.Select("")
	}
	if e == nil {
		t.Fatal("ambiguous OPKG label accepted")
	}
}
