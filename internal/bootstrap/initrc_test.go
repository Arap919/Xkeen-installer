package bootstrap

import (
	"context"
	"strings"
	"testing"
)

const bootstrapMedia = "media:\n name: Media0\n serial: SERIAL1\n port: 1\n partition:\n  uuid: 12345678-abcd-1234-abcd-123456789abc\n  label: ENTWARE\n  fstype: ext4\n  state: MOUNTED\n  free: 900000000\n"

func TestBootstrapReviewsRequiredTemporaryInitrcAndFinalGate(t *testing.T) {
	c := &fixtureCLI{media: bootstrapMedia, config: "cifs share ENTWARE 12345678-abcd-1234-abcd-123456789abc:/"}
	s := NewSession(c, &fixtureStore{})
	p, e := s.Prepare(context.Background(), "", "Fixture-password-2026!", "Fixture-password-2026!")
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Commands) != 2 || p.Commands[0] != "opkg initrc /opt/etc/init.d" || p.Commands[1] != "opkg disk 12345678-abcd-1234-abcd-123456789abc:/" {
		t.Fatal(p.Commands)
	}
	if e = FinalInitrc(context.Background(), c); e == nil {
		t.Fatal("missing final Initrc accepted")
	}
	c.config += "\nopkg initrc /opt/etc/init.d"
	if e = FinalInitrc(context.Background(), c); e == nil {
		t.Fatal("temporary Initrc accepted as final")
	}
	c.config = strings.ReplaceAll(c.config, "opkg initrc /opt/etc/init.d", "opkg initrc /opt/etc/init.d/rc.unslung")
	if e = FinalInitrc(context.Background(), c); e != nil {
		t.Fatal(e)
	}
}
