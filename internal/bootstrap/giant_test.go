package bootstrap

import (
	"context"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"strings"
	"testing"
)

// Firmware output captured from the affected model; the hardware serial is redacted.
const giantMedia = `media:
 name: FlashStorage
 bus: mtd
 ejectable: no
 removable: no
 state: ACTIVE
 manufacturer: Keenetic
 product: KN-2610
 serial: REDACTED
 initialize-supported:
 size: 68943872
 partition:
  id: Partition1
  uuid: 41C0000
  label: Storage
  fstype: ubifs
  check-supported: no
  format-supported:
  state: MOUNTED
  total: 57778176
  free: 57753600
  used-by:
media:
 name: Media0
 bus: usb
 ejectable: yes
 removable: yes
 usb:
 port: 1
 version: 3.00
 state: ACTIVE
 manufacturer: Kingston
 product: DataTraveler 111
 serial: REDACTED
 initialize-supported: ext4
 size: 30992891904
 partition:
  id: Partition1
  uuid: a48bca5d-5c3e-4a5f-a2fc-5087d910e6b7
  label: EXT4-NEOC9GHh
  fstype: ext4
  check-supported: yes
  format-supported: ext4
  format-supported: swap
  state: MOUNTED
  total: 30324928512
  free: 30322806784
  used-by: cifs
  used-by: opkg
`

func TestGiantAutomaticSMBSelectedLabelAndLateRuntimeCheck(t *testing.T) {
	ctx := context.Background()
	c := &fixtureCLI{version: "hw_id: KN-2610\narch: mips\nmodel: Giant\n", media: giantMedia, cifs: cifsRuntimeFixture, config: "opkg disk EXT4-NEOC9GHh:/\nopkg initrc \"\"\n"}
	snap, e := Inspect(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	if snap.Arch != catalog.MIPSel || len(snap.EligibleVolumes()) != 1 {
		t.Fatal("actual USB partition was not recognized")
	}
	v, e := snap.Select("")
	if e != nil || v.UUID != cifsUUID || v.Share != "EXT4-NEOC9GHh" || v.Free != 30322806784 {
		t.Fatalf("%+v %v", v, e)
	}
	store := &fixtureStore{}
	session := NewSession(c, store)
	plan, e := session.Prepare(ctx, "", "Fixture-password-2026!", "Fixture-password-2026!")
	if e != nil {
		t.Fatal(e)
	}
	if len(plan.Commands) != 3 || plan.Commands[0] != "no opkg disk" || plan.Commands[2] != "opkg disk "+cifsUUID+":/" {
		t.Fatal("same selected disk did not produce canonical reviewed trigger", plan.Commands)
	}
	session.download = func(context.Context, catalog.Artifact) ([]byte, error) {
		return []byte("fixture archive boundary"), nil
	}
	store.afterPublish = func() { c.cifs = strings.ReplaceAll(c.cifs, "active: yes", "active: no") }
	if e = session.Start(ctx, plan.ID, true, nil); e == nil || c.writes != 0 {
		t.Fatal("stale inactive SMB share allowed OPKG mutation", e, c.writes)
	}
}
