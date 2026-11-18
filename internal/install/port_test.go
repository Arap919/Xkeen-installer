package install

import (
	"context"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/router"
	"strings"
	"testing"
)

func TestUIPortPlanRejectsForeignListeners(t *testing.T) {
	for _, listener := range []string{
		"tcp 0 0 0.0.0.0:1000 0.0.0.0:* LISTEN 77/other\n",
		"tcp6 0 0 :::1000 :::* LISTEN 77/other\n",
		"tcp 0 0 0.0.0.0:1000 0.0.0.0:* LISTEN -\n",
	} {
		f := fixture()
		f.listeners = listener
		s, err := router.Inspect(context.Background(), f)
		if err != nil {
			t.Fatal(err)
		}
		sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}, ActiveCore: catalog.Xray}, UI: true}
		proposal, _ := config.Prepare(s, sel.Config, config.Import{})
		if _, err := BuildPlan(s, sel, proposal); err == nil {
			t.Fatalf("accepted occupied port: %s", listener)
		}
		if f.writes != 0 {
			t.Fatal("plan mutated router")
		}
	}
}

func TestUIPortAppearingAfterPlanStopsBeforeBackup(t *testing.T) {
	f := fixture()
	p := tlsPlan(t, f)
	f.listeners = "tcp6 0 0 :::1000 :::* LISTEN 77/other\n"
	_, err := run(context.Background(), confirm(t, p), f, nil, fixtureLoader)
	if err == nil || f.writes != 0 {
		t.Fatalf("late conflict: err=%v writes=%d", err, f.writes)
	}
	for _, cmd := range f.commands {
		if strings.Contains(cmd, "/opt/bin/opkg") && strings.Contains(cmd, " update") {
			t.Fatal("package mutation before gate")
		}
	}
}

func TestExistingUIOwnsItsConfiguredPort(t *testing.T) {
	f := fixture()
	f.files["/opt/etc/init.d/S99xkeen-ui"] = []byte(strings.Replace(string(newUIInit(true)), "-p 1000", "-p 4443", 1))
	f.listeners = "tcp6 0 0 :::4443 :::* LISTEN 42/xkeen-ui\n"
	p := tlsPlan(t, f)
	if !strings.Contains(p.String(), "4443") {
		t.Fatal("planned port absent from review")
	}
	f.listeners = "tcp6 0 0 :::4443 :::* LISTEN 77/xkeen-ui\n"
	_, err := run(context.Background(), confirm(t, p), f, nil, fixtureLoader)
	if err == nil || f.writes != 0 {
		t.Fatalf("name spoof accepted: %v writes=%d", err, f.writes)
	}
}
