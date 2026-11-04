package install

import (
	"bytes"
	"context"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/router"
	localtls "github.com/Arap919/xkeen-installer/internal/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tlsPlan(t *testing.T, f *fakeRouter) Plan {
	t.Helper()
	s, e := router.Inspect(context.Background(), f)
	if e != nil {
		t.Fatal(e)
	}
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}}, UI: true}
	c, e := config.Prepare(s, sel.Config, config.Import{})
	if e != nil {
		t.Fatal(e)
	}
	tls, e := localtls.PrepareTLS("192.168.1.1", localtls.TLSState{})
	if e != nil {
		t.Fatal(e)
	}
	if e = tls.Save(filepath.Join(t.TempDir(), "ca")); e != nil {
		t.Fatal(e)
	}
	p, e := BuildPlanWithTLS(s, sel, c, tls)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestNewUIWithTLSAndBackupGate(t *testing.T) {
	f := fixture()
	p := tlsPlan(t, f)
	var steps []string
	r, e := run(context.Background(), confirm(t, p), f, func(e Event) {
		if e.Status == "completed" {
			steps = append(steps, e.Step)
		}
	}, fixtureLoader)
	if e != nil {
		t.Fatal(e)
	}
	if !r.Complete || !r.Backup.Verified() {
		t.Fatal(r)
	}
	init := string(f.files["/opt/etc/init.d/S99xkeen-ui"])
	if !strings.Contains(init, "ENABLED=yes") || !strings.Contains(init, "--tls-cert /opt/etc/nginx/ssl/server.crt") {
		t.Fatal(init)
	}
	if f.modes["/opt/etc/nginx/ssl/server.key"] != 0600 {
		t.Fatal("key mode")
	}
	if strings.Index(strings.Join(steps, ","), "backup") > strings.Index(strings.Join(steps, ","), "tls") {
		t.Fatal(steps)
	}
	for _, b := range f.files {
		if bytes.Contains(b, []byte("BEGIN PRIVATE KEY")) && bytes.Contains(b, []byte("local CA")) {
			t.Fatal("CA key deployed")
		}
	}
	if len(r.Pending) == 0 {
		t.Fatal("HTTPS/trust verification missing")
	}
}
func TestTLSCancellationPreservesNoUIWrites(t *testing.T) {
	f := fixture()
	p := tlsPlan(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, e := run(ctx, confirm(t, p), f, func(e Event) {
		if e.Step == "backup" && e.Status == "completed" {
			cancel()
		}
	}, fixtureLoader)
	if e == nil {
		t.Fatal("cancel ignored")
	}
	if _, ok := f.files["/opt/etc/nginx/ssl/server.key"]; ok {
		t.Fatal("TLS written after cancel")
	}
}

func TestExistingValidTLSPreservedExactlyAndNoKeyPreview(t *testing.T) {
	f := fixture()
	tls, e := localtls.PrepareTLS("router.test", localtls.TLSState{})
	if e != nil {
		t.Fatal(e)
	}
	cert, key, _ := tls.ServerPair()
	f.files[serverCertPath] = cert
	f.files[serverKeyPath] = key
	f.files["/opt/etc/init.d/S99xkeen-ui"] = newUIInit(true)
	s, e := router.Inspect(context.Background(), f)
	if e != nil {
		t.Fatal(e)
	}
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}}, UI: true}
	proposal, _ := config.Prepare(s, sel.Config, config.Import{})
	preserved, e := localtls.PrepareTLS("router.test", localtls.ExistingTLS(cert, key, tls.PublicCA()))
	if e != nil {
		t.Fatal(e)
	}
	p, e := BuildPlanWithTLS(s, sel, proposal, preserved)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(p.String(), "PRIVATE KEY") {
		t.Fatal("key preview")
	}
	r, e := run(context.Background(), confirm(t, p), f, nil, fixtureLoader)
	if e != nil || !r.Complete {
		t.Fatal(r, e)
	}
	if !bytes.Equal(f.files[serverCertPath], cert) || !bytes.Equal(f.files[serverKeyPath], key) {
		t.Fatal("TLS replaced")
	}
	for path, b := range f.files {
		if bytes.Contains(b, []byte("BEGIN PRIVATE KEY")) && !bytes.Equal(b, key) {
			t.Fatal("non-server key in router payload", path)
		}
	}
}

func TestGeneratedCARequiresPrivatePersistence(t *testing.T) {
	f := fixture()
	s, _ := router.Inspect(context.Background(), f)
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}}, UI: true}
	proposal, _ := config.Prepare(s, sel.Config, config.Import{})
	tls, _ := localtls.PrepareTLS("router.test", localtls.TLSState{})
	if _, e := BuildPlanWithTLS(s, sel, proposal, tls); e == nil {
		t.Fatal("unsaved CA accepted")
	}
	dir := filepath.Join(t.TempDir(), "ca")
	if e := tls.Save(dir); e != nil {
		t.Fatal(e)
	}
	storedPlan, e := BuildPlanWithTLS(s, sel, proposal, tls)
	if e != nil {
		t.Fatal(e)
	}
	os.Remove(filepath.Join(dir, "ca.key"))
	if _, e = run(context.Background(), confirm(t, storedPlan), f, nil, fixtureLoader); e == nil || f.writes != 0 {
		t.Fatal("lost local authority did not stop before router writes", e, f.writes)
	}
	if _, e := BuildPlanWithTLS(s, sel, proposal, tls); e == nil {
		t.Fatal("lost CA key accepted")
	}
}

func TestExistingExtraKeyPEMRejectedWithoutOverwrite(t *testing.T) {
	f := fixture()
	original, _ := localtls.PrepareTLS("router.test", localtls.TLSState{})
	cert, key, _ := original.ServerPair()
	extra, _ := localtls.PrepareTLS("other.test", localtls.TLSState{})
	_, extraKey, _ := extra.ServerPair()
	unsafe := append(append([]byte(nil), key...), extraKey...)
	f.files[serverCertPath] = cert
	f.files[serverKeyPath] = unsafe
	f.files["/opt/etc/init.d/S99xkeen-ui"] = newUIInit(true)
	if _, e := localtls.PrepareTLS("router.test", localtls.ExistingTLS(cert, unsafe, original.PublicCA())); e == nil {
		t.Fatal("extra private key accepted")
	}
	safe, _ := localtls.PrepareTLS("router.test", localtls.ExistingTLS(cert, key, nil))
	snapshot, e := router.Inspect(context.Background(), f)
	if e != nil {
		t.Fatal(e)
	}
	selection := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}}, UI: true}
	proposal, _ := config.Prepare(snapshot, selection.Config, config.Import{})
	if _, e = BuildPlanWithTLS(snapshot, selection, proposal, safe); e == nil {
		t.Fatal("invalid existing pair silently replaced")
	}
	if f.writes != 0 || !bytes.Equal(f.files[serverKeyPath], unsafe) || !bytes.Equal(f.files[serverCertPath], cert) {
		t.Fatal("existing TLS overwritten")
	}
}
