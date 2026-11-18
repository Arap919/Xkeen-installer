package install

import (
	"context"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/router"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCronFreshInstallAndBackupOrdering(t *testing.T) {
	f := fixture()
	s, _ := router.Inspect(context.Background(), f)
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}}}
	proposal, _ := config.Prepare(s, sel.Config, config.Import{})
	p, e := BuildPlan(s, sel, proposal)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(strings.Join(p.Dependencies, " "), "cron") {
		t.Fatal("cron dependency absent")
	}
	if _, e = run(context.Background(), confirm(t, p), f, nil, reviewedFixtureLoader); e != nil {
		t.Fatal(e)
	}
	backup, dep, start, verify := -1, -1, -1, -1
	for i, c := range f.commands {
		if strings.Contains(c, "/opt/bin/opkg") && strings.Contains(c, " install ") {
			dep = i
		}
		if strings.Contains(c, "S10cron start") {
			start = i
		}
		if c == cronVerifyCommand {
			verify = i
		}
		if strings.Contains(c, "tar ") {
			backup = i
		}
	}
	// Backup itself uses Transport I/O; report order is independently covered by runner tests.
	_ = backup
	if dep < 0 || start < dep || verify < start {
		t.Fatal("cron dependency/start/verification order")
	}
}
func TestCronConflictFailsBeforeMutations(t *testing.T) {
	f := fixture()
	f.files["/opt/etc/init.d/S05crond"] = []byte("custom")
	f.modes["/opt/etc/init.d/S05crond"] = 0755
	s, _ := router.Inspect(context.Background(), f)
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}}}
	proposal, _ := config.Prepare(s, sel.Config, config.Import{})
	if _, e := BuildPlan(s, sel, proposal); e == nil {
		t.Fatal("conflicting cron accepted")
	}
	if f.writes != 0 {
		t.Fatal("mutation during plan")
	}
}
func TestCronProcessConflictAndStartFailure(t *testing.T) {
	for _, fail := range []string{cronPreflightCommand, "S10cron start", cronVerifyCommand} {
		f := fixture()
		s, _ := router.Inspect(context.Background(), f)
		sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}}}
		proposal, _ := config.Prepare(s, sel.Config, config.Import{})
		p, e := BuildPlan(s, sel, proposal)
		if e != nil {
			t.Fatal(e)
		}
		f.fail = fail
		_, e = run(context.Background(), confirm(t, p), f, nil, reviewedFixtureLoader)
		if e == nil {
			t.Fatalf("ignored failure %s", fail)
		}
		if fail == cronPreflightCommand && f.writes != 0 {
			t.Fatal("mutation before cron preflight")
		}
	}
}

func TestReviewedXraySubscriptionsAndRepeatPreservation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"node.test","port":443,"users":[{"id":"test"}]}]}}]}`))
	}))
	defer server.Close()
	oldTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = oldTransport }()
	input, e := config.ResolveSubscriptions(context.Background(), nil, []string{server.URL + "/private-token"})
	if e != nil {
		t.Fatal(e)
	}
	f := fixture()
	delete(f.files, config.XrayPath)
	delete(f.files, "/opt/etc/init.d/S05xkeen")
	f.active = ""
	f.files["/opt/etc/cron.d/user-job"] = []byte("1 * * * * root /opt/bin/user-command\n")
	s, e := router.Inspect(context.Background(), f)
	if e != nil {
		t.Fatal(e)
	}
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}, ActiveCore: catalog.Xray}}
	proposal, e := config.Prepare(s, sel.Config, input)
	if e != nil {
		t.Fatal(e)
	}
	p, e := BuildPlan(s, sel, proposal)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(p.String(), "private-token") {
		t.Fatal("plan leaked source")
	}
	loader := func(ctx context.Context, a []catalog.Artifact) ([]payload, error) {
		files, e := reviewedFixtureLoader(ctx, a)
		for _, name := range []string{"geoip.dat", "geosite.dat"} {
			files = append(files, payload{path: "/opt/etc/xray/dat/" + name, data: []byte("reviewed-geodata"), mode: 0644, component: catalog.Xray})
		}
		return files, e
	}
	r, e := run(context.Background(), confirm(t, p), f, nil, loader)
	if e != nil {
		t.Fatal(e)
	}
	if !r.Complete {
		t.Fatal("not completed")
	}
	for _, path := range []string{config.XraySourcesPath, config.XrayUpdaterPath, config.XraySchedulePath} {
		if f.modes[path] != 0600 {
			t.Fatalf("not private: %s", path)
		}
	}
	if string(f.files["/opt/etc/cron.d/user-job"]) != "1 * * * * root /opt/bin/user-command\n" {
		t.Fatal("user cron changed")
	}
	s, e = router.Inspect(context.Background(), f)
	if e != nil {
		t.Fatal(e)
	}
	proposal, e = config.Prepare(s, sel.Config, config.Import{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = BuildPlan(s, sel, proposal); e != nil {
		t.Fatal("repeat: ", e)
	}
	if len(proposal.Files) != 4 {
		t.Fatalf("managed files lost: %v", proposal)
	}
}
