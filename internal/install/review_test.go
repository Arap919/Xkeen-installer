package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/router"
)

const reviewedInitFixture = "#!/bin/sh\nname_client=\"xray\"\nproxy_start() { :; }\nproxy_stop() { :; }\ncase \"$1\" in esac\n"

func bothProposal(t *testing.T, f *fakeRouter) (router.Snapshot, Selection, config.ConfigProposal) {
	t.Helper()
	s, e := router.Inspect(context.Background(), f)
	if e != nil {
		t.Fatal(e)
	}
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Mihomo, catalog.Xray}, ActiveCore: catalog.Mihomo}}
	p, e := config.Prepare(s, sel.Config, config.ProviderImport("https://example.test/private"))
	if e != nil {
		t.Fatal(e)
	}
	return s, sel, p
}
func reviewedFixtureLoader(ctx context.Context, a []catalog.Artifact) ([]payload, error) {
	out, e := fixtureLoader(ctx, a)
	for i := range out {
		if out[i].path == "/opt/sbin/.xkeen/02_install/07_install_register/04_register_init.sh" {
			out[i].data = []byte(reviewedInitFixture)
		}
	}
	return out, e
}
func installBothFixture(t *testing.T, clearConflicts bool) (*fakeRouter, Plan, Report) {
	t.Helper()
	f := fixture()
	delete(f.files, config.XrayPath)
	delete(f.files, "/opt/etc/init.d/S05xkeen")
	f.active = ""
	s, sel, proposal := bothProposal(t, f)
	if clearConflicts {
		proposal.Conflicts = nil
	}
	p, e := BuildPlan(s, sel, proposal)
	if e != nil {
		t.Fatal(e)
	}
	r, e := run(context.Background(), confirm(t, p), f, nil, reviewedFixtureLoader)
	if e != nil {
		t.Fatal(e)
	}
	return f, p, r
}
func pendingXray(values []string) bool {
	for _, v := range values {
		if strings.Contains(v, "Xray установлен как неактивное") {
			return true
		}
	}
	return false
}
func TestInstalledGeneratedXrayBaseCannotBeActivated(t *testing.T) {
	f, _, _ := installBothFixture(t, false)
	s, e := router.Inspect(context.Background(), f)
	if e != nil {
		t.Fatal(e)
	}
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Mihomo, catalog.Xray}, ActiveCore: catalog.Xray}}
	proposal, e := config.Prepare(s, sel.Config, config.Import{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = BuildPlan(s, sel, proposal); e == nil {
		t.Fatal("installed unconfigured Xray base accepted for activation")
	}
}
func TestInactiveBasePendingComesFromPrivateBytes(t *testing.T) {
	f, p, r := installBothFixture(t, true)
	if !pendingXray(p.Notes) || !pendingXray(r.Pending) {
		t.Error("clearing public conflicts removed backend pending state")
	}
	s, e := router.Inspect(context.Background(), f)
	if e != nil {
		t.Fatal(e)
	}
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Mihomo, catalog.Xray}}}
	proposal, e := config.Prepare(s, sel.Config, config.Import{})
	if e != nil {
		t.Fatal(e)
	}
	p, e = BuildPlan(s, sel, proposal)
	if e != nil {
		t.Fatal(e)
	}
	r, e = run(context.Background(), confirm(t, p), f, nil, reviewedFixtureLoader)
	if e != nil {
		t.Fatal(e)
	}
	if !pendingXray(p.Notes) || !pendingXray(r.Pending) {
		t.Error("fresh inspection lost installed inactive-base pending state")
	}
}
func TestCoreShadowRejectedBeforeMutation(t *testing.T) {
	for _, core := range []catalog.Component{catalog.Xray, catalog.Mihomo} {
		t.Run(string(core), func(t *testing.T) {
			f := fixture()
			var p Plan
			if core == catalog.Xray {
				p = planFor(t, f)
			} else {
				s, sel, proposal := bothProposal(t, f)
				var e error
				p, e = BuildPlan(s, sel, proposal)
				if e != nil {
					t.Fatal(e)
				}
			}
			f.files["/opt/bin/"+string(core)] = []byte("old-unverified-core")
			r, e := run(context.Background(), confirm(t, p), f, nil, reviewedFixtureLoader)
			if e == nil || f.writes != 0 || r.Complete {
				t.Fatalf("shadow core used or mutated router: err=%v writes=%d", e, f.writes)
			}
		})
	}
}
func TestExplicitSwitchPreservesInitMode(t *testing.T) {
	f := fixture()
	f.modes["/opt/etc/init.d/S05xkeen"] = 0750
	s, sel, proposal := bothProposal(t, f)
	p, e := BuildPlan(s, sel, proposal)
	if e != nil {
		t.Fatal(e)
	}
	r, e := run(context.Background(), confirm(t, p), f, nil, reviewedFixtureLoader)
	if e != nil {
		t.Fatal(e)
	}
	if !r.Complete || f.modes["/opt/etc/init.d/S05xkeen"] != 0750 {
		t.Fatalf("existing init mode changed to %04o", f.modes["/opt/etc/init.d/S05xkeen"])
	}
}
func TestServiceLaunchClosesInheritedStreamsAndPreservesStatus(t *testing.T) {
	if _, e := os.Stat("/bin/sh"); e != nil {
		t.Skip("POSIX shell fixture unavailable")
	}
	f := fixture()
	f.files["/opt/etc/init.d/S99xkeen-ui"] = []byte("#!/bin/sh\nPROCS=xkeen-ui\n. /opt/etc/init.d/rc.func\n")
	s, _ := router.Inspect(context.Background(), f)
	sel := Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}}, UI: true}
	proposal, _ := config.Prepare(s, sel.Config, config.Import{})
	p, e := BuildPlan(s, sel, proposal)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = run(context.Background(), confirm(t, p), f, nil, reviewedFixtureLoader); e != nil {
		t.Fatal(e)
	}
	script := filepath.Join(t.TempDir(), "init-fixture")
	if e = os.WriteFile(script, []byte("#!/bin/sh\nsleep 1 &\nexit ${EXIT_CODE:-0}\n"), 0700); e != nil {
		t.Fatal(e)
	}
	starts := 0
	for _, c := range f.commands {
		service := ""
		if strings.HasPrefix(c, "/opt/etc/init.d/S05xkeen start on") {
			service = "/opt/etc/init.d/S05xkeen"
		}
		if strings.HasPrefix(c, "/opt/etc/init.d/S99xkeen-ui start") {
			service = "/opt/etc/init.d/S99xkeen-ui"
		}
		if service == "" {
			continue
		}
		starts++
		launch := strings.Replace(c, service, quote(script), 1)
		for _, exitCode := range []string{"0", "7"} {
			cmd := exec.Command("/bin/sh", "-c", "EXIT_CODE="+exitCode+" "+launch)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			cmd.WaitDelay = 100 * time.Millisecond
			started := time.Now()
			e = cmd.Run()
			if exitCode == "0" && e != nil {
				t.Errorf("%s background child held output streams: %v", service, e)
			}
			if exitCode == "7" {
				var status *exec.ExitError
				if !errors.As(e, &status) || status.ExitCode() != 7 {
					t.Errorf("%s launch exit status lost: %v", service, e)
				}
			}
			if time.Since(started) > 400*time.Millisecond {
				t.Errorf("%s launch waited for background child", service)
			}
		}
	}
	if starts != 2 {
		t.Fatalf("tested %d launch commands", starts)
	}
}
