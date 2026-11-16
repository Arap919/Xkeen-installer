package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/install"
	"github.com/Arap919/xkeen-installer/internal/router"
	"github.com/Arap919/xkeen-installer/internal/verify"
)

func testApp() *App {
	a := newApp()
	a.snapshotID = "inspection"
	a.inspectedAt = time.Now()
	a.transport = &testTransport{}
	a.plan = install.Plan{ID: "plan"}
	a.planSnapshot = "inspection"
	a.confirm = func(p install.Plan, id string) (install.Plan, error) {
		if id != p.ID {
			return install.Plan{}, errors.New("unconfirmed")
		}
		return p, nil
	}
	a.emit = func(Progress) {}
	return a
}

func TestInspectionFailuresAreActionableAndRedacted(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.New("ssh: handshake failed: ssh: unable to authenticate, password=private"), "[SSH_AUTH]"},
		{context.DeadlineExceeded, "[SSH_TIMEOUT]"},
		{errors.New("private transport output"), "[SSH_CONNECT]"},
	} {
		got := connectionFailure(tc.err).Error()
		if !strings.Contains(got, tc.want) || strings.Contains(got, "private") {
			t.Fatal(got)
		}
	}
	if got := inspectionFailure(router.ErrNotPOSIXShell).Error(); !strings.Contains(got, "[SSH_SHELL]") {
		t.Fatal(got)
	}
	if got := inspectionFailure(router.ErrUnsupportedCPU).Error(); !strings.Contains(got, "[SSH_ARCH]") {
		t.Fatal(got)
	}
	if got := inspectionFailure(errors.New("password=private")).Error(); !strings.Contains(got, "[SSH_INSPECT]") || strings.Contains(got, "private") {
		t.Fatal(got)
	}
}

func TestPlanRequiresCurrentInspection(t *testing.T) {
	a := testApp()
	if _, err := a.PreparePlan(PlanRequest{InspectionID: "older"}); err == nil {
		t.Fatal("stale inspection accepted")
	}
	a.inspectedAt = time.Now().Add(-10 * time.Minute)
	if _, err := a.PreparePlan(PlanRequest{InspectionID: "inspection"}); err == nil {
		t.Fatal("expired inspection accepted")
	}
}

func TestStartRequiresExplicitConfirmation(t *testing.T) {
	a := testApp()
	var calls atomic.Int32
	a.run = func(context.Context, install.Plan, router.Transport, func(install.Event)) (install.Report, error) {
		calls.Add(1)
		return install.Report{}, nil
	}
	if err := a.StartInstall("plan"); err == nil {
		t.Fatal("unconfirmed plan started")
	}
	if calls.Load() != 0 {
		t.Fatal("runner invoked")
	}
}

func TestDoubleStartAndCancelRequireReinspection(t *testing.T) {
	a := testApp()
	entered, exited := make(chan struct{}), make(chan struct{})
	a.run = func(ctx context.Context, _ install.Plan, _ router.Transport, _ func(install.Event)) (install.Report, error) {
		close(entered)
		<-ctx.Done()
		close(exited)
		return install.Report{ReinspectRequired: true}, ctx.Err()
	}
	if err := a.ConfirmPlan("plan"); err != nil {
		t.Fatal(err)
	}
	if err := a.StartInstall("plan"); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := a.StartInstall("plan"); err == nil {
		t.Fatal("second runner started")
	}
	a.CancelInstall()
	<-exited
	deadline := time.After(time.Second)
	for {
		a.mu.Lock()
		busy := a.busy
		a.mu.Unlock()
		if !busy {
			break
		}
		select {
		case <-deadline:
			t.Fatal("runner did not finish")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if _, err := a.PreparePlan(PlanRequest{InspectionID: "inspection"}); err == nil {
		t.Fatal("cancelled inspection reused")
	}
	if err := a.StartInstall("plan"); err == nil {
		t.Fatal("consumed plan reused")
	}
}

func TestReportAndCredentialsAreRedacted(t *testing.T) {
	a := testApp()
	proposal, err := config.Prepare(router.Snapshot{}, config.Selection{Cores: []catalog.Component{catalog.Mihomo}, ActiveCore: catalog.Mihomo}, config.ProviderImport("https://example.com/private-sentinel"))
	if err != nil {
		t.Fatal(err)
	}
	a.proposal = proposal
	a.result = ResultView{Status: "partial", Message: "Установка остановлена; повторите проверку"}
	raw, err := a.ExportRedactedReport()
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"password", "PRIVATE KEY", "VerificationFiles", "contents", "providerURL"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("report exposes %s", forbidden)
		}
	}
	b, _ := json.Marshal(a.planView())
	if strings.Contains(string(b), "private-sentinel") {
		t.Fatal("subscription URL exposed in plan DTO")
	}
	if strings.Contains(string(b), "private") {
		t.Fatal("private plan exposed")
	}
	if strings.Contains((ConnectionRequest{Password: "sentinel"}).String(), "sentinel") {
		t.Fatal("credentials formatted")
	}
}

type testTransport struct{ router.Transport }

func TestConflictDTOUsesRussianExplanationAndKeepsOnlyTechnicalAddition(t *testing.T) {
	a := testApp()
	a.proposal.Conflicts = []config.Conflict{{Path: config.MihomoPath, Reason: "Import would replace existing configuration; resolve manually.", NecessaryAddition: ""}}
	view := a.planView()
	if len(view.Conflicts) != 1 || !strings.Contains(view.Conflicts[0].Reason, "существующую конфигурацию") {
		t.Fatal("English conflict text exposed to UI")
	}
}

func TestVerifiedPanelAddressUsesActualPort(t *testing.T) {
	if got := verifiedPanelAddress("192.0.2.1", []byte("ARGS=\"-p 2050 --tls-cert /opt/etc/nginx/ssl/server.crt --tls-key /opt/etc/nginx/ssl/server.key\"\n")); got != "https://192.0.2.1:2050" {
		t.Fatalf("wrong actual panel URL: %q", got)
	}
	if got := verifiedPanelAddress("192.0.2.1", []byte("ARGS=\"-p invalid\"\n")); got != "" {
		t.Fatal("invalid port exposed")
	}
}

func TestOwnedTLSIsReloadedWithoutReplacingCA(t *testing.T) {
	base := filepath.Join(t.TempDir(), "owned")
	first, dir, err := prepareTLSStore("192.0.2.1", nil, nil, base)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, ok := first.ServerPair()
	if !ok {
		t.Fatal("no server pair")
	}
	second, reused, err := prepareTLSStore("192.0.2.1", cert, key, base)
	if err != nil {
		t.Fatal(err)
	}
	if dir != reused || !second.MatchesExisting(cert, key) || string(first.PublicCA()) != string(second.PublicCA()) {
		t.Fatal("owned TLS not reused")
	}
	if second.ReadyForDeployment() != nil {
		t.Fatal("reloaded CA not private and durable")
	}
}

func TestHostKeyReplacementAndImplicitTrustAreBlocked(t *testing.T) {
	a := testApp()
	a.hostKeys["router:22"] = "known"
	a.pendingHost = &HostKeyView{Kind: "changed", Address: "router:22", Fingerprint: "new", Expected: "known"}
	if a.ConfirmHostKey("router:22", "new") == nil {
		t.Fatal("changed key accepted")
	}
	if a.hostKeys["router:22"] != "known" {
		t.Fatal("known key replaced")
	}
	if _, err := a.ApplyTrust("unknown", true); err == nil {
		t.Fatal("unreviewed trust action accepted")
	}
}

func TestPreparePlanPreservesSubscriptionDiagnostic(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		a := testApp()
		r := PlanRequest{InspectionID: "inspection", Cores: []string{"mihomo"}, ActiveCore: "mihomo", MihomoProviderURLs: []string{"http://private.test/secret"}}
		if legacy {
			r.ProviderURL = r.MihomoProviderURLs[0]
			r.MihomoProviderURLs = nil
		}
		_, err := a.PreparePlan(r)
		if err == nil || err.Error() != "[SUBSCRIPTION/MIHOMO/URL/HTTP/1/0]" {
			t.Fatal(err)
		}
	}
}

func TestPlanInputDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		r    PlanRequest
		want string
	}{
		{PlanRequest{ImportText: strings.Repeat("a", config.MaxImportBytes+1)}, "[PLAN/INPUT/FILE_SIZE]"},
		{PlanRequest{ImportText: "{}", MihomoProviderURLs: []string{"https://private.test/key"}}, "[PLAN/INPUT/MIXED_SOURCES]"},
		{PlanRequest{ProviderURL: "https://private.test/key", MihomoProviderURLs: []string{"https://private.test/key"}}, "[PLAN/INPUT/DUPLICATE]"},
		{PlanRequest{ProviderURL: strings.Repeat("a", 8193), Cores: []string{"mihomo"}}, "[SUBSCRIPTION/MIHOMO/URL/LENGTH/1/0]"},
		{PlanRequest{MihomoProviderURLs: []string{"https://private.test/key"}}, "[SUBSCRIPTION/MIHOMO/SELECTION/CORE_MISSING/1/0]"},
		{PlanRequest{XrayProviderURLs: []string{"https://private.test/key"}}, "[SUBSCRIPTION/XRAY/SELECTION/CORE_MISSING/1/0]"},
	} {
		a := testApp()
		tc.r.InspectionID = "inspection"
		_, err := a.PreparePlan(tc.r)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("want %s, got %v", tc.want, err)
		}
	}
}
func TestConfigurationPlanDiagnosticIsExactAndRedacted(t *testing.T) {
	for _, tc := range []struct{ message, want string }{{"invalid core selection", "CORE_SELECTION"}, {"invalid Mihomo YAML mapping", "MIHOMO_YAML"}, {"generate API secret", "API_SECRET"}, {"invalid core selection: private-token", "INTERNAL"}, {"https://private.test/key", "INTERNAL"}} {
		got := configurationPlanDiagnostic(errors.New(tc.message))
		if got != "[PLAN/CONFIGURATION/"+tc.want+"]" {
			t.Fatal(got)
		}
	}
}
func TestPlanStateDiagnostics(t *testing.T) {
	a := testApp()
	a.busy = true
	if _, err := a.PreparePlan(PlanRequest{InspectionID: "inspection"}); err == nil || err.Error() != "[PLAN/STATE/BUSY]" {
		t.Fatal(err)
	}
	a.busy = false
	if _, err := a.PreparePlan(PlanRequest{InspectionID: "older"}); err == nil || err.Error() != "[PLAN/INSPECTION/STALE]" {
		t.Fatal(err)
	}
	a.inspectedAt = time.Now().Add(-10 * time.Minute)
	if _, err := a.PreparePlan(PlanRequest{InspectionID: "inspection"}); err == nil || err.Error() != "[PLAN/INSPECTION/STALE]" {
		t.Fatal(err)
	}
}

func TestVerifiedPanelReadyRequiresAllChecks(t *testing.T) {
	for _, state := range []verify.State{verify.Failed, verify.Pending, verify.NotApplicable, ""} {
		for _, field := range []string{"api", "https", "trust"} {
			s := verify.ServiceReport{Component: catalog.UI, API: verify.Check{State: verify.Passed}, HTTPS: verify.Check{State: verify.Passed}, Trust: verify.Check{State: verify.Passed}}
			switch field {
			case "api":
				s.API.State = state
			case "https":
				s.HTTPS.State = state
			case "trust":
				s.Trust.State = state
			}
			if verifiedPanelReady(s) {
				t.Fatalf("panel exposed with %s=%q", field, state)
			}
		}
	}
	s := verify.ServiceReport{Component: catalog.UI, API: verify.Check{State: verify.Passed}, HTTPS: verify.Check{State: verify.Passed}, Trust: verify.Check{State: verify.Passed}}
	if !verifiedPanelReady(s) {
		t.Fatal("verified UI withheld")
	}
	s.Component = catalog.Mihomo
	if verifiedPanelReady(s) {
		t.Fatal("non-UI accepted")
	}
}

func TestPackagePolicyFailureReachesUIWithoutPrivateErrorDetails(t *testing.T) {
	for _, tc := range []struct {
		err      error
		expected string
	}{
		{fmt.Errorf("private-secret: %w", install.ErrInsecureFeeds), "/opt/etc/opkg.conf"},
		{errors.New("private-secret password=hidden"), "частично"},
	} {
		a := testApp()
		finished := make(chan struct{})
		a.emit = func(progress Progress) {
			if progress.Step == "finished" {
				close(finished)
			}
		}
		a.run = func(context.Context, install.Plan, router.Transport, func(install.Event)) (install.Report, error) {
			return install.Report{ReinspectRequired: true}, tc.err
		}
		if err := a.ConfirmPlan("plan"); err != nil {
			t.Fatal(err)
		}
		if err := a.StartInstall("plan"); err != nil {
			t.Fatal(err)
		}
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("result missing")
		}
		message := a.GetResult().Message
		if !strings.Contains(message, tc.expected) || strings.Contains(message, "private-secret") || strings.Contains(message, "password=") {
			t.Fatal("actionable message lost or private error leaked", message)
		}
	}
}
