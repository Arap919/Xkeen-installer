package verify

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/install"
	"github.com/Arap919/xkeen-installer/internal/router"
	localtls "github.com/Arap919/xkeen-installer/internal/tls"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

type readRouter struct {
	files       map[string][]byte
	commands    []string
	dialAddress string
}

func (f *readRouter) Run(_ context.Context, c string) (router.Result, error) {
	f.commands = append(f.commands, c)
	switch c {
	case "printf 'XKEEN_SHELL_OK\\n'":
		return router.Result{Stdout: []byte("XKEEN_SHELL_OK\n")}, nil
	case "uname -m":
		return router.Result{Stdout: []byte("aarch64")}, nil
	case "/opt/bin/opkg list-installed":
		return router.Result{Stdout: []byte("opkg - 1\n")}, nil
	case "ps w":
		return router.Result{}, nil
	}
	if strings.HasPrefix(c, "pidof ") {
		return router.Result{Stdout: []byte("123")}, nil
	}
	return router.Result{ExitCode: 1}, nil
}
func (f *readRouter) Read(_ context.Context, p string) ([]byte, error) {
	b, ok := f.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}
func (f *readRouter) Stat(_ context.Context, p string) (router.Entry, error) {
	if b, ok := f.files[p]; ok {
		return router.Entry{Path: p, Mode: 0600, Size: int64(len(b))}, nil
	}
	for q := range f.files {
		if strings.HasPrefix(q, p+"/") {
			return router.Entry{Path: p, Mode: fs.ModeDir | 0700}, nil
		}
	}
	return router.Entry{}, fs.ErrNotExist
}
func (f *readRouter) ReadDir(ctx context.Context, p string) ([]router.Entry, error) {
	seen := map[string]bool{}
	var out []router.Entry
	for q := range f.files {
		if strings.HasPrefix(q, p+"/") {
			n := strings.Split(strings.TrimPrefix(q, p+"/"), "/")[0]
			if !seen[n] {
				seen[n] = true
				e, _ := f.Stat(ctx, path.Join(p, n))
				out = append(out, e)
			}
		}
	}
	return out, nil
}
func (f *readRouter) AvailableBytes(context.Context, string) (uint64, error) { return 1 << 30, nil }
func (f *readRouter) WriteAtomic(context.Context, string, []byte, fs.FileMode) error {
	panic("read-only verification wrote")
}
func (f *readRouter) MkdirAll(context.Context, string, fs.FileMode) error {
	panic("read-only verification wrote")
}
func (f *readRouter) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	return localDial(ctx, n, f.dialAddress)
}
func TestVerifySeparatesProcessConfigAPIHTTPSAndTrust(t *testing.T) {
	for _, invalidAPI := range []bool{false, true} {
		t.Run(map[bool]string{false: "healthy-custom-CA", true: "invalid-API"}[invalidAPI], func(t *testing.T) {
			f := &readRouter{files: map[string][]byte{"/opt/bin/opkg": []byte("opkg"), config.XrayPath: []byte(`{"inbounds":[{"tag":"in","protocol":"socks","port":1080,"settings":{}}],"outbounds":[{"tag":"out","protocol":"freedom","settings":{}}]}`)}}
			snapshot, e := router.Inspect(context.Background(), f)
			if e != nil {
				t.Fatal(e)
			}
			selection := install.Selection{Config: config.Selection{Cores: []catalog.Component{catalog.Xray}, ActiveCore: catalog.Xray}, UI: true}
			proposal, e := config.Prepare(snapshot, selection.Config, config.Import{})
			if e != nil {
				t.Fatal(e)
			}
			tlsProposal, e := localtls.PrepareTLS("router.test", localtls.TLSState{})
			if e != nil {
				t.Fatal(e)
			}
			if e = tlsProposal.Save(filepath.Join(t.TempDir(), "ca")); e != nil {
				t.Fatal(e)
			}
			p, e := install.BuildPlanWithTLS(snapshot, selection, proposal, tlsProposal)
			if e != nil {
				t.Fatal(e)
			}
			cert, key, _ := tlsProposal.ServerPair()
			pair, _ := tls.X509KeyPair(cert, key)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/auth/login" {
					t.Error(r.URL.Path)
				}
				if invalidAPI {
					w.Write([]byte(`{"private":"response-secret"}`))
				} else {
					w.Write([]byte(`{"enabled":true,"has_password":true,"authenticated":false}`))
				}
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
			server.StartTLS()
			defer server.Close()
			f.dialAddress = strings.TrimPrefix(server.URL, "https://")
			for path, b := range p.VerificationFiles() {
				f.files[path] = b
			}
			report, e := Verify(context.Background(), f, p)
			if e != nil {
				t.Fatal(e)
			}
			if len(report.Services) != 2 {
				t.Fatal(report)
			}
			core, ui := report.Services[0], report.Services[1]
			if core.Process.State != Passed || core.Configuration.State != Matched || core.API.State != NotApplicable {
				t.Fatal(core)
			}
			want := Passed
			if invalidAPI {
				want = Failed
			}
			if ui.Process.State != Passed || ui.HTTPS.State != Passed || ui.API.State != want || ui.Trust.State != Pending {
				t.Fatal(ui)
			}
			f.files[config.XrayPath] = []byte("changed")
			report, e = Verify(context.Background(), f, p)
			if e != nil || report.Services[0].Configuration.State != Failed || report.Services[0].Process.State != Passed {
				t.Fatal(report, e)
			}
			data, _ := json.Marshal(report)
			if strings.Contains(string(data), "response-secret") {
				t.Fatal("body leaked")
			}
		})
	}
}
func TestControllerFromBackendConfigAndMeaningfulVersion(t *testing.T) {
	address, secret, ok := controller([]byte("external-controller: 127.0.0.1:9090\nsecret: private-token\n"))
	if !ok || address != "127.0.0.1:9090" || secret != "private-token" {
		t.Fatal("controller")
	}
	if _, _, ok = controller([]byte("external-controller: evil.example:9090")); ok {
		t.Fatal("external controller")
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-token" {
			t.Error("auth")
		}
		w.Write([]byte(`{"meta":true,"version":"v1.19.33"}`))
	}))
	defer s.Close()
	r := probe(context.Background(), localDial, s.URL+"/version", secret, nil, "version")
	if !r.valid {
		t.Fatal(r)
	}
}
