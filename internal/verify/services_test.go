package verify

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func localDial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}
func TestProbeMeaningfulShapeAndAuthRedaction(t *testing.T) {
	secret := "controller-secret"
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("auth missing")
		}
		w.Write([]byte(`{"unexpected":"controller-secret"}`))
	}))
	defer s.Close()
	r := probe(context.Background(), localDial, s.URL+"/version", secret, nil, "version")
	if !r.connected || r.valid {
		t.Fatal("open port accepted invalid API")
	}
	if strings.Contains(r.detail, secret) {
		t.Fatal("secret leaked")
	}
}
func TestHTTPSChainHostnameAndPublicLogin(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"enabled":true,"has_password":true,"authenticated":false}`))
	}))
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	r := probe(context.Background(), localDial, s.URL+"/api/auth/login", "", roots, "login")
	if !r.valid || !r.connected {
		t.Fatal(r)
	}
	r = probe(context.Background(), localDial, s.URL+"/api/auth/login", "", x509.NewCertPool(), "login")
	if r.connected || r.valid {
		t.Fatal("bad chain")
	}
	wrong := strings.Replace(s.URL, "127.0.0.1", "wrong.test", 1)
	dial := func(ctx context.Context, n, a string) (net.Conn, error) {
		return localDial(ctx, n, strings.TrimPrefix(s.URL, "https://"))
	}
	r = probe(context.Background(), dial, wrong+"/api/auth/login", "", roots, "login")
	if r.connected {
		t.Fatal("wrong hostname")
	}
}
