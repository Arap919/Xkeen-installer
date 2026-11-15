package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestSubscriptionURLDiagnostics(t *testing.T) {
	for _, tc := range []struct{ raw, code string }{{"", "EMPTY"}, {strings.Repeat("a", 8193), "LENGTH"}, {"https://private.test/\nsecret", "CONTROL"}, {"https://private.test/a b", "WHITESPACE"}, {"https://private.test/%zz", "PARSE"}, {"http://private.test/key", "HTTP"}, {"ftp://private.test/key", "SCHEME"}, {"https:///key", "HOST"}, {"https://user:secret@private.test/key", "USERINFO"}, {"https://private.test/a b#label", "WHITESPACE"}, {"https://private.test/key?q=a b#label", "WHITESPACE"}, {"https://private.test/key#label\n", "CONTROL"}} {
		_, err := ResolveSubscriptions(context.Background(), []string{"https://valid.test/key", tc.raw}, nil)
		want := "[SUBSCRIPTION/MIHOMO/URL/" + tc.code + "/2/0]"
		if err == nil || err.Error() != want {
			t.Fatalf("%s: %v", tc.code, err)
		}
	}
	_, err := ResolveSubscriptions(context.Background(), make([]string, 11), nil)
	if err == nil || err.Error() != "[SUBSCRIPTION/MIHOMO/URL/COUNT/11/0]" {
		t.Fatal(err)
	}
}
func TestMihomoOnlyNeverFetches(t *testing.T) {
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	calls := 0
	http.DefaultTransport = subscriptionTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("must not fetch") })
	if _, err := ResolveSubscriptions(context.Background(), []string{"https://valid.test/private"}, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("Mihomo URL fetched")
	}
}
func TestSubscriptionFetchDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{{context.Canceled, "CANCELED"}, {context.DeadlineExceeded, "TIMEOUT"}, {&net.DNSError{Err: "private", Name: "secret"}, "DNS"}, {&net.OpError{Op: "dial", Err: errors.New("private")}, "CONNECTION"}, {errors.New("private"), "TRANSPORT"}} {
		client := &http.Client{Transport: subscriptionTransport(func(*http.Request) (*http.Response, error) { return nil, tc.err })}
		_, err := resolveSubscriptions(context.Background(), client, Import{xrayURLs: []string{"https://private.test/token"}})
		if err == nil || err.Error() != "[SUBSCRIPTION/XRAY/FETCH/"+tc.code+"/1/0]" {
			t.Fatal(err)
		}
	}
	client := &http.Client{Transport: subscriptionTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("secret"))}, nil
	})}
	_, err := resolveSubscriptions(context.Background(), client, Import{xrayURLs: []string{"https://private.test/token"}})
	if err == nil || err.Error() != "[SUBSCRIPTION/XRAY/FETCH/HTTP_STATUS/1/403]" {
		t.Fatal(err)
	}
}
func TestSubscriptionJSONDiagnostics(t *testing.T) {
	for _, tc := range []struct{ body, stage, code string }{{"not json", "JSON", "SYNTAX"}, {"null", "JSON", "DOCUMENT"}, {"{}", "JSON", "OUTBOUNDS"}, {`{"outbounds":[1]}`, "JSON", "OUTBOUND"}, {`{"outbounds":[{"protocol":"vless"}]}`, "JSON", "SETTINGS"}, {`{"outbounds":[{"protocol":"vless","settings":{},"proxySettings":{}}]}`, "MERGE", "DEPENDENCY"}, {`{"outbounds":[]}`, "MERGE", "NO_PROXY"}} {
		_, err := mergeXraySubscriptions([][]byte{[]byte(`{"outbounds":[{"protocol":"vless","settings":{}}]}`), []byte(tc.body)})
		if err == nil || err.Error() != "[SUBSCRIPTION/XRAY/"+tc.stage+"/"+tc.code+"/2/0]" {
			t.Fatal(err)
		}
	}
}

type failedSubscriptionBody struct{}

func (failedSubscriptionBody) Read([]byte) (int, error) {
	return 0, errors.New("private response body")
}
func (failedSubscriptionBody) Close() error { return nil }
func TestSubscriptionResponseAndRedirectDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		body io.ReadCloser
		code string
	}{{failedSubscriptionBody{}, "BODY_READ"}, {io.NopCloser(strings.NewReader(strings.Repeat("x", MaxImportBytes+1))), "SIZE"}} {
		client := &http.Client{Transport: subscriptionTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: tc.body}, nil
		})}
		_, err := resolveSubscriptions(context.Background(), client, Import{xrayURLs: []string{"https://private.test/token"}})
		if err == nil || err.Error() != "[SUBSCRIPTION/XRAY/FETCH/"+tc.code+"/1/0]" {
			t.Fatal(err)
		}
	}
	for _, target := range []string{"http://private.test/token", "https://private.test/loop"} {
		client := subscriptionClient()
		client.Transport = subscriptionTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{target}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		})
		_, err := resolveSubscriptions(context.Background(), client, Import{xrayURLs: []string{"https://private.test/token"}})
		if err == nil || err.Error() != "[SUBSCRIPTION/XRAY/FETCH/REDIRECT/1/0]" {
			t.Fatal(err)
		}
	}
	for _, cause := range []error{&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, tls.RecordHeaderError{Msg: "private"}} {
		if got := subscriptionFetchFailure(cause, 2).Error(); got != "[SUBSCRIPTION/XRAY/FETCH/TLS/2/0]" {
			t.Fatal(got)
		}
	}
	_, err := resolveSubscriptions(context.Background(), &http.Client{}, Import{xrayURLs: []string{"https://private.test/%zz"}})
	if err == nil || err.Error() != "[SUBSCRIPTION/XRAY/FETCH/REQUEST/1/0]" {
		t.Fatal(err)
	}
}
func TestSubscriptionMergedOutputLimit(t *testing.T) {
	body := []byte(`{"outbounds":[{"protocol":"vless","settings":{"padding":"` + strings.Repeat("a", MaxImportBytes*3/5) + `"}}]}`)
	_, err := mergeXraySubscriptions([][]byte{body, body})
	if err == nil || err.Error() != "[SUBSCRIPTION/XRAY/MERGE/OUTPUT_LIMIT/0/0]" {
		t.Fatal(err)
	}
}
func TestSubscriptionDiagnosticRejectsUntrustedMetadata(t *testing.T) {
	for _, diagnostic := range []*SubscriptionError{{core: "private.test/token", stage: "URL", code: "HTTP", index: 1}, {core: "MIHOMO", stage: "FETCH", code: "DNS", index: 1}, {core: "XRAY", stage: "FETCH", code: "HTTP_STATUS", index: 1, status: 999}, {core: "XRAY", stage: "JSON", code: "SYNTAX", index: 11}} {
		if got := PublicSubscriptionError(diagnostic); got != "[SUBSCRIPTION/UNKNOWN/INTERNAL/UNEXPECTED/0/0]" {
			t.Fatal(got)
		}
	}
}

func TestXraySubscriptionFragmentStillRejected(t *testing.T) {
	_, err := ResolveSubscriptions(context.Background(), nil, []string{"https://private.test/key#label"})
	if err == nil || err.Error() != "[SUBSCRIPTION/XRAY/URL/FRAGMENT/1/0]" {
		t.Fatal(err)
	}
}
