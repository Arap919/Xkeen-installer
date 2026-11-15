package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// SubscriptionError contains only fixed diagnostic keys and bounded numeric metadata.
type SubscriptionError struct {
	core, stage, code string
	index, status     int
}

var subscriptionCodes = map[string]bool{
	"URL/COUNT":              true,
	"URL/EMPTY":              true,
	"URL/LENGTH":             true,
	"URL/CONTROL":            true,
	"URL/WHITESPACE":         true,
	"URL/PARSE":              true,
	"URL/HTTP":               true,
	"URL/SCHEME":             true,
	"URL/HOST":               true,
	"URL/USERINFO":           true,
	"URL/FRAGMENT":           true,
	"FETCH/REQUEST":          true,
	"FETCH/TIMEOUT":          true,
	"FETCH/CANCELED":         true,
	"FETCH/DNS":              true,
	"FETCH/TLS":              true,
	"FETCH/CONNECTION":       true,
	"FETCH/REDIRECT":         true,
	"FETCH/HTTP_STATUS":      true,
	"FETCH/BODY_READ":        true,
	"FETCH/SIZE":             true,
	"FETCH/TRANSPORT":        true,
	"JSON/SIZE":              true,
	"JSON/SYNTAX":            true,
	"JSON/DOCUMENT":          true,
	"JSON/OUTBOUNDS":         true,
	"JSON/OUTBOUND":          true,
	"JSON/SETTINGS":          true,
	"MERGE/DEPENDENCY":       true,
	"MERGE/NO_PROXY":         true,
	"MERGE/OUTPUT_LIMIT":     true,
	"SELECTION/CORE_MISSING": true,
}

func subscriptionFailure(core, stage, code string, index int) *SubscriptionError {
	return &SubscriptionError{core: core, stage: stage, code: code, index: index}
}
func (e *SubscriptionError) Error() string {
	if e == nil {
		return "[SUBSCRIPTION/UNKNOWN/INTERNAL/UNEXPECTED/0/0]"
	}
	valid := subscriptionCodes[e.stage+"/"+e.code] && (e.core == "MIHOMO" || e.core == "XRAY") && e.index >= 0 && e.index <= MaxSubscriptions+1 && e.status == 0
	if e.core == "MIHOMO" && e.stage != "URL" && e.stage != "SELECTION" {
		valid = false
	}
	if e.code == "HTTP_STATUS" {
		valid = e.core == "XRAY" && e.stage == "FETCH" && e.index >= 1 && e.index <= MaxSubscriptions && e.status >= 100 && e.status <= 599
	}
	if e.index == 0 && !(e.core == "XRAY" && e.stage == "MERGE" && (e.code == "OUTPUT_LIMIT" || e.code == "NO_PROXY")) {
		valid = false
	}
	if e.index == MaxSubscriptions+1 && !(e.stage == "URL" && e.code == "COUNT") {
		valid = false
	}
	if e.code == "COUNT" && e.index != MaxSubscriptions+1 {
		valid = false
	}
	if !valid {
		return "[SUBSCRIPTION/UNKNOWN/INTERNAL/UNEXPECTED/0/0]"
	}
	return fmt.Sprintf("[SUBSCRIPTION/%s/%s/%s/%d/%d]", e.core, e.stage, e.code, e.index, e.status)
}

// PublicSubscriptionError never serializes arbitrary backend error text.
func PublicSubscriptionError(err error) string {
	var diagnostic *SubscriptionError
	if errors.As(err, &diagnostic) {
		return diagnostic.Error()
	}
	return ""
}
func validateSubscriptionURLs(core string, urls []string) error {
	if len(urls) > MaxSubscriptions {
		return subscriptionFailure(core, "URL", "COUNT", MaxSubscriptions+1)
	}
	for index, raw := range urls {
		whitespaceURL := raw
		if core == "MIHOMO" {
			whitespaceURL, _, _ = strings.Cut(raw, "#")
		}
		code := ""
		switch {
		case raw == "":
			code = "EMPTY"
		case len(raw) > 8192:
			code = "LENGTH"
		case strings.ContainsFunc(raw, unicode.IsControl):
			code = "CONTROL"
		case strings.ContainsFunc(whitespaceURL, unicode.IsSpace):
			code = "WHITESPACE"
		}
		if code != "" {
			return subscriptionFailure(core, "URL", code, index+1)
		}
		u, err := url.Parse(raw)
		switch {
		case err != nil:
			code = "PARSE"
		case u.Scheme == "http":
			code = "HTTP"
		case u.Scheme != "https":
			code = "SCHEME"
		case u.Hostname() == "":
			code = "HOST"
		case u.User != nil:
			code = "USERINFO"
		case core != "MIHOMO" && u.Fragment != "":
			code = "FRAGMENT"
		}
		if code != "" {
			return subscriptionFailure(core, "URL", code, index+1)
		}
	}
	return nil
}

var errSubscriptionRedirect = errors.New("subscription redirect rejected")

func subscriptionClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || validateSubscriptionURLs("XRAY", []string{r.URL.String()}) != nil {
			return errSubscriptionRedirect
		}
		return nil
	}}
}
func subscriptionFetchFailure(err error, index int) error {
	code := "TRANSPORT"
	var dns *net.DNSError
	var op *net.OpError
	var certificate *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var record tls.RecordHeaderError
	var network net.Error
	switch {
	case errors.Is(err, errSubscriptionRedirect):
		code = "REDIRECT"
	case errors.Is(err, context.Canceled):
		code = "CANCELED"
	case errors.Is(err, context.DeadlineExceeded):
		code = "TIMEOUT"
	case errors.As(err, &network) && network.Timeout():
		code = "TIMEOUT"
	case errors.As(err, &dns):
		code = "DNS"
	case errors.As(err, &certificate) || errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &hostname) || errors.As(err, &record):
		code = "TLS"
	case errors.As(err, &op):
		code = "CONNECTION"
	}
	return subscriptionFailure("XRAY", "FETCH", code, index)
}
