// Package verify provides bounded, read-only checks. It never changes service
// state, reruns potentially writing native validators, or changes host trust.
package verify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/Arap919/xkeen-installer/internal/catalog"
	"github.com/Arap919/xkeen-installer/internal/config"
	"github.com/Arap919/xkeen-installer/internal/install"
	"github.com/Arap919/xkeen-installer/internal/router"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type State string

const (
	Passed        State = "passed"
	Failed        State = "failed"
	Pending       State = "pending"
	NotApplicable State = "not-applicable"
	Unconfigured  State = "unconfigured"
	Matched       State = "matched-reviewed-plan"
)

type Check struct {
	State  State
	Detail string
}
type ServiceReport struct {
	Component                                 catalog.Component
	Process, Configuration, API, HTTPS, Trust Check
}
type VerificationReport struct{ Services []ServiceReport }

// ProbeTransport optionally forwards TCP through the already authenticated SSH
// connection. No remote shell, curl dependency or credential arguments are used.
type ProbeTransport interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}
type dialFunc func(context.Context, string, string) (net.Conn, error)
type probeResult struct {
	connected, valid bool
	detail           string
}

func probe(ctx context.Context, dial dialFunc, url, secret string, roots *x509.CertPool, shape string) probeResult {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tr := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if e != nil {
		return probeResult{detail: "API request unavailable"}
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	res, e := client.Do(req)
	if e != nil {
		return probeResult{detail: "API connection or certificate verification failed"}
	}
	defer res.Body.Close()
	result := probeResult{connected: true, detail: "API response invalid"}
	b, e := io.ReadAll(io.LimitReader(res.Body, (64<<10)+1))
	if e != nil || len(b) > 64<<10 || res.StatusCode != http.StatusOK {
		return result
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(b, &object) != nil || object == nil {
		return result
	}
	switch shape {
	case "version":
		var version string
		result.valid = json.Unmarshal(object["version"], &version) == nil && strings.TrimSpace(version) != "" && len(version) < 128 && regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.]+)?$`).MatchString(version)
	case "login":
		result.valid = true
		for _, key := range []string{"enabled", "has_password", "authenticated"} {
			var v bool
			raw, ok := object[key]
			if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &v) != nil {
				result.valid = false
			}
		}
	}
	if result.valid {
		result.detail = "API response shape verified"
	}
	return result
}
func process(ctx context.Context, t router.Transport, name string) Check {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r, e := t.Run(bounded, "pidof "+name)
	if e != nil || r.ExitCode != 0 {
		return Check{Failed, "Процесс не подтверждён"}
	}
	fields := strings.Fields(string(r.Stdout))
	if len(fields) == 0 {
		return Check{Failed, "Процесс не найден"}
	}
	for _, f := range fields {
		n, e := strconv.ParseUint(f, 10, 32)
		if e != nil || n == 0 {
			return Check{Failed, "Ответ проверки процесса некорректен"}
		}
	}
	return Check{Passed, "Процесс найден"}
}
func configuration(ctx context.Context, t router.Transport, files map[string][]byte, prefix string) Check {
	found := false
	for path, want := range files {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		found = true
		got, e := t.Read(ctx, path)
		if e != nil || !bytes.Equal(got, want) {
			return Check{Failed, "Установленная конфигурация отличается от просмотренного плана"}
		}
	}
	if !found {
		return Check{Unconfigured, "Конфигурация не задана"}
	}
	return Check{Matched, "Байты соответствуют проверенному плану; native validation выполняется только на этапе установки"}
}
func controller(data []byte) (string, string, bool) {
	var c struct {
		Controller string `yaml:"external-controller"`
		Secret     string `yaml:"secret"`
	}
	if yaml.Unmarshal(data, &c) != nil || c.Controller == "" {
		return "", "", false
	}
	host, port, e := net.SplitHostPort(c.Controller)
	if e != nil {
		return "", "", false
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return "", "", false
	}
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = "127.0.0.1"
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", "", false
		}
	}
	return net.JoinHostPort(host, port), c.Secret, true
}
func Verify(ctx context.Context, t router.Transport, p install.Plan) (VerificationReport, error) {
	var report VerificationReport
	if !p.Includes(catalog.XKeen) {
		return report, errors.New("План проверки недоступен")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	files := p.VerificationFiles()
	forward, canProbe := t.(ProbeTransport)
	na := Check{NotApplicable, "HTTP API не предусмотрен контрактом службы"}
	for _, component := range []catalog.Component{catalog.Mihomo, catalog.Xray, catalog.Watchdog, catalog.UI} {
		if !p.Includes(component) {
			continue
		}
		s := ServiceReport{Component: component, API: na, HTTPS: Check{NotApplicable, "HTTPS не предусмотрен"}, Trust: Check{NotApplicable, "Системное доверие не требуется"}}
		switch component {
		case catalog.Mihomo, catalog.Xray:
			s.Process = process(ctx, t, string(component))
			if component != p.VerificationActiveCore() {
				s.Process = Check{NotApplicable, "Ядро установлено как неактивное"}
			}
			s.Configuration = configuration(ctx, t, files, "/opt/etc/"+string(component)+"/")
			if component == catalog.Mihomo && component == p.VerificationActiveCore() {
				address, secret, ok := controller(files[config.MihomoPath])
				if !ok {
					s.API = Check{Unconfigured, "Совместимый loopback controller не задан"}
				} else if !canProbe {
					s.API = Check{Pending, "SSH TCP forwarding недоступен"}
				} else {
					r := probe(ctx, forward.DialContext, "http://"+address+"/version", secret, nil, "version")
					s.API = Check{Failed, "Mihomo version API не прошёл проверку"}
					if r.valid {
						s.API = Check{Passed, "Mihomo version API проверен с настройками авторизации конфигурации"}
					}
				}
			}
		case catalog.Watchdog:
			s.Process = Check{NotApplicable, "Watchdog запускается по расписанию; постоянный процесс не ожидается"}
			s.Configuration = configuration(ctx, t, files, config.WatchdogPath)
		case catalog.UI:
			s.Process = process(ctx, t, "xkeen-ui")
			s.Configuration = Check{Unconfigured, "Параметры init панели недоступны"}
			s.API = Check{Unconfigured, "HTTPS endpoint не задан"}
			s.HTTPS = Check{Unconfigured, "HTTPS endpoint не задан"}
			s.Trust = Check{Pending, "Системное доверие CA не подтверждено"}
			init, e := t.Read(ctx, "/opt/etc/init.d/S99xkeen-ui")
			if e != nil {
				break
			}
			port, ok := uiHTTPSPort(init)
			if !ok {
				break
			}
			s.Configuration = configuration(ctx, t, files, "/opt/etc/init.d/S99xkeen-ui")
			address, ca, prepared := p.VerificationTLS()
			if !prepared {
				s.HTTPS = Check{Pending, "Для проверки hostname требуется подготовленный TLS proposal"}
				break
			}
			if !canProbe {
				s.API = Check{Pending, "SSH TCP forwarding недоступен"}
				s.HTTPS = s.API
				break
			}
			target := net.JoinHostPort("127.0.0.1", port)
			dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
				return forward.DialContext(ctx, network, target)
			}
			var roots *x509.CertPool
			if len(ca) > 0 {
				roots = x509.NewCertPool()
				if !roots.AppendCertsFromPEM(ca) {
					s.HTTPS = Check{Failed, "Публичный CA некорректен"}
					break
				}
			}
			url := "https://" + net.JoinHostPort(address, port) + "/api/auth/login"
			r := probe(ctx, dial, url, "", roots, "login")
			s.HTTPS = Check{Failed, "Проверка hostname и цепочки HTTPS не завершена"}
			s.API = Check{Failed, "Публичный auth API панели не прошёл проверку"}
			if r.connected {
				s.HTTPS = Check{Passed, "HTTPS hostname и цепочка сертификата проверены"}
			}
			if r.valid {
				s.API = Check{Passed, "Публичный auth API панели проверен"}
			}
			// Custom-root success cannot imply browser trust or PWA readiness. A second
			// request uses only the actual host root pool, without adding the proposal CA.
			if r.connected {
				system := probe(ctx, dial, url, "", nil, "login")
				if system.connected {
					s.Trust = Check{Passed, "Цепочка принимается системным хранилищем этого компьютера"}
				}
			}
		}
		report.Services = append(report.Services, s)
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
	}
	return report, nil
}

var uiArgs = regexp.MustCompile(`(?m)^ARGS="([^"\r\n]*)"$`)

func uiHTTPSPort(init []byte) (string, bool) {
	m := uiArgs.FindSubmatch(init)
	if len(m) != 2 {
		return "", false
	}
	fields := strings.Fields(string(m[1]))
	port, cert, key := "", "", ""
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "-p", "--port", "--tls-cert", "--tls-key":
			if i+1 >= len(fields) {
				return "", false
			}
			flag := fields[i]
			i++
			switch flag {
			case "-p", "--port":
				port = fields[i]
			case "--tls-cert":
				cert = fields[i]
			case "--tls-key":
				key = fields[i]
			}
		}
	}
	n, e := strconv.Atoi(port)
	return port, e == nil && n > 0 && n <= 65535 && cert == "/opt/etc/nginx/ssl/server.crt" && key == "/opt/etc/nginx/ssl/server.key"
}
