// Package tls prepares backend-only HTTPS material. It never changes host trust.
package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

type Status string

const (
	Missing   Status = "missing"
	Invalid   Status = "invalid"
	Prepared  Status = "prepared"
	Preserved Status = "preserved"
)

type Trust string

const (
	TrustPending   Trust = "pending"
	TrustManual    Trust = "manual"
	TrustInstalled Trust = "installed"
)

type TLSState struct{ cert, key, ca []byte }

func ExistingTLS(cert, key, ca []byte) TLSState { return TLSState{clone(cert), clone(key), clone(ca)} }
func (s TLSState) String() string               { return "TLSState{private material}" }
func (s TLSState) GoString() string             { return s.String() }

type material struct {
	storageMu            sync.RWMutex
	storageDir           string
	address              string
	cert, key, ca, caKey []byte
	status               Status
	trust                Trust
}
type TLSProposal struct{ private *material }
type StateError struct{ State Status }

func (e *StateError) Error() string {
	return "TLS material is " + string(e.State) + "; manual reconciliation required"
}
func clone(b []byte) []byte { return append([]byte(nil), b...) }
func (p TLSProposal) Status() Status {
	if p.private == nil {
		return Missing
	}
	return p.private.status
}
func (p TLSProposal) TrustStatus() Trust {
	if p.private == nil {
		return TrustManual
	}
	return p.private.trust
}
func (p TLSProposal) Address() string {
	if p.private == nil {
		return ""
	}
	return p.private.address
}
func (p TLSProposal) PublicCA() []byte {
	if p.private == nil {
		return nil
	}
	return clone(p.private.ca)
}

// ServerPair is a backend-only deployment accessor. Never expose it through a GUI bridge.
func (p TLSProposal) ServerPair() ([]byte, []byte, bool) {
	if p.private == nil {
		return nil, nil, false
	}
	return clone(p.private.cert), clone(p.private.key), true
}
func (p TLSProposal) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Status Status
		Trust  Trust
	}{p.Status(), p.TrustStatus()})
}
func (p TLSProposal) String() string   { b, _ := p.MarshalJSON(); return string(b) }
func (p TLSProposal) GoString() string { return p.String() }
func validAddress(a string) bool {
	if net.ParseIP(a) != nil {
		return true
	}
	if len(a) > 253 || strings.ContainsAny(a, "/:\\\x00\r\n") {
		return false
	}
	for _, label := range strings.Split(a, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func ValidatePair(address string, cert, key []byte, now time.Time) error {
	fail := func() error { return &StateError{Invalid} }
	if !validAddress(address) || !certificatesOnly(cert) {
		return fail()
	}
	pair, e := stdtls.X509KeyPair(cert, key)
	if e != nil || len(pair.Certificate) == 0 {
		return fail()
	}
	c, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || c.IsCA || now.Before(c.NotBefore) || !now.Before(c.NotAfter) || c.VerifyHostname(address) != nil {
		return fail()
	}
	server := false
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			server = true
		}
	}
	if !server || c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fail()
	}
	return nil
}
func PrepareTLS(address string, existing TLSState) (TLSProposal, error) {
	if !validAddress(address) {
		return TLSProposal{}, &StateError{Invalid}
	}
	if len(existing.cert) > 0 || len(existing.key) > 0 || len(existing.ca) > 0 {
		if len(existing.ca) > 0 && !certificatesOnly(existing.ca) {
			return TLSProposal{}, &StateError{Invalid}
		}
		if e := ValidatePair(address, existing.cert, existing.key, time.Now()); e != nil {
			return TLSProposal{}, e
		}
		trust := TrustManual
		if verifyChain(address, existing.cert, existing.ca, time.Now()) == nil {
			trust = TrustPending
		}
		return TLSProposal{&material{address: address, cert: clone(existing.cert), key: clone(existing.key), ca: clone(existing.ca), status: Preserved, trust: trust}}, nil
	}
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return TLSProposal{}, errors.New("TLS generation failed")
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return TLSProposal{}, errors.New("TLS generation failed")
	}
	now := time.Now()
	serial := func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)); return n }
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "XKeen Installer local CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLenZero: true}
	leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: address}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(address); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{address}
	}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		return TLSProposal{}, errors.New("TLS generation failed")
	}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if e != nil {
		return TLSProposal{}, errors.New("TLS generation failed")
	}
	encode := func(k *ecdsa.PrivateKey) []byte {
		b, _ := x509.MarshalPKCS8PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
	}
	return TLSProposal{&material{address: address, cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key: encode(key), ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), caKey: encode(caKey), status: Prepared, trust: TrustPending}}, nil
}
func verifyChain(address string, cert, ca []byte, now time.Time) error {
	roots := x509.NewCertPool()
	if len(ca) == 0 || !roots.AppendCertsFromPEM(ca) {
		return errors.New("CA unavailable")
	}
	block, rest := pem.Decode(cert)
	if block == nil {
		return errors.New("certificate unavailable")
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return errors.New("certificate invalid")
	}
	inter := x509.NewCertPool()
	inter.AppendCertsFromPEM(rest)
	_, e = leaf.Verify(x509.VerifyOptions{DNSName: address, Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if e != nil {
		return errors.New("certificate chain unverified")
	}
	return nil
}

// MatchesExisting prevents a caller from replacing a valid inventoried pair silently.
func (p TLSProposal) MatchesExisting(cert, key []byte) bool {
	return p.private != nil && bytes.Equal(cert, p.private.cert) && bytes.Equal(key, p.private.key)
}

func certificatesOnly(data []byte) bool {
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		b, rest := pem.Decode(data)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return false
		}
		if _, e := x509.ParseCertificate(b.Bytes); e != nil {
			return false
		}
		count++
		data = rest
	}
	return count > 0
}
