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
	"encoding/asn1"
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
	if !validAddress(address) || !certificatesOnly(cert) || !privateKeyOnly(key) {
		return fail()
	}
	pair, e := stdtls.X509KeyPair(cert, bytes.TrimSpace(key))
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
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || bytes.Count(data[:len(data)-len(rest)], []byte("-----BEGIN ")) != 1 {
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

// Private-key input must be exactly one supported PEM block. X509KeyPair alone
// ignores surrounding data and additional blocks, which could contain a CA key.
func privateKeyOnly(data []byte) bool {
	data = bytes.TrimSpace(data)
	block, rest := pem.Decode(data)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || bytes.Count(data[:len(data)-len(rest)], []byte("-----BEGIN ")) != 1 || !oneASN1Value(block.Bytes) {
		return false
	}
	if !keyEnvelope(block.Type, block.Bytes) {
		return false
	}
	return bytes.HasPrefix(data, []byte("-----BEGIN "+block.Type+"-----"))
}

// x509 parsers can ignore trailing DER. Bound both the outer key and PKCS8's
// nested PrivateKey value without discarding legitimate optional attributes.
func oneASN1Value(der []byte) bool {
	var raw asn1.RawValue
	rest, e := asn1.Unmarshal(der, &raw)
	return e == nil && len(rest) == 0 && len(raw.FullBytes) == len(der)
}

// Check only field/tag envelopes which x509 struct decoders can silently ignore.
// Key semantics stay with x509; legitimate PKCS8 attributes remain byte-exact.
func asn1Parts(data []byte) ([]asn1.RawValue, bool) {
	var fields []asn1.RawValue
	for len(data) > 0 {
		var field asn1.RawValue
		rest, e := asn1.Unmarshal(data, &field)
		if e != nil || len(rest) >= len(data) {
			return nil, false
		}
		fields = append(fields, field)
		data = rest
	}
	return fields, true
}
func universal(field asn1.RawValue, tag int) bool {
	return field.Class == 0 && field.Tag == tag && field.IsCompound == (tag == asn1.TagSequence || tag == asn1.TagSet)
}
func keyFields(der []byte) ([]asn1.RawValue, bool) {
	var outer asn1.RawValue
	rest, e := asn1.Unmarshal(der, &outer)
	if e != nil || len(rest) != 0 || !universal(outer, asn1.TagSequence) {
		return nil, false
	}
	return asn1Parts(outer.Bytes)
}
func keyEnvelope(kind string, der []byte) bool {
	fields, ok := keyFields(der)
	if !ok {
		return false
	}
	switch kind {
	case "PRIVATE KEY":
		if len(fields) < 3 || len(fields) > 4 || !universal(fields[0], asn1.TagInteger) || !universal(fields[1], asn1.TagSequence) || !universal(fields[2], asn1.TagOctetString) {
			return false
		}
		if len(fields) == 4 {
			attrs := fields[3]
			if attrs.Class != 2 || attrs.Tag != 0 || !attrs.IsCompound {
				return false
			}
			entries, ok := asn1Parts(attrs.Bytes)
			if !ok {
				return false
			}
			for _, entry := range entries {
				parts, ok := keyFields(entry.FullBytes)
				if !ok || len(parts) != 2 || !universal(parts[0], asn1.TagOID) || !universal(parts[1], asn1.TagSet) {
					return false
				}
				values, ok := asn1Parts(parts[1].Bytes)
				if !ok || len(values) == 0 {
					return false
				}
			}
		}
		algo, ok := keyFields(fields[1].FullBytes)
		if !ok || len(algo) < 1 || len(algo) > 2 || !universal(algo[0], asn1.TagOID) {
			return false
		}
		var oid asn1.ObjectIdentifier
		if _, e := asn1.Unmarshal(algo[0].FullBytes, &oid); e != nil {
			return false
		}
		switch {
		case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}):
			if len(algo) == 2 && (!universal(algo[1], asn1.TagNull) || len(algo[1].Bytes) != 0) {
				return false
			}
			return keyEnvelope("RSA PRIVATE KEY", fields[2].Bytes)
		case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}):
			return len(algo) == 2 && universal(algo[1], asn1.TagOID) && keyEnvelope("EC PRIVATE KEY", fields[2].Bytes)
		case oid.Equal(asn1.ObjectIdentifier{1, 3, 101, 112}):
			if len(algo) != 1 {
				return false
			}
			values, ok := asn1Parts(fields[2].Bytes)
			return ok && len(values) == 1 && universal(values[0], asn1.TagOctetString)
		default:
			return false
		}
	case "EC PRIVATE KEY":
		if len(fields) < 2 || len(fields) > 4 || !universal(fields[0], asn1.TagInteger) || !universal(fields[1], asn1.TagOctetString) {
			return false
		}
		last := -1
		for _, field := range fields[2:] {
			if field.Class != 2 || !field.IsCompound || field.Tag < 0 || field.Tag > 1 || field.Tag <= last {
				return false
			}
			last = field.Tag
			values, ok := asn1Parts(field.Bytes)
			tag := asn1.TagOID
			if field.Tag == 1 {
				tag = asn1.TagBitString
			}
			if !ok || len(values) != 1 || !universal(values[0], tag) {
				return false
			}
		}
		return true
	case "RSA PRIVATE KEY":
		if len(fields) < 9 || len(fields) > 10 {
			return false
		}
		for _, field := range fields[:9] {
			if !universal(field, asn1.TagInteger) {
				return false
			}
		}
		if len(fields) == 10 {
			if !universal(fields[9], asn1.TagSequence) {
				return false
			}
			primes, ok := asn1Parts(fields[9].Bytes)
			if !ok {
				return false
			}
			for _, prime := range primes {
				values, ok := keyFields(prime.FullBytes)
				if !ok || len(values) != 3 {
					return false
				}
				for _, value := range values {
					if !universal(value, asn1.TagInteger) {
						return false
					}
				}
			}
		}
		return true
	default:
		return false
	}
}
