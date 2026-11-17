package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestGeneratedCertificateLifetimes(t *testing.T) {
	before := time.Now()
	p, err := PrepareTLS("router.test", TLSState{})
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	ca := parseConstraintCertificate(t, p.PublicCA())
	cert, _, _ := p.ServerPair()
	leaf := parseConstraintCertificate(t, cert)
	if ca.NotAfter.Before(before.AddDate(1, 0, 0).Add(-time.Second)) || ca.NotAfter.After(after.AddDate(1, 0, 0)) {
		t.Fatal("CA lifetime must be one year")
	}
	if leaf.NotAfter.Before(before.Add(90*24*time.Hour).Add(-time.Second)) || leaf.NotAfter.After(after.Add(90*24*time.Hour)) {
		t.Fatal("server lifetime must be 90 days")
	}
	if leaf.NotAfter.After(ca.NotAfter) {
		t.Fatal("server outlives CA")
	}
}

func parseConstraintCertificate(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("certificate missing")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
func TestGeneratedCAEnforcesOnlyRouterIdentity(t *testing.T) {
	for _, address := range []string{"192.168.1.1", "2001:db8::1", "::ffff:192.168.1.1", "router.test", "ROUTER.test"} {
		t.Run(address, func(t *testing.T) {
			p, err := PrepareTLS(address, TLSState{})
			if err != nil {
				t.Fatal(err)
			}
			ca := parseConstraintCertificate(t, p.PublicCA())
			if !ca.PermittedDNSDomainsCritical {
				t.Error("critical Name Constraints missing")
			}
			cert, _, _ := p.ServerPair()
			if err = verifyChain(address, cert, p.PublicCA(), time.Now()); err != nil {
				t.Fatal("intended router rejected")
			}
			block, _ := pem.Decode(p.private.caKey)
			issuer, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			for i, scenario := range []string{"foreign-dns", "subdomain", "foreign-ipv4", "foreign-ipv6", "mixed-san", "foreign-uri", "foreign-email"} {
				leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 10)), Subject: pkix.Name{CommonName: address}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
				if ip := net.ParseIP(address); ip != nil {
					leaf.IPAddresses = []net.IP{ip}
				} else {
					leaf.DNSNames = []string{address}
				}
				switch scenario {
				case "foreign-dns":
					leaf.DNSNames = []string{"example.com"}
				case "subdomain":
					leaf.DNSNames = []string{"other." + address}
				case "foreign-ipv4":
					leaf.IPAddresses = []net.IP{net.ParseIP("198.51.100.99")}
				case "foreign-ipv6":
					leaf.IPAddresses = []net.IP{net.ParseIP("2001:db8::99")}
				case "mixed-san":
					leaf.DNSNames = append(leaf.DNSNames, "example.com")
				case "foreign-uri":
					leaf.URIs = []*url.URL{{Scheme: "https", Host: "example.com"}}
				case "foreign-email":
					leaf.EmailAddresses = []string{"user@example.com"}
				}
				der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, issuer)
				if err != nil {
					t.Fatal(err)
				}
				// No DNSName option: rejection must come from the CA constraints rather
				// than a simple mismatch with the originally requested router address.
				signed, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				roots := x509.NewCertPool()
				roots.AddCert(ca)
				if _, err = signed.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
					t.Errorf("%s: unrelated identity accepted", scenario)
				}
			}
		})
	}
}

func TestExistingLegacyAuthorityIsNotReplaced(t *testing.T) {
	p, err := PrepareTLS("router.test", TLSState{})
	if err != nil {
		t.Fatal(err)
	}
	ca := parseConstraintCertificate(t, p.PublicCA())
	ca.NotAfter = time.Now().AddDate(10, 0, 0)
	ca.PermittedDNSDomainsCritical = false
	ca.PermittedDNSDomains = nil
	ca.ExcludedDNSDomains = nil
	ca.PermittedIPRanges = nil
	ca.ExcludedIPRanges = nil
	ca.PermittedEmailAddresses = nil
	ca.ExcludedEmailAddresses = nil
	ca.PermittedURIDomains = nil
	ca.ExcludedURIDomains = nil
	block, _ := pem.Decode(p.private.caKey)
	issuer, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, ca.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	legacyCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, key, _ := p.ServerPair()
	leaf := parseConstraintCertificate(t, cert)
	leaf.NotAfter = time.Now().AddDate(1, 0, 0)
	der, err = x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	legacyCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	reused, err := PrepareTLS("router.test", ExistingTLS(legacyCert, key, legacyCA))
	if err != nil {
		t.Fatal(err)
	}
	gotCert, gotKey, _ := reused.ServerPair()
	if reused.Status() != Preserved || !bytes.Equal(gotCert, legacyCert) || !bytes.Equal(gotKey, key) || !bytes.Equal(reused.PublicCA(), legacyCA) {
		t.Fatal("legacy TLS was silently replaced")
	}
}
