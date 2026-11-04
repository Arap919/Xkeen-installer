package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestSANAndReuse(t *testing.T) {
	for _, host := range []string{"192.168.1.1", "router.test"} {
		p, e := PrepareTLS(host, TLSState{})
		if e != nil {
			t.Fatal(e)
		}
		c, k, ok := p.ServerPair()
		if !ok {
			t.Fatal("missing pair")
		}
		if ValidatePair(host, c, k, time.Now()) != nil {
			t.Fatal("invalid pair")
		}
		q, e := PrepareTLS(host, ExistingTLS(c, k, nil))
		if e != nil {
			t.Fatal(e)
		}
		a, b, _ := q.ServerPair()
		if !bytes.Equal(a, c) || !bytes.Equal(b, k) || q.TrustStatus() != TrustManual {
			t.Fatal("existing pair replaced")
		}
	}
}

func TestWrongKeyEKUAndSecretBoundaries(t *testing.T) {
	p, _ := PrepareTLS("router.test", TLSState{})
	q, _ := PrepareTLS("router.test", TLSState{})
	cert, key, _ := p.ServerPair()
	_, wrong, _ := q.ServerPair()
	if ValidatePair("router.test", cert, wrong, time.Now()) == nil {
		t.Fatal("mismatched key accepted")
	}
	if ValidatePair("wrong.test", cert, key, time.Now()) == nil || ValidatePair("router.test", cert, key, time.Now().AddDate(2, 0, 0)) == nil {
		t.Fatal("hostname or expiry")
	}
	block, _ := pem.Decode(p.private.ca)
	ca, _ := x509.ParseCertificate(block.Bytes)
	block, _ = pem.Decode(p.private.caKey)
	raw, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(55), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"router.test"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, raw)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	if ValidatePair("router.test", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), time.Now()) == nil {
		t.Fatal("client EKU accepted")
	}
	b, _ := json.Marshal(p)
	text := string(b) + fmt.Sprintf("%#v %+v", p, p)
	if strings.Contains(text, string(p.private.caKey)) || strings.Contains(text, string(key)) || strings.Contains(text, "PRIVATE KEY") {
		t.Fatal("private material preview")
	}
	if ValidatePair("router.test", append(cert, p.private.caKey...), key, time.Now()) == nil {
		t.Fatal("private data in public certificate accepted")
	}
	if _, e := PrepareTLS("router.test", ExistingTLS(cert, key, p.private.caKey)); e == nil {
		t.Fatal("private CA public payload accepted")
	}
}
