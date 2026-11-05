package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
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

func TestPrivateKeyPEMIsExactlyOneBlock(t *testing.T) {
	p, _ := PrepareTLS("router.test", TLSState{})
	cert, key, _ := p.ServerPair()
	cases := map[string][]byte{
		"malformed-first-block":  append([]byte("-----BEGIN PRIVATE KEY-----\nmalformed\n"), key...),
		"CA-key-appended":        append(clone(key), p.private.caKey...),
		"duplicate-key":          append(clone(key), key...),
		"trailing-data":          append(clone(key), []byte("private trailing data")...),
		"prefix-data":            append([]byte("private prefix data\n"), key...),
		"certificate-appended":   append(clone(key), cert...),
		"malformed-second-block": append(clone(key), []byte("-----BEGIN PRIVATE KEY-----\nmalformed")...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if ValidatePair("router.test", cert, data, time.Now()) == nil {
				t.Error("extra key data accepted")
			}
			q, e := PrepareTLS("router.test", ExistingTLS(cert, data, p.PublicCA()))
			if e == nil {
				t.Errorf("unsafe existing key preserved as %v", q)
			}
			var invalid *StateError
			if !errors.As(e, &invalid) || invalid.State != Invalid {
				t.Error("expected typed invalid state")
			}
			if e != nil && strings.Contains(e.Error(), "PRIVATE KEY") {
				t.Error("secret diagnostic")
			}
		})
	}
	parsedBlock, _ := pem.Decode(key)
	parsedKey, e := x509.ParsePKCS8PrivateKey(parsedBlock.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	ecDER, e := x509.MarshalECPrivateKey(parsedKey.(*ecdsa.PrivateKey))
	if e != nil {
		t.Fatal(e)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})
	if ValidatePair("router.test", cert, ecPEM, time.Now()) != nil {
		t.Fatal("valid SEC1 key rejected")
	}
	padded := append([]byte(" \n\t"), key...)
	padded = append(padded, []byte("\r\n \t")...)
	q, e := PrepareTLS("router.test", ExistingTLS(cert, padded, nil))
	if e != nil {
		t.Fatal(e)
	}
	_, got, _ := q.ServerPair()
	if !bytes.Equal(got, padded) {
		t.Fatal("valid exact key bytes changed")
	}
}

func TestPrivateKeyDERHasNoAdditionalValues(t *testing.T) {
	p, _ := PrepareTLS("router.test", TLSState{})
	cert, key, _ := p.ServerPair()
	block, _ := pem.Decode(key)
	ca, _ := pem.Decode(p.private.caKey)
	top := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: append(clone(block.Bytes), ca.Bytes...)})
	var container struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if _, e := asn1.Unmarshal(block.Bytes, &container); e != nil {
		t.Fatal(e)
	}
	container.PrivateKey = append(container.PrivateKey, ca.Bytes...)
	nestedDER, e := asn1.Marshal(container)
	if e != nil {
		t.Fatal(e)
	}
	nested := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: nestedDER})
	for name, data := range map[string][]byte{"outer-DER": top, "nested-PKCS8-DER": nested} {
		t.Run(name, func(t *testing.T) {
			if ValidatePair("router.test", cert, data, time.Now()) == nil {
				t.Fatal("additional DER private key accepted")
			}
			if _, e := PrepareTLS("router.test", ExistingTLS(cert, data, nil)); e == nil {
				t.Fatal("extra DER preserved")
			}
		})
	}
}

func appendKeyField(t *testing.T, der, field []byte) []byte {
	t.Helper()
	var outer asn1.RawValue
	if _, e := asn1.Unmarshal(der, &outer); e != nil {
		t.Fatal(e)
	}
	out, e := asn1.Marshal(asn1.RawValue{Class: 0, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(clone(outer.Bytes), field...)})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestKeySequenceFieldBoundaries(t *testing.T) {
	p, _ := PrepareTLS("router.test", TLSState{})
	cert, key, _ := p.ServerPair()
	block, _ := pem.Decode(key)
	ca, _ := pem.Decode(p.private.caKey)
	parsed, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	ec, _ := x509.MarshalECPrivateKey(parsed.(*ecdsa.PrivateKey))
	badEC := appendKeyField(t, ec, ca.Bytes)
	var nested struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	asn1.Unmarshal(block.Bytes, &nested)
	nested.PrivateKey = badEC
	badNested, _ := asn1.Marshal(nested)
	for name, tc := range map[string]struct {
		kind string
		der  []byte
	}{"PKCS8": {"PRIVATE KEY", appendKeyField(t, block.Bytes, ca.Bytes)}, "SEC1": {"EC PRIVATE KEY", badEC}, "nested-SEC1": {"PRIVATE KEY", badNested}} {
		t.Run(name, func(t *testing.T) {
			key := pem.EncodeToMemory(&pem.Block{Type: tc.kind, Bytes: tc.der})
			if ValidatePair("router.test", cert, key, time.Now()) == nil {
				t.Error("unrecognized key field accepted")
			}
			if _, e := PrepareTLS("router.test", ExistingTLS(cert, key, nil)); e == nil {
				t.Error("unsafe field preserved")
			}
		})
	}
	rsaKey, e := rsa.GenerateKey(rand.Reader, 1024)
	if e != nil {
		t.Fatal(e)
	}
	rsaDER := x509.MarshalPKCS1PrivateKey(rsaKey)
	badRSA := appendKeyField(t, appendKeyField(t, rsaDER, []byte{0x30, 0}), ca.Bytes)
	rsaPKCS8, e := x509.MarshalPKCS8PrivateKey(rsaKey)
	if e != nil {
		t.Fatal(e)
	}
	asn1.Unmarshal(rsaPKCS8, &nested)
	nested.PrivateKey = badRSA
	badNestedRSA, e := asn1.Marshal(nested)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		kind string
		der  []byte
	}{{"RSA PRIVATE KEY", badRSA}, {"PRIVATE KEY", badNestedRSA}} {
		if privateKeyOnly(pem.EncodeToMemory(&pem.Block{Type: tc.kind, Bytes: tc.der})) {
			t.Error("unrecognized RSA key field accepted")
		}
	}
	if !privateKeyOnly(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: rsaDER})) {
		t.Fatal("legitimate PKCS1 key rejected")
	}
}
func TestPKCS8LegitimateAttributesPreserved(t *testing.T) {
	p, _ := PrepareTLS("router.test", TLSState{})
	cert, key, _ := p.ServerPair()
	block, _ := pem.Decode(key)
	oid, e := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20})
	if e != nil {
		t.Fatal(e)
	}
	value, e := asn1.Marshal("router")
	if e != nil {
		t.Fatal(e)
	}
	values, e := asn1.Marshal(asn1.RawValue{Class: 0, Tag: asn1.TagSet, IsCompound: true, Bytes: value})
	if e != nil {
		t.Fatal(e)
	}
	attribute, e := asn1.Marshal(asn1.RawValue{Class: 0, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(oid, values...)})
	if e != nil {
		t.Fatal(e)
	}
	attrs, e := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: attribute})
	if e != nil {
		t.Fatal(e)
	}
	der := appendKeyField(t, block.Bytes, attrs)
	withAttrs := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	q, e := PrepareTLS("router.test", ExistingTLS(cert, withAttrs, nil))
	if e != nil {
		t.Fatal(e)
	}
	_, actual, _ := q.ServerPair()
	if !bytes.Equal(actual, withAttrs) {
		t.Fatal("legitimate attributes changed")
	}
}
