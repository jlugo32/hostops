// Package testhost builds fake host trees and certificates for tests,
// testscript fixtures and the eval corpus. Nothing here runs in production.
package testhost

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// CertSpec describes a leaf certificate and its fake issuer.
type CertSpec struct {
	Domains   []string
	IssuerCN  string // e.g. "R11" or "(STAGING) Ersatz Edamame E1"
	IssuerOrg string // e.g. "Let's Encrypt" or "(STAGING) Let's Encrypt"
	NotBefore time.Time
	NotAfter  time.Time
	Serial    int64
}

// MakeCert returns PEM leaf+chain ("fullchain") and the leaf's key.
func MakeCert(s CertSpec) (fullchain, key []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(s.Serial + 1000),
		Subject:               pkix.Name{CommonName: s.IssuerCN, Organization: []string{s.IssuerOrg}},
		NotBefore:             s.NotBefore.Add(-24 * time.Hour),
		NotAfter:              s.NotAfter.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(s.Serial),
		Subject:      pkix.Name{CommonName: s.Domains[0]},
		DNSNames:     s.Domains,
		NotBefore:    s.NotBefore,
		NotAfter:     s.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	kb, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, nil, err
	}
	fullchain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return fullchain, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), nil
}
