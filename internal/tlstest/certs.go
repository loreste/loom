// Package tlstest generates ephemeral certs for mTLS integration tests.
package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// Bundle holds CA, server, and client material.
type Bundle struct {
	CACert            *x509.Certificate
	ServerCert        tls.Certificate
	ClientCert        tls.Certificate
	ClientX509        *x509.Certificate
	ClientFingerprint string
}

// Generate creates a test PKI (CA + server + client).
func Generate() (*Bundle, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "loom-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	srvTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	srvCert, err := tlsCert(srvDER, srvKey)
	if err != nil {
		return nil, err
	}

	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cliTpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "svc-payments"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTpl, caCert, &cliKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	cliCert, err := tlsCert(cliDER, cliKey)
	if err != nil {
		return nil, err
	}
	cliX509, err := x509.ParseCertificate(cliDER)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(cliDER)

	return &Bundle{
		CACert:            caCert,
		ServerCert:        srvCert,
		ClientCert:        cliCert,
		ClientX509:        cliX509,
		ClientFingerprint: hex.EncodeToString(sum[:]),
	}, nil
}

// ServerTLSConfig requires and verifies client certs against the CA.
func (b *Bundle) ServerTLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(b.CACert)
	return &tls.Config{
		Certificates: []tls.Certificate{b.ServerCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
}

// ClientTLSConfig presents the client cert and trusts the CA.
func (b *Bundle) ClientTLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(b.CACert)
	return &tls.Config{
		Certificates: []tls.Certificate{b.ClientCert},
		RootCAs:      pool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}
}

func tlsCert(der []byte, key *ecdsa.PrivateKey) (tls.Certificate, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
