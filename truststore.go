package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// LoadTrustPool loads a certificate pool from path. Returns nil when path is
// empty, which causes tls.Config to use the OS system certificate pool.
func LoadTrustPool(path, password string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading truststore %q: %w", path, err)
	}
	format, err := detectFormat(path)
	if err != nil {
		return nil, fmt.Errorf("detecting truststore format: %w", err)
	}
	switch format {
	case FormatPEM:
		return loadPEMTrustPool(data)
	case FormatPKCS12:
		pool, err := loadPKCS12TrustPool(data, password)
		if err != nil && password == "" {
			// May be a raw DER-encoded single certificate.
			if cert, derErr := x509.ParseCertificate(data); derErr == nil {
				p := x509.NewCertPool()
				p.AddCert(cert)
				return p, nil
			}
		}
		return pool, err
	default:
		return nil, fmt.Errorf("unsupported truststore format")
	}
}

func loadPEMTrustPool(data []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest := data
	found := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate in PEM truststore: %w", err)
		}
		pool.AddCert(cert)
		found = true
	}
	if !found {
		// Try the whole file as raw DER.
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("no certificates found in truststore")
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

func loadPKCS12TrustPool(data []byte, password string) (*x509.CertPool, error) {
	certs, err := pkcs12.DecodeTrustStore(data, password)
	if err != nil {
		return nil, fmt.Errorf("decoding PKCS12 truststore: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PKCS12 truststore")
	}
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool, nil
}
