package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// LoadClientCert loads a client certificate and private key from path.
// Returns nil, nil when path is empty (client auth disabled).
func LoadClientCert(path, password string) (*tls.Certificate, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading keystore %q: %w", path, err)
	}
	format, err := detectFormat(path)
	if err != nil {
		return nil, fmt.Errorf("detecting keystore format: %w", err)
	}
	switch format {
	case FormatPEM:
		return loadPEMClientCert(data)
	case FormatPKCS12:
		return loadPKCS12ClientCert(data, password)
	default:
		return nil, fmt.Errorf("unsupported keystore format")
	}
}

// loadPEMClientCert expects a combined PEM file with a CERTIFICATE block and
// a private key block (PRIVATE KEY, RSA PRIVATE KEY, or EC PRIVATE KEY).
func loadPEMClientCert(data []byte) (*tls.Certificate, error) {
	var certDER []byte
	var keyDER []byte
	var keyType string
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			if certDER == nil {
				certDER = block.Bytes
			}
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if keyDER == nil {
				keyDER = block.Bytes
				keyType = block.Type
			}
		}
	}
	if certDER == nil {
		return nil, fmt.Errorf("no CERTIFICATE block found in PEM keystore")
	}
	if keyDER == nil {
		return nil, fmt.Errorf("no private key block found in PEM keystore; file must contain PRIVATE KEY, RSA PRIVATE KEY, or EC PRIVATE KEY")
	}

	var privKey any
	var err error
	switch keyType {
	case "PRIVATE KEY":
		privKey, err = x509.ParsePKCS8PrivateKey(keyDER)
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(keyDER)
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(keyDER)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	if err := validateKeyPair(leaf, privKey); err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
		Leaf:        leaf,
	}, nil
}

func loadPKCS12ClientCert(data []byte, password string) (*tls.Certificate, error) {
	privKey, cert, err := pkcs12.Decode(data, password)
	if err != nil {
		return nil, fmt.Errorf("decoding PKCS12 keystore: %w", err)
	}
	if err := validateKeyPair(cert, privKey); err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privKey,
		Leaf:        cert,
	}, nil
}

func validateKeyPair(cert *x509.Certificate, privKey any) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key type mismatch: certificate has RSA public key")
		}
		if pub.N.Cmp(priv.PublicKey.N) != 0 {
			return fmt.Errorf("private key does not match certificate")
		}
	case *ecdsa.PublicKey:
		priv, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key type mismatch: certificate has ECDSA public key")
		}
		pubBytes, err1 := x509.MarshalPKIXPublicKey(pub)
		privPubBytes, err2 := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err1 != nil || err2 != nil || !bytes.Equal(pubBytes, privPubBytes) {
			return fmt.Errorf("private key does not match certificate")
		}
	case ed25519.PublicKey:
		priv, ok := privKey.(ed25519.PrivateKey)
		if !ok {
			return fmt.Errorf("private key type mismatch: certificate has Ed25519 public key")
		}
		if !bytes.Equal(pub, priv.Public().(ed25519.PublicKey)) {
			return fmt.Errorf("private key does not match certificate")
		}
	}
	return nil
}
