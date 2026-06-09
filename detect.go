package main

import (
	"os"
	"path/filepath"
	"strings"
)

type StoreFormat int

const (
	FormatPEM    StoreFormat = iota
	FormatPKCS12 StoreFormat = iota
)

// detectFormat determines the store format from file extension and magic bytes.
func detectFormat(path string) (StoreFormat, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".pem", ".crt", ".cer":
		return FormatPEM, nil
	case ".p12", ".pfx":
		return FormatPKCS12, nil
	}
	// No recognizable extension: peek at magic bytes.
	f, err := os.Open(path)
	if err != nil {
		return FormatPEM, err
	}
	defer f.Close()

	buf := make([]byte, 4)
	n, _ := f.Read(buf)
	if n == 0 {
		return FormatPEM, nil
	}
	// ASN.1 SEQUENCE tag 0x30 → PKCS12 (or raw DER cert; handled by callers)
	if buf[0] == 0x30 {
		return FormatPKCS12, nil
	}
	// "----" → PEM
	return FormatPEM, nil
}
