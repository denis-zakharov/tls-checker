package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// PrintConnectionInfo prints TLS session details before the certificate chain.
func PrintConnectionInfo(state *tls.ConnectionState) {
	fmt.Printf("Connected:  TLS %s | Cipher: %s\n",
		tlsVersionName(state.Version),
		tls.CipherSuiteName(state.CipherSuite))
	if state.NegotiatedProtocol != "" {
		fmt.Printf("ALPN:       %s\n", state.NegotiatedProtocol)
	}
	fmt.Println()
}

// PrintCertInfo prints all relevant fields for one certificate in the chain.
func PrintCertInfo(cert *x509.Certificate, index int) {
	label := "intermediate"
	if index == 0 {
		label = "leaf"
	} else if cert.IsCA {
		label = "CA"
	}
	fmt.Printf("--- Certificate [%d] (%s) ---\n", index, label)
	fmt.Printf("  %-24s %s\n", "Subject:", cert.Subject.String())
	fmt.Printf("  %-24s %s\n", "Issuer:", cert.Issuer.String())
	fmt.Printf("  %-24s %s\n", "Serial Number:", formatSerial(cert.SerialNumber))
	fmt.Printf("  %-24s %s\n", "Not Before:", cert.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  %-24s %s\n", "Not After:", cert.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC"))

	days := DaysUntilExpiry(cert.NotAfter)
	status := certStatus(cert)
	statusStr := colorStatus(status)
	if days < 0 {
		fmt.Printf("  %-24s %d days ago  %s\n", "Days Until Expiry:", -days, statusStr)
	} else {
		fmt.Printf("  %-24s %d  %s\n", "Days Until Expiry:", days, statusStr)
	}

	fmt.Printf("  %-24s %s\n", "Key:", KeyInfo(cert.PublicKey))
	fmt.Printf("  %-24s %s\n", "Signature Alg:", cert.SignatureAlgorithm.String())
	fmt.Printf("  %-24s %s\n", "DNS SANs:", joinOrNone(cert.DNSNames))
	fmt.Printf("  %-24s %s\n", "IP SANs:", joinIPsOrNone(cert.IPAddresses))
	fmt.Printf("  %-24s %s\n", "Email SANs:", joinOrNone(cert.EmailAddresses))
	fmt.Printf("  %-24s %v\n", "Is CA:", cert.IsCA)
	fmt.Println()
}

// certValidity represents the temporal validity state of a certificate.
type certValidity int

const (
	validCert       certValidity = iota
	expiredCert     certValidity = iota
	notYetValidCert certValidity = iota
)

func certStatus(cert *x509.Certificate) certValidity {
	now := time.Now()
	if now.After(cert.NotAfter) {
		return expiredCert
	}
	if now.Before(cert.NotBefore) {
		return notYetValidCert
	}
	return validCert
}

func colorStatus(v certValidity) string {
	tty := isTerminal()
	switch v {
	case expiredCert:
		if tty {
			return "\033[31m[EXPIRED]\033[0m"
		}
		return "[EXPIRED]"
	case notYetValidCert:
		if tty {
			return "\033[33m[NOT YET VALID]\033[0m"
		}
		return "[NOT YET VALID]"
	default:
		if tty {
			return "\033[32m[VALID]\033[0m"
		}
		return "[VALID]"
	}
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// KeyInfo returns a human-readable description of a public key type and size.
func KeyInfo(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-%s", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("Unknown (%T)", pub)
	}
}

// DaysUntilExpiry returns days remaining until t; negative means already expired.
func DaysUntilExpiry(t time.Time) int {
	return int(time.Until(t).Hours() / 24)
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}

func formatSerial(n *big.Int) string {
	b := n.Bytes()
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	if len(parts) == 0 {
		return "00"
	}
	return strings.Join(parts, ":")
}

func joinOrNone(ss []string) string {
	if len(ss) == 0 {
		return "(none)"
	}
	return strings.Join(ss, ", ")
}

func joinIPsOrNone(ips []net.IP) string {
	if len(ips) == 0 {
		return "(none)"
	}
	ss := make([]string, len(ips))
	for i, ip := range ips {
		ss[i] = ip.String()
	}
	return strings.Join(ss, ", ")
}
