package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

type config struct {
	endpoint       string
	truststorePath string
	truststorePass string
	keystorePath   string
	keystorePass   string
	proxyURL       string
	serverName     string
	timeout        time.Duration
	insecure       bool
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(3)
	}
	os.Exit(run(cfg))
}

func run(cfg config) int {
	trustPool, err := LoadTrustPool(cfg.truststorePath, cfg.truststorePass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 3
	}

	clientCert, err := LoadClientCert(cfg.keystorePath, cfg.keystorePass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 3
	}

	if cfg.insecure {
		fmt.Fprintln(os.Stderr, "WARNING: certificate verification is disabled (-insecure)")
	}

	state, err := Dial(DialConfig{
		Addr:       cfg.endpoint,
		ServerName: cfg.serverName,
		ProxyURL:   cfg.proxyURL,
		RootCAs:    trustPool,
		ClientCert: clientCert,
		Timeout:    cfg.timeout,
		Insecure:   cfg.insecure,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	PrintConnectionInfo(state)

	anyInvalid := false
	for i, cert := range state.PeerCertificates {
		PrintCertInfo(cert, i)
		if certStatus(cert) != validCert {
			anyInvalid = true
		}
	}

	if anyInvalid {
		return 1
	}
	return 0
}

func parseFlags() (config, error) {
	var cfg config
	flag.StringVar(&cfg.truststorePath, "truststore", "", "truststore file (PEM/CRT/P12); omit to use system roots")
	flag.StringVar(&cfg.truststorePass, "truststore-password", "", "truststore password")
	flag.StringVar(&cfg.keystorePath, "keystore", "", "keystore file for client authentication (PEM/P12)")
	flag.StringVar(&cfg.keystorePass, "keystore-password", "", "keystore password")
	flag.StringVar(&cfg.proxyURL, "proxy", "", "proxy URL: http://host:port or socks5://host:port")
	flag.StringVar(&cfg.serverName, "servername", "", "override SNI server name (cannot be an IP address)")
	flag.DurationVar(&cfg.timeout, "timeout", 30*time.Second, "connection timeout")
	flag.BoolVar(&cfg.insecure, "insecure", false, "skip certificate verification (prints warning)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: tls-checker [flags] host:port\n\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExit codes: 0=valid  1=expired/not-yet-valid  2=handshake error  3=bad args/file\n")
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		return cfg, fmt.Errorf("exactly one host:port argument required")
	}
	cfg.endpoint = flag.Arg(0)

	host, port, err := net.SplitHostPort(cfg.endpoint)
	if err != nil {
		return cfg, fmt.Errorf("invalid endpoint %q: must be host:port", cfg.endpoint)
	}
	if host == "" || port == "" {
		return cfg, fmt.Errorf("endpoint must include both host and port")
	}

	if cfg.serverName != "" && net.ParseIP(cfg.serverName) != nil {
		return cfg, fmt.Errorf("-servername %q cannot be an IP address", cfg.serverName)
	}

	return cfg, nil
}
