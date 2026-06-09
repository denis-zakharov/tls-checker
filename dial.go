package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// DialConfig holds all parameters for establishing a TLS connection.
type DialConfig struct {
	Addr       string
	ServerName string
	ProxyURL   string
	RootCAs    *x509.CertPool
	ClientCert *tls.Certificate
	Timeout    time.Duration
	Insecure   bool
}

// Dial connects to Addr (optionally through a proxy), performs the TLS
// handshake, and returns the resulting ConnectionState.
func Dial(cfg DialConfig) (*tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	serverName := cfg.ServerName
	if serverName == "" && net.ParseIP(host) == nil {
		serverName = host
	}

	tlsCfg := &tls.Config{
		ServerName:         serverName,
		RootCAs:            cfg.RootCAs,
		InsecureSkipVerify: cfg.Insecure, //nolint:gosec
	}
	if cfg.ClientCert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cfg.ClientCert}
	}

	var rawConn net.Conn
	if cfg.ProxyURL != "" {
		rawConn, err = dialThroughProxy(ctx, cfg.Addr, cfg.ProxyURL)
	} else {
		rawConn, err = (&net.Dialer{}).DialContext(ctx, "tcp", cfg.Addr)
	}
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", cfg.Addr, err)
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	state := tlsConn.ConnectionState()
	tlsConn.Close()
	return &state, nil
}

func dialThroughProxy(ctx context.Context, addr, proxyURL string) (net.Conn, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parsing proxy URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
		return dialHTTPConnect(ctx, addr, u)
	case "socks5", "socks5h":
		return dialSOCKS5(ctx, addr, u)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use http:// or socks5://)", u.Scheme)
	}
}

func dialHTTPConnect(ctx context.Context, addr string, proxyURL *url.URL) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("connecting to proxy %s: %w", proxyURL.Host, err)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	req.Header.Set("User-Agent", "tls-checker")
	if proxyURL.User != nil {
		user := proxyURL.User.Username()
		pass, _ := proxyURL.User.Password()
		encoded := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set("Proxy-Authorization", "Basic "+encoded)
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("writing CONNECT request: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading proxy CONNECT response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	// bufio.Reader may have consumed bytes past the HTTP response headers.
	// Wrap so those buffered bytes are read before falling through to conn.
	return &bufConn{Conn: conn, r: br}, nil
}

func dialSOCKS5(ctx context.Context, addr string, proxyURL *url.URL) (net.Conn, error) {
	var auth *proxy.Auth
	if proxyURL.User != nil {
		pass, _ := proxyURL.User.Password()
		auth = &proxy.Auth{
			User:     proxyURL.User.Username(),
			Password: pass,
		}
	}
	dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("creating SOCKS5 dialer: %w", err)
	}
	type contextDialer interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}
	if cd, ok := dialer.(contextDialer); ok {
		return cd.DialContext(ctx, "tcp", addr)
	}
	return dialer.Dial("tcp", addr)
}

// bufConn wraps net.Conn with a bufio.Reader so bytes buffered during HTTP
// header parsing are not lost when the connection is handed to the TLS stack.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }
