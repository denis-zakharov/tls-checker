# tls-checker

A command-line TLS inspector — a simplified `openssl s_client` written in Go.

Connects to a TLS endpoint, performs the handshake, and prints the full certificate chain with subject, issuer, SANs, validity period, key info, and expiry status. Useful for debugging certificate issues, verifying custom trust stores, and testing mutual TLS setups.

## Install

```sh
go install tls-checker@latest
```

Or build from source:

```sh
git clone ...
cd tls-checker
go build -o tls-checker .
```

## Usage

```
tls-checker [flags] host:port
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-truststore` | — | Trust store file (PEM/CRT/P12). Omit to use system roots. |
| `-truststore-password` | — | Password for the trust store. |
| `-keystore` | — | Key store for client authentication (PEM/P12). |
| `-keystore-password` | — | Password for the key store. |
| `-proxy` | — | Proxy URL: `http://host:port` or `socks5://host:port`. |
| `-servername` | — | Override the SNI server name (cannot be an IP address). |
| `-timeout` | `30s` | Connection timeout. |
| `-insecure` | `false` | Skip certificate verification (prints a warning). |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Handshake succeeded, all certificates valid |
| `1` | Handshake succeeded, at least one certificate expired or not yet valid |
| `2` | TLS handshake failed |
| `3` | Bad arguments or unreadable store file |

## Examples

**Basic check against a public endpoint:**
```sh
tls-checker google.com:443
```

**Use a custom CA bundle (PEM):**
```sh
tls-checker -truststore /etc/ssl/my-ca-bundle.pem internal.corp:8443
```

**Use a PKCS12 trust store:**
```sh
tls-checker -truststore truststore.p12 -truststore-password changeit internal.corp:8443
```

**Client certificate authentication:**
```sh
tls-checker -keystore client.p12 -keystore-password secret api.corp:443
```

The PEM keystore must be a single combined file containing both a `CERTIFICATE` block and a private key block (`PRIVATE KEY`, `RSA PRIVATE KEY`, or `EC PRIVATE KEY`).

**Route through an HTTP CONNECT proxy:**
```sh
tls-checker -proxy http://proxy.corp:3128 external.host:443
```

**Route through a SOCKS5 proxy:**
```sh
tls-checker -proxy socks5://127.0.0.1:1080 external.host:443
```

**Override SNI (e.g. when connecting by IP):**
```sh
tls-checker -servername example.com 203.0.113.1:443
```

**Inspect an expired certificate without failing the handshake:**
```sh
tls-checker -insecure expired.badssl.com:443
```

## Supported formats

| Format | Extension | Trust store | Key store |
|--------|-----------|:-----------:|:---------:|
| PEM / CRT | `.pem` `.crt` `.cer` | ✓ | ✓ |
| PKCS#12 | `.p12` `.pfx` | ✓ | ✓ |

Format is detected by file extension first, then by magic bytes for files with non-standard extensions.

When no `-truststore` is provided, the OS system certificate pool is used.  
When a custom trust store is provided, it replaces the system roots entirely (no merging), matching Java's `-Djavax.net.ssl.trustStore` behaviour.

## Sample output

```
Connected:  TLS 1.3 | Cipher: TLS_AES_128_GCM_SHA256

--- Certificate [0] (leaf) ---
  Subject:                 CN=*.google.com
  Issuer:                  CN=WE2,O=Google Trust Services,C=US
  Serial Number:           e2:d2:15:e5:6d:69:2f:03
  Not Before:              2026-05-18 18:35:28 UTC
  Not After:               2026-08-10 18:35:27 UTC
  Days Until Expiry:       61  [VALID]
  Key:                     ECDSA-P-256
  Signature Alg:           ECDSA-SHA256
  DNS SANs:                *.google.com, *.appengine.google.com, ...
  IP SANs:                 (none)
  Email SANs:              (none)
  Is CA:                   false

--- Certificate [1] (CA) ---
  ...
```
