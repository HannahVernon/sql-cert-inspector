# sql-cert-inspector

A command-line tool that inspects the TLS certificate used by a SQL Server instance to encrypt client connections. Connects at the raw TDS protocol level and captures the certificate from the TLS handshake **without requiring SQL Server authentication**.

## Features

- **No authentication required** — extracts the certificate from the TLS handshake (PRELOGIN phase), before any login attempt
- **Full certificate details** — Subject, Issuer, SANs, thumbprint (SHA-1 and SHA-256), key algorithm/size, signature algorithm, validity dates, and more
- **Connection security metadata** — TLS protocol version, cipher suite, SQL Server version, encryption mode
- **Certificate health checks** — warns about expired certs, expiring soon, self-signed, hostname mismatch, weak keys, deprecated algorithms
- **Full certificate chain** — optionally display intermediate and root CA certificates
- **Named instance support** — resolves ports via SQL Server Browser service (UDP 1434)
- **JSON output** — machine-readable output for scripting and automation
- **Colored console output** — auto-detects redirected output, suppresses colors when piping

## Installation

Download the self-contained executable from the [Releases](https://github.com/HannahVernon/sql-cert-inspector/releases) page. No .NET runtime required.

### Build from source

```bash
dotnet publish -p:PublishProfile=Properties\PublishProfiles\win-x64.pubxml
```

The executable will be in `bin\publish\win-x64\sql-cert-inspector.exe`.

## Usage

```
sql-cert-inspector --server <server> [options]
```

### Options

| Option | Alias | Description |
|---|---|---|
| `--server <server>` | `-s` | SQL Server target (**required**). Accepts `server`, `server\instance`, `server,port`, or `ip,port` |
| `--port <port>` | `-p` | TCP port (alternative to `,port` or `\instance` syntax) |
| `--timeout <seconds>` | `-t` | Connection timeout in seconds (default: 5) |
| `--json` | | Output in JSON format |
| `--show-full-certificate-chain` | | Display the full certificate chain |
| `--no-color` | | Disable colored console output |
| `--help` | | Show help |
| `--version` | | Show version |

### Examples

```bash
# Inspect default instance on a server
sql-cert-inspector --server myserver

# Inspect a named instance (resolved via SQL Browser)
sql-cert-inspector --server myserver\SQLEXPRESS

# Inspect with explicit port
sql-cert-inspector --server myserver,1434

# Or using the --port flag
sql-cert-inspector --server myserver --port 1434

# JSON output for scripting
sql-cert-inspector --server myserver --json

# Full certificate chain
sql-cert-inspector --server myserver --show-full-certificate-chain

# With custom timeout
sql-cert-inspector --server myserver --timeout 10
```

### Sample output

```
Connecting to myserver on TCP port 1433...

═══ Connection Details ═══
  Server                     myserver
  Resolved Host              myserver
  Resolved Port              1433
  SQL Server Version         16.0.4175.1
  Encryption Mode            ON

═══ TLS Connection Security ═══
  TLS Protocol               Tls13
  Cipher Suite               TLS_AES_256_GCM_SHA384
  Key Exchange               N/A (TLS 1.3 — key exchange is implicit)
  Hash Algorithm             N/A (TLS 1.3 — hash is part of cipher suite)

═══ Server Certificate ═══
  Subject                    CN=myserver.domain.com
  Issuer                     CN=Enterprise CA, O=Contoso
  Serial Number              4A00000123456789AB
  Thumbprint (SHA-1)         A1B2C3D4E5F6...
  Fingerprint (SHA-256)      1234ABCD5678...
  Valid From                 2024-01-15 00:00:00 UTC
  Valid To                   2026-01-15 23:59:59 UTC (640 days remaining)
  Key Algorithm              RSA (2048 bits)
  Signature Algorithm        sha256RSA
  Certificate Version        V3
  Self-Signed                No
  Is CA                      No
  Key Usage                  DigitalSignature, KeyEncipherment
  Enhanced Key Usage         Server Authentication
  SANs                       DNS:myserver.domain.com, DNS:myserver

✓ No certificate issues detected.
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | **Success** — connected, certificate displayed, no critical issues |
| `1` | **Connection/certificate failure** — TCP connection failed, TLS handshake failed, or certificate has error-severity issues (e.g., expired) |
| `2` | **Encryption not enabled** — the server does not encrypt connections |
| `3` | **Browser resolution failure** — could not resolve named instance via SQL Server Browser service |
| `4` | **Invalid arguments** — bad or conflicting command-line options |
| `5` | **Unexpected error** — an unhandled exception occurred |

## How it works

1. Opens a TCP connection to the SQL Server port
2. Sends a TDS PRELOGIN packet requesting encryption
3. Parses the PRELOGIN response (SQL Server version, encryption support)
4. If encryption is supported, performs a TLS handshake wrapped inside TDS packets
5. Extracts the server certificate and TLS connection metadata
6. Disconnects — no LOGIN packet is ever sent, so no authentication is needed

## License

MIT
