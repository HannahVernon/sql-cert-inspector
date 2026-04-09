# sql-cert-inspector

A command-line tool that inspects the TLS certificate and Kerberos configuration of a SQL Server instance. Connects at the raw TDS protocol level and captures the certificate from the TLS handshake **without requiring SQL Server authentication**.

## Features

- **No authentication required** — extracts the certificate from the TLS handshake (PRELOGIN phase), before any login attempt
- **Full certificate details** — Subject, Issuer, SANs, thumbprint (SHA-1 and SHA-256), key algorithm/size, signature algorithm, validity dates, and more
- **Connection security metadata** — TLS protocol version, cipher suite, SQL Server version, encryption mode
- **Certificate health checks** — warns about expired certs, expiring soon, self-signed, hostname mismatch, weak keys, deprecated algorithms
- **Full certificate chain** — optionally display intermediate and root CA certificates
- **Kerberos diagnostics** — SPN registration lookup via LDAP, DNS forward/reverse validation, CNAME detection, SPN account owner identification
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
| `--skip-kerberos` | | Skip Kerberos and DNS diagnostics |
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

# Skip Kerberos diagnostics
sql-cert-inspector --server myserver --skip-kerberos

# With custom timeout
sql-cert-inspector --server myserver --timeout 10
```

### Sample output

```
Resolving instance 'SQLPROD' via SQL Server Browser service on myserver.corp.example.com:1434 (UDP)...
Resolved to TCP port 22136.
Connecting to myserver.corp.example.com\SQLPROD on TCP port 22136...
Running Kerberos and DNS diagnostics...

═══ Connection Details ═══
  Server                    myserver.corp.example.com\SQLPROD
  Resolved Host             myserver.corp.example.com
  Resolved Port             22136
  Instance Name             SQLPROD
  SQL Server Version        15.0.4455.0
  Encryption Mode           ON

═══ TLS Connection Security ═══
  TLS Protocol              Tls12
  Cipher Suite              TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  Key Exchange              ECDHE (384 bits)
  Hash Algorithm            SHA-384

═══ Server Certificate ═══
  Subject                   CN=myserver.corp.example.com, OU=DBA, O=Contoso, S=Ontario, C=CA
  Issuer                    CN=Contoso Private SSL Int1, O=Contoso Inc., L=Toronto, S=ON, C=CA
  Serial Number             1F756738BE512E6925712F52FCDE14EF
  Thumbprint (SHA-1)        7D70F7D229C0D639BF68E0CBB3B1FF02B0491732
  Fingerprint (SHA-256)     C75C49854AEFC52D7C6C74F7590181824605038AC55A485CA9631D695AC85878
  Valid From                2025-09-24 14:12:31 UTC
  Valid To                  2026-09-24 14:12:31 UTC (167 days remaining)
  Key Algorithm             RSA (4096 bits)
  Signature Algorithm       sha256RSA
  Certificate Version       V3
  Self-Signed               No
  Is CA                     No
  Key Usage                 KeyEncipherment, DigitalSignature
  Enhanced Key Usage        Server Authentication, Client Authentication
  SANs                      DNS:myserver.corp.example.com, DNS:myserver-ag.corp.example.com

[PASS] No certificate issues detected.

═══ DNS Resolution ═══
  Requested Hostname        myserver.corp.example.com
  Resolved IPs              10.200.24.228
  Reverse Lookup            myserver.corp.example.com
  Forward/Reverse Match     OK

═══ Kerberos SPN Registration ═══
  Expected SPN (port)       MSSQLSvc/myserver.corp.example.com:22136
  Expected SPN (base)       MSSQLSvc/myserver.corp.example.com
  Port SPN                  REGISTERED → svc-sql-prod (User)
  Base SPN                  NOT FOUND

═══ Kerberos Health Checks ═══
  [INFO] Port-specific SPN is registered and base SPN is absent. This is the expected
         configuration for a named instance - a base SPN without a port could conflict
         with other instances on the same host.
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
6. Performs DNS forward/reverse resolution and SPN lookup via LDAP (unless `--skip-kerberos`)
7. Disconnects — no LOGIN packet is ever sent, so no authentication is needed

For more details, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Versioning

This project uses [MinVer](https://github.com/adamralph/minver) for automatic version derivation from git tags. Version numbers follow the format `v{Major}.{Minor}.{Patch}`:

- **Major** — manually bumped for breaking changes
- **Minor** — auto-incremented on each PR merge to main
- **Patch** — set to the merged PR number for traceability

## License

MIT
