# sql-cert-inspector

A command-line tool that inspects the TLS certificate and Kerberos configuration of a SQL Server instance. Connects at the raw TDS protocol level and captures the certificate from the TLS handshake **without requiring SQL Server authentication**.

## Features

- **No authentication required** — extracts the certificate from the TLS handshake (PRELOGIN phase), before any login attempt
- **Full certificate details** — Subject, Issuer, SANs, thumbprint (SHA-1 and SHA-256), key algorithm/size, signature algorithm, validity dates, and more
- **Connection security metadata** — TLS protocol version, cipher suite, SQL Server version, encryption mode
- **Certificate health checks** — warns about expired certs, expiring soon, self-signed, hostname mismatch, weak keys, deprecated algorithms, missing SANs (CN-only), missing Server Authentication EKU
- **SAN cross-reference** — validates CNAME targets and reverse DNS hostnames appear in the certificate's SANs; optionally performs SPN lookups for each SAN hostname (`--full-spn-diagnostics`) and full certificate inspection for each SAN (`--test-san-connectivity`)
- **Full certificate chain** — optionally display intermediate and root CA certificates
- **Kerberos diagnostics** — SPN registration lookup via LDAP, DNS forward/reverse validation, CNAME detection (via P/Invoke to `DnsQuery_W` for actual DNS record types), SPN account owner identification, and `setspn` remediation commands when SPNs are missing
- **Smart hostname handling** — short (non-FQDN) hostnames are automatically resolved to their FQDN for certificate matching and SPN construction, avoiding false mismatch warnings
- **TDS 8.0 (Strict) support** — connect to servers using strict encryption (`--encrypt-strict` / `--tds8`) where TLS negotiation precedes all TDS traffic; auto-fallback between TDS 7.x and 8.0 with user guidance
- **Named instance support** — resolves ports via SQL Server Browser service (UDP 1434)
- **JSON output** — machine-readable output for scripting and automation
- **Colored console output** — auto-detects redirected output, suppresses colors when piping

> **Note:** Extended Protection for Authentication (EPA / Channel Binding) is not currently inspected by this tool, as it is negotiated during the LOGIN phase which we never reach. EPA is on our roadmap — see [ARCHITECTURE.md](ARCHITECTURE.md#extended-protection-for-authentication-epa) for technical details and [#15](https://github.com/HannahVernon/sql-cert-inspector/issues/15) for tracking.

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
| `--output [filename]` | `-o` | Write JSON output to a file. If no filename is given, auto-generates from `--server` value. Suppresses console output. |
| `--show-full-certificate-chain` | | Display the full certificate chain |
| `--skip-kerberos` | | Skip Kerberos SPN diagnostics (DNS diagnostics still run) |
| `--skip-dns` | | Skip DNS diagnostics (Kerberos SPN lookups still run using raw hostname) |
| `--full-spn-diagnostics` | | Check all SPN variants including portless base SPNs and SPN coverage for each certificate SAN hostname |
| `--test-san-connectivity` | | Perform a full certificate inspection for each DNS name in the certificate's SANs |
| `--encrypt-strict` | `--tds8` | Use TDS 8.0 strict encryption (TLS before PRELOGIN) |
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

# Save JSON to a specific file
sql-cert-inspector --server myserver --output report.json

# Save JSON with auto-generated filename (myserver.json)
sql-cert-inspector --server myserver --output

# Save JSON for a named instance (myserver-SQLEXPRESS.json)
sql-cert-inspector --server myserver\SQLEXPRESS -o

# Full certificate chain
sql-cert-inspector --server myserver --show-full-certificate-chain

# Skip SPN checks only
sql-cert-inspector --server myserver --skip-kerberos

# Skip DNS checks only
sql-cert-inspector --server myserver --skip-dns

# With custom timeout
sql-cert-inspector --server myserver --timeout 10

# Connect to a server requiring strict encryption (TDS 8.0)
sql-cert-inspector --server myserver --encrypt-strict

# Test SAN connectivity — full cert inspection for each SAN hostname
sql-cert-inspector --server myserver --test-san-connectivity

# Full SPN diagnostics with SAN coverage
sql-cert-inspector --server myserver --full-spn-diagnostics
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
  Record Types              A
  Resolved IPs              10.200.24.228
  Reverse Lookup            myserver.corp.example.com
  Forward/Reverse Match     OK

═══ Kerberos SPN Registration ═══
  FQDN + Port          MSSQLSvc/myserver.corp.example.com:22136  REGISTERED → svc-sql-prod (User)
  FQDN + Instance      MSSQLSvc/myserver.corp.example.com:SQLPROD  REGISTERED → svc-sql-prod (User)
  Short + Port         MSSQLSvc/myserver:22136  NOT FOUND
  Short + Instance     MSSQLSvc/myserver:SQLPROD  NOT FOUND

[PASS] No Kerberos issues detected.
```

> **SPN scope:** By default, only port- and instance-specific SPNs are checked — these
> are what SQL Server registers for TCP connections and what client drivers use. Portless
> base SPNs (used by non-TCP protocols like named pipes) are only shown with
> `--full-spn-diagnostics`. This applies to standalone instances, AG listeners, and
> failover cluster virtual names — the SPN format is the same for all.
>
> When missing SPNs are detected, the tool suggests `setspn` commands using only the
> FQDN-qualified port and instance variants, which are safe to register without risk of
> conflicting with other instances on the same host.
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
| `6` | **File write error** — could not write the output file specified by `--output` |

## How it works

### TDS 7.x (default)

1. Resolves the hostname to IP addresses via DNS (skipped when the target is already an IP address)
2. Opens a TCP connection — if DNS returns multiple IPs, connects to all of them simultaneously and uses whichever responds first (similar to `MultiSubnetFailover=True` in SqlClient)
3. Sends a TDS PRELOGIN packet requesting encryption
4. Parses the PRELOGIN response (SQL Server version, encryption support)
5. If encryption is supported, performs a TLS handshake wrapped inside TDS packets
6. Extracts the server certificate and TLS connection metadata
7. Performs DNS resolution via `DnsQuery_W` P/Invoke for accurate record type detection (A, AAAA, CNAME), reverse lookup, and SPN lookup via LDAP (unless `--skip-kerberos`)
8. Disconnects — no LOGIN packet is ever sent, so no authentication is needed

### TDS 8.0 Strict (`--encrypt-strict`)

1. Resolves hostname and opens TCP connection (same as TDS 7.x)
2. Performs a standard TLS handshake directly on the TCP socket (like HTTPS — no TDS wrapping)
3. Extracts the server certificate and TLS connection metadata from the TLS handshake
4. Sends a TDS PRELOGIN packet *inside* the encrypted tunnel to retrieve SQL Server version
5. Performs Kerberos/DNS diagnostics (unless `--skip-kerberos`)
6. Disconnects

### Auto-fallback

If the initial protocol fails with what appears to be a protocol mismatch (e.g., connection reset, unexpected response), the tool automatically retries with the alternate protocol. On success, it displays guidance suggesting the correct option for that server:

- *"This server requires strict encryption (TDS 8.0). Use `--encrypt-strict` to connect directly and avoid a retry."*
- *"This server does not support strict encryption. Omit `--encrypt-strict` to connect directly."*

### Multi-subnet failover

When a hostname (such as an Availability Group listener or a CNAME pointing to one) resolves to multiple IP addresses, the tool automatically races connections to all IPs in parallel — for both SQL Browser UDP queries and TCP connections. This avoids the ~21-second sequential timeout that occurs when the first IP is unreachable after a multi-subnet AG failover.

This mirrors the behavior of `MultiSubnetFailover=True` in Microsoft.Data.SqlClient, but is applied automatically whenever DNS returns multiple IPs — no flag or configuration needed.

The output shows all resolved IPs and which one was used for the connection.

For more details, see [ARCHITECTURE.md](ARCHITECTURE.md).

## TDS Protocol Compatibility

This tool supports both TDS 7.x and TDS 8.0 (Strict) protocol flows.

| SQL Server Version | TDS Version | Supported |
|---|---|---|
| SQL Server 2005 | 7.2 | ✅ Yes |
| SQL Server 2008 / 2008 R2 | 7.3 | ✅ Yes |
| SQL Server 2012–2019 | 7.4 | ✅ Yes |
| SQL Server 2022 | 7.4 / 8.0 | ✅ Yes (both modes) |
| SQL Server 2025 | 7.4 / 8.0 | ✅ Yes (both modes) |
| Azure SQL Database | 7.4 / 8.0 | ✅ Yes (both modes) |

**TDS 7.x** (default): The PRELOGIN packet is sent in cleartext, then TLS is negotiated inside TDS packet wrappers. This has been the standard flow since SQL Server 2005.

**TDS 8.0 Strict** (`--encrypt-strict`): Introduced in SQL Server 2022, TLS negotiation occurs *before* any TDS packets — like HTTPS. Use `--encrypt-strict` for servers configured with `Encrypt=Strict`.

## References

- [MS-TDS: Tabular Data Stream Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/b46a581a-39de-4745-b076-ec4dbb7d13ec) — Microsoft's official TDS protocol specification (covers TDS 7.x and 8.0)
- [TDS 8.0 and Strict Encryption](https://learn.microsoft.com/en-us/sql/relational-databases/security/networking/tds-8?view=sql-server-ver16) — How TDS 8.0 changes the TLS handshake order and its compatibility matrix

## Versioning

This project uses [MinVer](https://github.com/adamralph/minver) for automatic version derivation from git tags. Version numbers follow the format `v{Major}.{Minor}.{Patch}`:

- **Major** — manually bumped for breaking changes
- **Minor** — auto-incremented on each PR merge to main
- **Patch** — set to the merged PR number for traceability

## License

MIT
