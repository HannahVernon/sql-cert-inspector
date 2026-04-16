# Architecture

## Overview

`sql-cert-inspector` is a .NET 9 console application that inspects SQL Server connection security without requiring authentication. It operates at the raw TDS (Tabular Data Stream) protocol level, performing only the PRELOGIN handshake and TLS negotiation — it never sends a LOGIN packet.

## Component Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                         Program.cs                               │
│                    (Entry point + orchestration)                 │
│                                                                  │
│  1. Parse CLI args (System.CommandLine)                          │
│  2. Resolve server endpoint                                      │
│  3. Connect and inspect                                          │
│  4. Run Kerberos diagnostics                                     │
│  5. Report results                                               │
└──────┬───────────┬──────────────┬──────────────┬─────────────────┘
       │           │              │              │
       ▼           ▼              ▼              ▼
┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐
│ ServerEnd- │ │ TdsPrelog- │ │ Kerberos-  │ │ ConsoleReporter /  │
│ pointRe-   │ │ inClient   │ │ Inspector  │ │ JsonReporter       │
│ solver     │ │            │ │            │ │                    │
│            │ │ ┌────────┐ │ │ DNS lookup │ │ Colored text or    │
│ Parse host │ │ │TdsPacke│ │ │ SPN lookup │ │ JSON output        │
│ instance   │ │ │t       │ │ │ via LDAP   │ │                    │
│ port       │ │ └────────┘ │ │            │ │                    │
│            │ │ ┌────────┐ │ └────────────┘ └────────────────────┘
│ ┌────────┐ │ │ │TdsPre- │ │
│ │SqlBrow-│ │ │ │loginSt-│ │
│ │serClie-│ │ │ │ream    │ │
│ │nt      │ │ │ └────────┘ │
│ └────────┘ │ │            │
└────────────┘ │ ┌────────┐ │
               │ │Certifi-│ │
               │ │cateAna-│ │
               │ │lyzer   │ │
               │ └────────┘ │
               └────────────┘
```

## Source Files

| File | Responsibility |
|------|----------------|
| `Program.cs` | Entry point. Parses CLI arguments via `System.CommandLine`, orchestrates the inspection pipeline, handles errors, and delegates to the appropriate reporter. |
| `CommandLineOptions.cs` | POCO holding parsed CLI options (`--server`, `--port`, `--timeout`, `--json`, `--show-full-certificate-chain`, `--skip-kerberos`, `--no-color`). |
| `ExitCodes.cs` | Constants for process exit codes (0–5). |
| `ServerEndpointResolver.cs` | Parses the `--server` string into host, instance name, and port components. Validates conflicts between `--port` and port/instance in the server string. |
| `DnsResolver.cs` | P/Invoke wrapper for `DnsQuery_W` (`dnsapi.dll`). Queries A, AAAA, and CNAME records and returns structured results with actual DNS record types. Detects DNS suffix expansion (short name → FQDN) vs true CNAME records. Windows-only. |
| `SqlBrowserClient.cs` | Queries the SQL Server Browser service on UDP 1434 to resolve a named instance to its TCP port. When the hostname resolves to multiple IPs, sends Browser queries to all IPs in parallel and uses the first response. Distinguishes between timeout (instance not found) and connection failure (service unreachable). |
| `TdsPacket.cs` | Reads and writes TDS packet headers (8-byte framing: type, status, length, SPID, packet ID, window). |
| `TdsPreloginStream.cs` | Custom `Stream` implementation that wraps TLS handshake data inside TDS PRELOGIN packets (type 0x12). Required because SQL Server frames TLS records inside TDS during the handshake phase. |
| `TdsPreloginClient.cs` | Core inspection logic. Resolves hostname to IP addresses via DNS, races TCP connections in parallel when multiple IPs are returned (multi-subnet failover), sends a TDS PRELOGIN packet, parses the server's response (SQL version, encryption mode), performs a TLS handshake via `SslStream` over `TdsPreloginStream`, and extracts the server certificate and TLS metadata. |
| `CertificateInfo.cs` | Model class holding extracted certificate details, health warnings, and optional chain certificates. |
| `ConnectionSecurityInfo.cs` | Model class holding connection metadata, TLS properties, the certificate, and Kerberos diagnostics. |
| `CertificateAnalyzer.cs` | Extracts all fields from an `X509Certificate2` (subject, issuer, SANs, key info, etc.) and runs health checks (expiry, self-signed, hostname mismatch, weak keys, deprecated algorithms). Accepts an optional resolved FQDN to avoid false hostname mismatch warnings when a short (non-FQDN) name was used. Builds the certificate chain when requested. |
| `KerberosDiagnostics.cs` | Model class for Kerberos/DNS diagnostic results (SPN lookup results, DNS resolution, DNS record types, resolved FQDN, warnings). |
| `KerberosInspector.cs` | Uses `DnsResolver` for DNS resolution with record type awareness. Performs reverse lookup, CNAME detection (true CNAME vs DNS suffix expansion), and SPN lookup via LDAP `DirectorySearcher`. When input is a non-FQDN short name, uses the resolved FQDN for SPN construction. Runs health checks for DNS mismatches, missing SPNs, and duplicate SPN registrations. Windows-only (`[SupportedOSPlatform("windows")]`). |
| `ConsoleReporter.cs` | Renders results as colored plain text. Auto-detects redirected output and suppresses colors. Maps raw algorithm enum values to human-readable names. |
| `JsonReporter.cs` | Renders results as indented JSON via `System.Text.Json`. Applies the same algorithm name mappings as the console reporter. |
| `Directory.Build.props` | Configures MinVer for automatic version derivation from git tags. |

## Key Design Decisions

### No-Auth Certificate Extraction

SQL Server's TDS protocol performs TLS negotiation during the PRELOGIN phase, *before* the LOGIN packet. The handshake sequence is:

1. **Client → Server**: TDS PRELOGIN packet (type `0x12`) with `ENCRYPTION=ON`
2. **Server → Client**: TDS response (type `0x04`) with server version and encryption support
3. **TLS Handshake**: If encryption is negotiated, TLS records are exchanged wrapped inside TDS PRELOGIN packets
4. **Certificate extracted**: The server presents its certificate during the TLS handshake
5. **Disconnect**: We close the connection without ever sending a LOGIN packet

This means we can inspect any SQL Server's certificate without needing credentials.

### TDS-Wrapped TLS

During the TLS handshake phase, SQL Server wraps TLS records inside TDS packets (type `0x12`). This is non-standard — you can't just point an `SslStream` at a raw TCP socket. The `TdsPreloginStream` class handles this by:

- **Write path**: Wraps outgoing TLS data in TDS PRELOGIN packets
- **Read path**: Strips TDS headers from incoming packets and feeds the raw TLS data to `SslStream`

After the TLS handshake completes, subsequent data (LOGIN, SQL batches) flows as pure TLS — but we never reach that stage.

### SPN Lookup via LDAP

Rather than shelling out to `setspn.exe`, the Kerberos inspector queries Active Directory directly using `System.DirectoryServices.DirectorySearcher` with an LDAP filter on the `servicePrincipalName` attribute. This is:

- Faster (no process spawn)
- More reliable (parses structured data, not command-line output)
- Richer (returns the account name, object class, and distinguished name)

### MinVer Versioning

Version numbers are derived entirely from git tags — no version strings are hardcoded in the project file. This avoids merge conflicts and ensures the version always reflects the repository state. GitHub Actions automatically creates tags on PR merge to main.

## Data Flow

```
CLI args
  │
  ▼
ServerEndpointResolver.Parse()
  │
  ├─ Named instance? ──► SqlBrowserClient.ResolveInstancePort()
  │                        │
  │                        ├─ DNS resolve hostname → IP address(es)
  │                        ├─ UDP 1434 query (parallel if multiple IPs)
  │                        └─► TCP port
  │                                                                    │
  ├─ Explicit port? ───────────────────────────────────────────────────┤
  │                                                                    │
  ▼                                                                    ▼
TdsPreloginClient.InspectAsync(host, port)
  │
  ├─ DNS resolve hostname → IP address(es)
  │   └─ Skip if hostname is already an IP address
  ├─ TCP connect (parallel race if multiple IPs)
  ├─ Send PRELOGIN (request encryption)
  ├─ Parse PRELOGIN response (version, encryption mode)
  ├─ TLS handshake via SslStream + TdsPreloginStream
  ├─ Extract certificate from SslStream.RemoteCertificate
  ├─ Extract TLS metadata (protocol, cipher, key exchange)
  │
  ▼
CertificateAnalyzer.Analyze(cert, hostname, resolvedFqdn)
  │
  ├─ Extract all certificate fields
  ├─ Run health checks (expiry, self-signed, hostname, key strength, sig algo)
  │   └─ Hostname check uses resolved FQDN as fallback when short name doesn't match
  ├─ Optionally build certificate chain
  │
  ▼
KerberosInspector.Inspect(hostname, port, isNamedInstance)
  │
  ├─ DnsResolver.ResolveHost (P/Invoke DnsQuery_W)
  │   ├─ Query A records (includes CNAME chain if present)
  │   ├─ Query AAAA records
  │   └─ Detect suffix expansion vs true CNAME
  ├─ DNS reverse lookup
  ├─ SPN lookup via LDAP (uses resolved FQDN for SPN construction when input is short name)
  ├─ Health checks (missing SPNs, DNS mismatch, true CNAME warnings, duplicate SPNs)
  │
  ▼
ConsoleReporter.Report() or JsonReporter.Report()
  │
  ▼
Exit code
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `System.CommandLine` | 2.0.0-beta4 | CLI argument parsing |
| `System.DirectoryServices` | 10.0.5 | LDAP queries for SPN lookup (Windows-only) |
| `MinVer` | 6.0.0 | Automatic version derivation from git tags |
