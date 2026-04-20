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
| `CommandLineOptions.cs` | POCO holding parsed CLI options (`--server`, `--port`, `--timeout`, `--json`, `--output`, `--show-full-certificate-chain`, `--skip-kerberos`, `--encrypt-strict`, `--no-color`). |
| `ExitCodes.cs` | Constants for process exit codes (0–6). |
| `ServerEndpointResolver.cs` | Parses the `--server` string into host, instance name, and port components. Validates conflicts between `--port` and port/instance in the server string. |
| `DnsResolver.cs` | P/Invoke wrapper for `DnsQuery_W` (`dnsapi.dll`). Queries A, AAAA, and CNAME records and returns structured results with actual DNS record types. Detects DNS suffix expansion (short name → FQDN) vs true CNAME records. Windows-only. |
| `SqlBrowserClient.cs` | Queries the SQL Server Browser service on UDP 1434 to resolve a named instance to its TCP port. When the hostname resolves to multiple IPs, sends Browser queries to all IPs in parallel and uses the first response. Distinguishes between timeout (instance not found) and connection failure (service unreachable). |
| `TdsPacket.cs` | Reads and writes TDS packet headers (8-byte framing: type, status, length, SPID, packet ID, window). |
| `TdsPreloginStream.cs` | Custom `Stream` implementation that wraps TLS handshake data inside TDS PRELOGIN packets (type 0x12). Required because SQL Server frames TLS records inside TDS during the handshake phase. |
| `TdsPreloginClient.cs` | Core inspection logic. Supports both TDS 7.x (PRELOGIN first, TLS wrapped in TDS packets) and TDS 8.0 Strict (TLS first on raw socket, PRELOGIN inside encrypted tunnel). Resolves hostname to IP addresses via DNS, races TCP connections in parallel when multiple IPs are returned (multi-subnet failover), and extracts the server certificate and TLS metadata. Throws `ProtocolMismatchException` when a protocol version mismatch is detected, enabling auto-fallback. |
| `TdsProtocolVersion.cs` | Enum (`Tds7`, `Tds8Strict`) and display string extension method for the TDS protocol flow variant used. |
| `CertificateInfo.cs` | Model class holding extracted certificate details, health warnings, and optional chain certificates. |
| `ConnectionSecurityInfo.cs` | Model class holding connection metadata, TLS properties, TDS protocol version, fallback status, the certificate, and Kerberos diagnostics. |
| `CertificateAnalyzer.cs` | Extracts all fields from an `X509Certificate2` (subject, issuer, SANs, key info, etc.) and runs health checks (expiry, self-signed, hostname mismatch, weak keys, deprecated algorithms). Accepts an optional resolved FQDN to avoid false hostname mismatch warnings when a short (non-FQDN) name was used. Builds the certificate chain when requested. |
| `KerberosDiagnostics.cs` | Model class for Kerberos/DNS diagnostic results (SPN lookup results, DNS resolution, DNS record types, resolved FQDN, warnings, and `setspn` remediation commands). |
| `KerberosInspector.cs` | Uses `DnsResolver` for DNS resolution with record type awareness. Performs reverse lookup, CNAME detection (true CNAME vs DNS suffix expansion), and SPN lookup via LDAP `DirectorySearcher`. When input is a non-FQDN short name, uses the resolved FQDN for SPN construction. By default, only checks port/instance-specific SPNs (used by TCP connections); portless base SPNs are included only with `--full-spn-diagnostics`. Suggests `setspn` remediation commands (FQDN-only) when SPNs are missing. Runs health checks for DNS mismatches, missing SPNs, and duplicate SPN registrations. Windows-only (`[SupportedOSPlatform("windows")]`). |
| `ConsoleReporter.cs` | Renders results as colored plain text. Auto-detects redirected output and suppresses colors. Maps raw algorithm enum values to human-readable names. |
| `JsonReporter.cs` | Renders results as indented JSON via `System.Text.Json`. Provides `GenerateJson()` for string output (used by `--output` file writing) and `Report()` for direct console output. Applies the same algorithm name mappings as the console reporter. |
| `OutputFileHelper.cs` | Generates output filenames from `--server` values by replacing illegal filename characters (`\/:*?"<>\|`) with hyphens. |
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

This is the **TDS 7.x** handshake flow, which has been stable across all versions from SQL Server 2005 (TDS 7.2) through SQL Server 2025 (TDS 7.4). See the [MS-TDS specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/b46a581a-39de-4745-b076-ec4dbb7d13ec) for full protocol details.

### TDS 8.0 Strict Encryption

SQL Server 2022 introduced [TDS 8.0](https://learn.microsoft.com/en-us/sql/relational-databases/security/networking/tds-8?view=sql-server-ver16), where TLS negotiation occurs *before* any TDS packets — like HTTPS. The handshake sequence is:

1. **TLS Handshake**: Standard TLS directly on the TCP socket (no TDS wrapping)
2. **Certificate extracted**: The server presents its certificate during the TLS handshake
3. **Client → Server**: TDS PRELOGIN packet (inside the encrypted tunnel)
4. **Server → Client**: PRELOGIN response with server version (inside the encrypted tunnel)
5. **Disconnect**: We close the connection without ever sending a LOGIN packet

This is simpler than TDS 7.x because we don't need the `TdsPreloginStream` wrapper — `SslStream` connects directly to the `NetworkStream`. The ALPN protocol `tds/8.0` is advertised during the TLS handshake.

When a protocol mismatch is detected (e.g., sending TDS 7.x PRELOGIN to a strict-only server, or TLS ClientHello to a TDS 7.x-only server), the tool throws a `ProtocolMismatchException`. `Program.cs` catches this and retries with the alternate protocol, then displays guidance to the user.

### TDS-Wrapped TLS (TDS 7.x only)

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

### Extended Protection for Authentication (EPA)

Extended Protection (also known as Channel Binding or EPA) is a SQL Server security feature that mitigates NTLM relay / man-in-the-middle attacks by binding authentication to the specific TLS channel.

**How it works:**

1. During the TLS handshake, the client computes a **Channel Binding Token (CBT)** — a hash derived from the server's TLS certificate
2. The client includes this CBT alongside its NTLM or Kerberos authentication token in the LOGIN packet
3. The server independently computes the CBT from its own certificate and verifies that the two match
4. If an attacker performed a MitM (terminating TLS with their own certificate and re-encrypting to the real server), the CBTs will differ and authentication is rejected

**SQL Server Configuration Manager settings:**

| Setting | Behavior |
|---|---|
| **Off** | No channel binding enforcement; clients are not required to send CBTs |
| **Allowed** | Clients that support EPA send CBTs (and they are validated); older clients that don't are still accepted |
| **Required** | All clients must send CBTs or authentication is denied; older clients that don't support EPA cannot connect |

**Relevance to sql-cert-inspector:**

EPA is negotiated during the LOGIN phase, which this tool never reaches — we disconnect after the TLS handshake. Therefore, we cannot currently detect or report the server's Extended Protection setting. However, EPA is closely related to certificate security (the CBT is derived from the certificate) and is increasingly important:

- SQL Server 2022 CU14+ and SQL Server 2025 default to **Required** for new installations
- Misconfigured EPA can break connectivity for older client drivers
- The CBT depends on the specific certificate — certificate rotation without coordinated EPA awareness can cause outages

Future work may explore detecting EPA settings via alternative means (e.g., attempting a minimal LOGIN handshake or querying `sys.dm_exec_connections` if credentials are optionally provided). See [GitHub Issue #15](https://github.com/HannahVernon/sql-cert-inspector/issues/15).

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
KerberosInspector.Inspect(hostname, port, instanceName, isPortExplicit, fullSpnDiagnostics)
  │
  ├─ DnsResolver.ResolveHost (P/Invoke DnsQuery_W)
  │   ├─ Query A records (includes CNAME chain if present)
  │   ├─ Query AAAA records
  │   └─ Detect suffix expansion vs true CNAME
  ├─ DNS reverse lookup
  ├─ SPN lookup via LDAP (uses resolved FQDN for SPN construction when input is short name)
  ├─ Health checks (missing SPNs, DNS mismatch, true CNAME warnings, duplicate SPNs)
  └─ Generate setspn remediation commands for missing FQDN-qualified SPNs
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
