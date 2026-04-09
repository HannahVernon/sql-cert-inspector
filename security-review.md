# Security Review — sql-cert-inspector

**Review date:** 2026-04-09
**Reviewer:** Automated red-team audit (AI-assisted)
**Scope:** Full codebase audit — all source files, workflows, templates, and configuration
**Overall posture:** Good. No critical or high-severity vulnerabilities found.

---

## Findings

### 1. LDAP Filter Escaping — No Injection Vector

**Severity:** None (verified safe)
**File:** `KerberosInspector.cs` — `EscapeLdapFilter()`

The `EscapeLdapFilter` function escapes the five characters required by RFC 4515 §3 (`\ * ( ) \0`). User-supplied hostnames and instance names pass through this function before reaching any LDAP query. No injection vector exists.

### 2. TLS Certificate Validation Bypass (By Design)

**Severity:** Low (accepted risk)
**File:** `TdsPreloginClient.cs`

The `SslStream` callback unconditionally accepts all certificates. This is intentional — the tool's purpose is to *inspect* certificates, not enforce trust. No credentials or sensitive data are transmitted after the handshake. The code includes a comment documenting this design choice.

### 3. SQL Browser Raw Response in Error Messages (Fixed)

**Severity:** Low
**File:** `SqlBrowserClient.cs`
**Status:** ✅ Fixed — raw Browser response removed from error messages.

Previously, when the SQL Browser returned a response without a TCP port, the raw response text was included in the error message. This could leak internal instance names, pipe names, and server version information if tool output was logged or shared. The raw response has been removed from the error message.

### 4. IPv4 Address Generates Invalid Short-Name SPNs (Fixed)

**Severity:** High (functional bug)
**File:** `KerberosInspector.cs`
**Status:** ✅ Fixed — `IPAddress.TryParse()` guard added.

When the hostname was an IPv4 address (e.g., `192.168.1.10`), the short-name extraction split on `.` and produced invalid SPNs like `MSSQLSvc/192:1433`. An `IPAddress.TryParse()` check now skips short-name SPN generation for IP address inputs.

### 5. GitHub Actions Pinned to Commit SHAs (Fixed)

**Severity:** Info (supply-chain hardening)
**Files:** `.github/workflows/version-bump.yml`, `.github/workflows/build-release.yml`
**Status:** ✅ Fixed — all third-party actions pinned to commit SHAs.

Previously, all GitHub Actions were referenced by major version tag (e.g., `actions/checkout@v4`), which could be silently updated. All actions are now pinned to specific commit SHAs with version comments:

| Action | SHA | Version |
|--------|-----|---------|
| `actions/checkout` | `34e114876b...` | v4.3.1 |
| `actions/setup-dotnet` | `67a3573c9a...` | v4.3.1 |
| `actions/upload-artifact` | `ea165f8d65...` | v4.6.2 |
| `actions/download-artifact` | `d3f86a106a...` | v4.3.0 |
| `softprops/action-gh-release` | `153bb8e044...` | v2.6.1 |

### 6. UDP Response Spoofing — SQL Browser Protocol (Accepted Risk)

**Severity:** Medium (inherent protocol limitation)
**File:** `SqlBrowserClient.cs`

The SQL Browser UDP protocol accepts responses from any source IP. An attacker on the same network segment could spoof a response with a malicious port number, redirecting the tool to a different TCP endpoint. This is inherent to the SQL Browser protocol — the official SQL Server client drivers have the same limitation. Since the tool never sends credentials, the impact is limited to potentially misleading certificate output.

### 7. No Command Injection Surface

**Severity:** None (verified safe)

No `Process.Start`, shell execution, or process-spawning APIs exist in the codebase. LDAP queries use the `DirectorySearcher` API, not `setspn.exe`. DNS queries use `Dns.GetHostEntry`, not `nslookup`.

### 8. Proper Resource Cleanup

**Severity:** None (verified safe)

All disposable resources (`TcpClient`, `UdpClient`, `DirectorySearcher`, `SslStream`) are used within `using` blocks or `IDisposable` patterns. Network stream timeouts are enforced and clamped to 1–120 seconds.

### 9. TDS Packet Size Bounds

**Severity:** None (verified safe)
**File:** `TdsPacket.cs`

Incoming TDS packet payloads are bounded to 65,536 bytes maximum. Combined with stream read timeouts, this prevents unbounded memory allocation from malicious servers.

### 10. Dependency Assessment

| Package | Version | Risk |
|---------|---------|------|
| `System.CommandLine` | 2.0.0-beta4 | Pre-release (beta since 2022). No known CVEs. API surface could change. |
| `System.DirectoryServices` | 10.0.5 | No known vulnerabilities. |
| `MinVer` | 6.0.0 | Build-only (`PrivateAssets="All"`). No runtime exposure. |

`dotnet list package --vulnerable` and `dotnet list package --deprecated` both return clean.

### 11. No Sensitive Data in Source

No hardcoded credentials, API keys, internal server names, or PII exist in the source code or git history. README examples use `example.com` / `corp.example.com` domains.

### 12. TLS Version Negotiation (Informational)

**File:** `TdsPreloginClient.cs`

`SslProtocols.None` delegates TLS version selection to the OS, which is the Microsoft-recommended practice. On modern Windows this means TLS 1.2+. Since the tool inspects what the server supports rather than enforcing policy, this is correct.

---

## Severity Summary

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 0 | — |
| High | 1 | ✅ Fixed (IPv4 SPN bug) |
| Medium | 1 | Accepted (UDP protocol limitation) |
| Low | 2 | ✅ Fixed (Browser response disclosure), Accepted (TLS bypass by design) |
| Info | 2 | ✅ Fixed (SHA pinning), Noted (beta dependency) |

## Recommendations for Future Development

1. If a `--verbose` flag is added, gate detailed network diagnostics behind it.
2. Periodically re-check `System.CommandLine` for GA release or CVEs.
3. Review pinned action SHAs when updating workflow files.
4. If cross-platform support is added, re-evaluate `System.DirectoryServices` (Windows-only) and consider alternative SPN lookup methods.
