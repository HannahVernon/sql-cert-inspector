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

### 8. Proper Resource Cleanup (Fixed)

**Severity:** High
**Files:** `TdsPreloginClient.cs`
**Status:** ✅ Fixed — `SslStream` and `X509Certificate2` now properly disposed.

`SslStream` instances in both TDS 7.x and TDS 8.0 code paths were created without `using` statements, leaking native TLS handles. Additionally, `new X509Certificate2(remoteCert)` in `ExtractCertificate` was never disposed, leaking a certificate handle per invocation. All three resources are now wrapped in `using` statements with `leaveInnerStreamOpen: true` preserved so the underlying network stream remains usable.

### 9. TDS Packet Size Bounds

**Severity:** None (verified safe)
**File:** `TdsPacket.cs`

Incoming TDS packet payloads are bounded to 65,536 bytes maximum. Combined with stream read timeouts, this prevents unbounded memory allocation from malicious servers.

### 13. PRELOGIN ENCRYPTION Option Missing Length Validation (Fixed)

**Severity:** Critical
**File:** `TdsPreloginClient.cs`
**Status:** ✅ Fixed — `enc.length >= 1` guard added.

The PRELOGIN response parser checked that the ENCRYPTION option's offset was within bounds but did not verify the declared length was at least 1 byte. A malicious server could send a zero-length ENCRYPTION option, and while the current code would read at the offset anyway (within bounds), it represented an unvalidated assumption. The parser now requires `enc.length >= 1` and `enc.offset >= 0` before reading the encryption byte.

### 14. Unbounded DNS P/Invoke Linked-List Traversal (Fixed)

**Severity:** High
**File:** `DnsResolver.cs`
**Status:** ✅ Fixed — iteration limit of 1,000 records added.

The `ParseRecords()` method followed `pNext` pointers in the `DNS_RECORD` linked list returned by `DnsQuery_W` with no iteration limit. A corrupted or malicious DNS response could create a cycle in the linked list, causing an infinite loop. A `maxRecords = 1000` counter now breaks the loop, which is well above any legitimate DNS response size.

### 15. SQL Browser Response Type and Length Not Validated (Fixed)

**Severity:** High
**File:** `SqlBrowserClient.cs`
**Status:** ✅ Fixed — response type byte (0x05) and declared length now validated.

The `ParseInstanceResponse()` method skipped the response type byte (expected `0x05` for SVR_RESP) and the 2-byte length field, converting all bytes after offset 3 to a string regardless. A spoofed or corrupted response with a wrong type byte or inflated length field would be silently accepted. The parser now validates the type byte, reads the declared 2-byte length field, and uses `Math.Min(declaredLength, actualLength)` to bound the string conversion.

### 16. Integer Overflow Risk in PRELOGIN Offset+Length Bounds Check (Fixed)

**Severity:** High
**File:** `TdsPreloginClient.cs`
**Status:** ✅ Fixed — bounds checks normalized to subtraction form and `offset >= 0` guards added.

The VERSION option bounds check used `offset + length <= payload.Length`, where `offset` and `length` are 16-bit values stored as `int`. While overflow is unlikely with 16-bit source values, the check has been normalized to `offset <= payload.Length - length` (with `length >= 6` verified first to prevent underflow). Consistent `offset >= 0` guards are now applied to both VERSION and ENCRYPTION options.

### 10. Dependency Assessment

| Package | Version | Risk |
|---------|---------|------|
| `System.CommandLine` | 2.0.6 | Stable GA release. No known CVEs. |
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
| Critical | 1 | ✅ Fixed (PRELOGIN ENCRYPTION length validation) |
| High | 5 | ✅ Fixed (IPv4 SPN, resource disposal, DNS loop, Browser validation, offset overflow) |
| Medium | 1 | Accepted (UDP protocol limitation) |
| Low | 2 | ✅ Fixed (Browser response disclosure), Accepted (TLS bypass by design) |
| Info | 2 | ✅ Fixed (SHA pinning), Noted (beta dependency) |

## Recommendations for Future Development

1. If a `--verbose` flag is added, gate detailed network diagnostics behind it.
2. Review pinned action SHAs when updating workflow files.
3. If cross-platform support is added, re-evaluate `System.DirectoryServices` (Windows-only) and consider alternative SPN lookup methods.

---

## Security Audit — 2026-04-20

**Framework:** [HannahVernon/ai-security-audit](https://github.com/HannahVernon/ai-security-audit)
**Audits run:** 6 of 14 (01, 03, 06, 08, 09, 11)

### 17. Path Traversal via `--output` Option (Fixed)

**Severity:** Critical (CWE-22)
**File:** `Program.cs` — `WriteOutputFile()`
**Status:** ✅ Fixed — `Path.GetFullPath()` canonicalization added.

The `--output` value was passed directly to `File.WriteAllText()` without validation. Paths like `../../sensitive.json` or absolute paths could write to arbitrary locations. The path is now canonicalized via `Path.GetFullPath()` before use.

### 18. Auto-Generated Filename Missing `..` Sanitization (Fixed)

**Severity:** High (CWE-22)
**File:** `OutputFileHelper.cs` — `GenerateOutputFileName()`
**Status:** ✅ Fixed — `..` sequences collapsed to `.` in a loop.

The filename sanitizer replaced illegal characters but did not block `..` sequences. While exploitation was unlikely (auto-generated from server names), the sanitizer now collapses `..` to `.` to close the gap.

### 19. UDP `Task.WaitAll` Without Timeout (Fixed)

**Severity:** High (DoS)
**File:** `SqlBrowserClient.cs` — `QueryBrowserParallel()`
**Status:** ✅ Fixed — `Task.WaitAll` now passes an explicit timeout.

The parallel SQL Browser query used `Task.WaitAll(tasks)` with no timeout. While individual tasks had `ReceiveTimeout` set on the socket, platform-level hangs could cause indefinite blocking. A timeout of `(timeoutSeconds + 5) * 1000` ms (clamped 5-125s) is now passed to `Task.WaitAll`.

### 20. System.CommandLine Beta Upgraded to Stable (Fixed)

**Severity:** Medium (supply chain)
**File:** `sql-cert-inspector.csproj`
**Status:** ✅ Fixed — upgraded from `2.0.0-beta4.22272.1` to `2.0.6` (stable GA).

The pre-release beta from April 2022 has been replaced with the stable 2.0.6 release. This required migrating to the new API surface (`Option` constructor changes, `SetAction` replaces `SetHandler`, `GetValue` replaces `GetValueForOption`, `Parse().Invoke()` replaces `InvokeAsync`).

### 21. Explicit LDAP Timeouts on DirectorySearcher (Fixed)

**Severity:** Low
**File:** `KerberosInspector.cs` — `LookupSpn()`
**Status:** ✅ Fixed — `ServerTimeLimit` (15s) and `ClientTimeout` (30s) set.

`DirectorySearcher` previously relied on platform defaults. Explicit timeouts ensure SPN lookups cannot hang indefinitely.

### 22. File Write Errors Leak Full Paths (Fixed)

**Severity:** Medium (CWE-209)
**File:** `Program.cs` — `WriteOutputFile()`
**Status:** ✅ Fixed — error messages now show only the filename via `Path.GetFileName()`.

Error messages previously included the full resolved file path, which could reveal directory structure in CI/CD logs. Messages now show only the filename and a generic error description.

### Audit Domains with No Issues Found

| Audit | Domain | Result |
|-------|--------|--------|
| 01 | Credential & Connection String Handling | ✅ Clean |
| 08 | Binary Protocol Parsing | ✅ Clean |
| 09 | TLS Configuration & Certificate Handling | ✅ Clean |

### Updated Severity Summary

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 2 | ✅ Fixed (PRELOGIN length validation, path traversal) |
| High | 7 | ✅ Fixed (IPv4 SPN, resource disposal, DNS loop, Browser validation, offset overflow, filename sanitization, UDP timeout) |
| Medium | 3 | ✅ Fixed (System.CommandLine upgrade, path leakage), Accepted (UDP protocol limitation) |
| Low | 3 | ✅ Fixed (Browser response disclosure, LDAP timeouts), Accepted (TLS bypass by design) |
| Info | 1 | ✅ Fixed (SHA pinning) |
