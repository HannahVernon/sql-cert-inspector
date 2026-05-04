# Invoke-CertHealthCheck

A PowerShell script that automates SQL Server TLS certificate health checks using [sql-cert-inspector](../../README.md). It reads a list of servers, inspects each one, generates an HTML report, and optionally emails the results.

## Quick Start

```powershell
# 1. Create a server list (or let the script create a sample for you)
.\Invoke-CertHealthCheck.ps1 -InputFile servers.txt

# 2. Preview what would be checked without running
.\Invoke-CertHealthCheck.ps1 -InputFile servers.txt -WhatIf

# 3. Run and save the report
.\Invoke-CertHealthCheck.ps1 -InputFile servers.txt -OutputPath report.html
```

## Parameters

Parameter | Description | Default
----------|-------------|--------
`-InputFile` | Path to pipe-delimited server list (required unless `-Setup`) | —
`-ExePath` | Directory containing `sql-cert-inspector.exe` | Current directory
`-OutputPath` | Save HTML report to this file path | —
`-Timeout` | Global connection timeout in seconds | Tool default (5s)
`-AlwaysSendEmail` | Send email on every run, not just when issues are found | Off
`-Setup` | Interactive SMTP configuration wizard | —
`-WhatIf` | Show planned actions without executing | —

## Input File Format

Pipe-delimited with a header row. Lines starting with `#` are comments. Blank columns use defaults.

```
server-name|port|tds-version|full-spn-diagnostics|test-san-connectivity|timeout
myserver\SQLEXPRESS|1434||||
myserver2.example.com||tds8|true|true|
myserver3||||||15
```

Column | Description | Default if blank
-------|-------------|------------------
`server-name` | SQL Server target (required) | —
`port` | TCP port | 1433 or Browser resolution
`tds-version` | `tds8` for strict encryption | TDS 7.x
`full-spn-diagnostics` | `true` to check all SPN variants | false
`test-san-connectivity` | `true` to test each SAN hostname | false
`timeout` | Per-server timeout override (seconds) | `-Timeout` value or 5s

## Health Status Classification

Status | Condition
-------|-----------
🔴 Critical | Certificate expired or expires within 7 days
🟡 Warning | Expires within 30 days, self-signed, weak key (<2048 bits), SHA-1/MD5 signature, or other warnings from sql-cert-inspector
🟢 Healthy | No issues detected
⚫ Error | Server unreachable, connection failed, encryption not enabled

## Email Setup

Configure SMTP for automated email delivery:

```powershell
.\Invoke-CertHealthCheck.ps1 -Setup
```

The wizard prompts for:
- SMTP server and port
- TLS enabled (true/false)
- From, To, CC, and BCC addresses
- Whether SMTP authentication is required
- Username and password (if authenticated; password is masked)

A test email is sent before saving. Configuration is stored in `smtp-config.json` (gitignored). Credentials are stored in Windows Credential Manager under target `Invoke-CertHealthCheck-Smtp`.

### Email behavior

- **Default:** Email is sent only when Critical, Warning, or Error results are found
- **`-AlwaysSendEmail`:** Email is sent on every run
- **No SMTP configured:** Email is silently skipped (unless `-AlwaysSendEmail` is set, which produces a warning)

The email subject is dynamic:
- `CRITICAL: 2 certificates expiring — SQL Certificate Health Report — 2026-05-04`
- `WARNING: 1 issue found — SQL Certificate Health Report — 2026-05-04`
- `All Healthy — SQL Certificate Health Report — 2026-05-04`

## Exit Codes

Code | Meaning
-----|--------
`0` | All servers healthy
`1` | One or more servers had errors (unreachable, connection failure)
`2` | One or more certificates are critical (expired or expiring within 7 days)
`3` | One or more servers had warnings (no critical issues)

## Windows Task Scheduler

This script supports unattended execution. When running non-interactively:

- Interactive prompts (like "create sample file?") are skipped
- The script exits with appropriate error codes
- Email is sent automatically if SMTP is configured

### Example scheduled task action

```
Program: powershell.exe
Arguments: -ExecutionPolicy Bypass -File "C:\Tools\Invoke-CertHealthCheck.ps1" -InputFile "C:\Tools\servers.txt" -OutputPath "C:\Reports\cert-health.html" -AlwaysSendEmail
Start in: C:\Tools
```

Ensure `sql-cert-inspector.exe` is in the "Start in" directory, or specify `-ExePath`.

## HTML Report

The report is a single self-contained HTML file with inline CSS (no external dependencies). It includes:

1. **Summary cards** — total, critical, warning, error, and healthy counts
2. **Summary table** — one row per server with status, certificate subject, expiry, TLS version
3. **Collapsible detail sections** — per-server command line, connection details, certificate details, TLS info, warnings, DNS/Kerberos diagnostics
4. **Footer** — execution time, tool path, sending machine FQDN
