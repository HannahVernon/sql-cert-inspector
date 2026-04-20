# Security Policy

## Supported Versions

Only the latest release of sql-cert-inspector is supported with security
updates. If you are using an older version, please upgrade to the latest release
before reporting a vulnerability.

| Version        | Supported |
| -------------- | --------- |
| Latest release | Yes       |
| Older versions | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in sql-cert-inspector, please report it
responsibly using one of the following methods:

1. **GitHub Private Vulnerability Reporting (preferred):** Navigate to the
   repository's **Security** tab and click **Report a vulnerability**. This
   ensures the report remains private until a fix is available.

2. **Email:** Send a detailed report to <coc@mvct.com>.

Please include:

- A description of the vulnerability
- Steps to reproduce the issue
- The potential impact
- Any suggested fixes or mitigations, if available

## Response Time

- We will **acknowledge** your report within **48 hours**.
- We aim to provide a **fix or mitigation plan** within **7 days** of
  acknowledgement.

## Scope

This security policy covers:

- The **sql-cert-inspector** tool itself
- Its **dependencies** (NuGet packages and transitive dependencies)

## A Note on Credentials

The sql-cert-inspector tool does **not** handle credentials or authentication
data. It inspects TLS certificates presented by SQL Server endpoints without
requiring or storing any login information. However, the security of the
**TLS/certificate validation logic** is critical to the tool's purpose and is
treated with the highest priority.

## Disclosure

We follow a coordinated disclosure process. Once a fix is available, we will
publish a security advisory on GitHub and credit the reporter (unless anonymity
is requested).
