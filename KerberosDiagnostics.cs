namespace SqlCertInspector;

/// <summary>
/// Holds Kerberos and DNS diagnostic information for a SQL Server endpoint.
/// </summary>
public sealed class KerberosDiagnostics
{
    /* DNS resolution */
    public string RequestedHostname { get; set; } = string.Empty;
    public List<string> ResolvedIpAddresses { get; set; } = new();
    public string? ReverseHostname { get; set; }
    public bool ForwardReverseMismatch { get; set; }
    public string? CnameTarget { get; set; }
    public string? ResolvedFqdn { get; set; }
    public List<string> DnsRecordTypes { get; set; } = new();
    public string? DnsError { get; set; }

    /* SPN information — all expected variants and their lookup results */
    public List<SpnExpectation> ExpectedSpns { get; set; } = new();
    public string? SpnLookupError { get; set; }

    /* CNAME target SPN information — SPNs checked for the canonical hostname
       when a CNAME is detected. Microsoft.Data.SqlClient resolves CNAMEs via
       Dns.GetHostEntry() before building SPNs, so these are the SPNs that
       modern .NET clients actually use. */
    public List<SpnExpectation>? CnameTargetSpns { get; set; }

    /* Warnings */
    public List<KerberosWarning> Warnings { get; set; } = new();

    /* Remediation — suggested setspn commands for missing SPNs */
    public List<string> SuggestedSetspnCommands { get; set; } = new();

    /* SAN SPN coverage — SPN lookup results for each certificate SAN hostname (--full-spn-diagnostics) */
    public List<SanSpnCheck>? SanSpnCoverage { get; set; }
}

/// <summary>
/// SPN lookup result for a single SAN hostname from the certificate.
/// </summary>
public sealed class SanSpnCheck
{
    public string SanHostname { get; set; } = string.Empty;
    public string Spn { get; set; } = string.Empty;
    public bool Found { get; set; }
    public string? AccountName { get; set; }
    public string? AccountType { get; set; }
}

/// <summary>
/// Describes one expected SPN variant (e.g. FQDN:port, shortname:instance) and its lookup result.
/// </summary>
public sealed class SpnExpectation
{
    public string Label { get; set; } = string.Empty;
    public string Spn { get; set; } = string.Empty;
    public SpnLookupResult? Result { get; set; }
}

public sealed class SpnLookupResult
{
    public bool Found { get; set; }
    public string? AccountName { get; set; }
    public string? AccountType { get; set; }
}

public sealed class KerberosWarning
{
    public WarningSeverity Severity { get; set; }
    public string Message { get; set; } = string.Empty;

    public KerberosWarning(WarningSeverity severity, string message)
    {
        Severity = severity;
        Message = message;
    }
}
