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
    public string? DnsError { get; set; }

    /* SPN information */
    public string ExpectedSpnWithPort { get; set; } = string.Empty;
    public string ExpectedSpnWithoutPort { get; set; } = string.Empty;
    public SpnLookupResult? SpnWithPort { get; set; }
    public SpnLookupResult? SpnWithoutPort { get; set; }
    public string? SpnLookupError { get; set; }

    /* Warnings */
    public List<KerberosWarning> Warnings { get; set; } = new();
}

public sealed class SpnLookupResult
{
    public string Spn { get; set; } = string.Empty;
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
