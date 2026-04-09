using System.Security.Cryptography.X509Certificates;

namespace SqlCertInspector;

/// <summary>
/// Holds extracted details about an X.509 certificate.
/// </summary>
public sealed class CertificateInfo
{
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string ThumbprintSha1 { get; set; } = string.Empty;
    public string ThumbprintSha256 { get; set; } = string.Empty;
    public DateTime ValidFrom { get; set; }
    public DateTime ValidTo { get; set; }
    public int DaysUntilExpiry { get; set; }
    public string KeyAlgorithm { get; set; } = string.Empty;
    public int KeySizeBits { get; set; }
    public string SignatureAlgorithm { get; set; } = string.Empty;
    public int Version { get; set; }
    public List<string> SubjectAlternativeNames { get; set; } = new();
    public string? KeyUsage { get; set; }
    public List<string> EnhancedKeyUsage { get; set; } = new();
    public bool IsCA { get; set; }
    public bool IsSelfSigned { get; set; }

    /// <summary>
    /// Certificates in the chain (leaf first, root last).
    /// Only populated when --show-full-certificate-chain is specified.
    /// </summary>
    public List<CertificateInfo>? ChainCertificates { get; set; }

    /// <summary>
    /// Chain validation status messages, if any.
    /// </summary>
    public List<string> ChainStatusMessages { get; set; } = new();

    /// <summary>
    /// Health warnings detected during analysis.
    /// </summary>
    public List<CertificateWarning> Warnings { get; set; } = new();
}

public sealed class CertificateWarning
{
    public WarningSeverity Severity { get; set; }
    public string Message { get; set; } = string.Empty;

    public CertificateWarning(WarningSeverity severity, string message)
    {
        Severity = severity;
        Message = message;
    }
}

public enum WarningSeverity
{
    Info,
    Warning,
    Error
}
