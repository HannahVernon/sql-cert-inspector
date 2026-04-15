namespace SqlCertInspector;

/// <summary>
/// Holds metadata about the TLS connection and SQL Server PRELOGIN response.
/// </summary>
public sealed class ConnectionSecurityInfo
{
    public string ServerName { get; set; } = string.Empty;
    public string ResolvedHost { get; set; } = string.Empty;
    public int ResolvedPort { get; set; }
    public string? InstanceName { get; set; }

    /// <summary>
    /// All IP addresses returned by DNS resolution for the target hostname.
    /// Null when the hostname was already an IP address (no DNS lookup needed).
    /// </summary>
    public string[]? ResolvedIPs { get; set; }

    /// <summary>
    /// The IP address that was actually used for the TCP connection.
    /// Populated when DNS returned multiple addresses and a parallel race was used.
    /// </summary>
    public string? ConnectedIP { get; set; }

    /* From PRELOGIN response */
    public string? SqlServerVersion { get; set; }
    public string? EncryptionMode { get; set; }

    /* From TLS handshake */
    public string? TlsProtocolVersion { get; set; }
    public string? CipherSuite { get; set; }
    public string? KeyExchangeAlgorithm { get; set; }
    public int? KeyExchangeStrength { get; set; }
    public string? HashAlgorithm { get; set; }
    public int? HashStrength { get; set; }

    public bool IsEncrypted { get; set; }

    /// <summary>
    /// The server certificate extracted from the TLS handshake.
    /// </summary>
    public CertificateInfo? Certificate { get; set; }

    /// <summary>
    /// Kerberos and DNS diagnostic results. Null if skipped.
    /// </summary>
    public KerberosDiagnostics? Kerberos { get; set; }
}
