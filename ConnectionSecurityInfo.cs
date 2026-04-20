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

    /// <summary>
    /// The fully-qualified domain name resolved from DNS, when the user supplied a
    /// short (non-FQDN) hostname. Used for certificate matching and SPN construction.
    /// Null when the input was already an FQDN or an IP address.
    /// </summary>
    public string? ResolvedHostname { get; set; }

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
    /// The TDS protocol flow used for this connection.
    /// </summary>
    public TdsProtocolVersion TdsProtocol { get; set; }

    /// <summary>
    /// True when the initial protocol attempt failed and the tool retried with the
    /// alternate protocol. Used to display guidance about --encrypt-strict.
    /// </summary>
    public bool UsedFallback { get; set; }

    /// <summary>
    /// The server certificate extracted from the TLS handshake.
    /// </summary>
    public CertificateInfo? Certificate { get; set; }

    /// <summary>
    /// Kerberos and DNS diagnostic results. Null if skipped.
    /// </summary>
    public KerberosDiagnostics? Kerberos { get; set; }

    /// <summary>
    /// Results of SAN connectivity tests. Null if --test-san-connectivity was not specified.
    /// </summary>
    public List<SanConnectivityResult>? SanConnectivityResults { get; set; }
}

/// <summary>
/// Result of a full certificate inspection for one SAN hostname.
/// </summary>
public sealed class SanConnectivityResult
{
    public string SanHostname { get; set; } = string.Empty;
    public bool Connected { get; set; }
    public string? Error { get; set; }

    /// <summary>
    /// Full inspection result for this SAN hostname. Null if connection failed.
    /// </summary>
    public ConnectionSecurityInfo? SecurityInfo { get; set; }

    /// <summary>
    /// True when the certificate served on this SAN matches the primary certificate
    /// (same SHA-256 thumbprint).
    /// </summary>
    public bool SameCertificate { get; set; }
}
