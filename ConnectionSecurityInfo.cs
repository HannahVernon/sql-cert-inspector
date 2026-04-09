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
}
