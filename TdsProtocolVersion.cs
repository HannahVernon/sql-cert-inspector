namespace SqlCertInspector;

/// <summary>
/// The TDS protocol flow variant used for the connection.
/// </summary>
public enum TdsProtocolVersion
{
    /// <summary>
    /// TDS 7.x: PRELOGIN sent in cleartext, then TLS handshake wrapped inside TDS packets.
    /// Used by SQL Server 2005 through 2025 when encryption is not set to Strict.
    /// </summary>
    Tds7,

    /// <summary>
    /// TDS 8.0 (Strict): TLS handshake occurs first on the raw TCP socket (like HTTPS),
    /// then PRELOGIN is sent inside the encrypted tunnel.
    /// Introduced in SQL Server 2022 for Encrypt=Strict mode.
    /// </summary>
    Tds8Strict
}

public static class TdsProtocolVersionExtensions
{
    public static string ToDisplayString(this TdsProtocolVersion version) => version switch
    {
        TdsProtocolVersion.Tds7 => "7.x",
        TdsProtocolVersion.Tds8Strict => "8.0 (Strict)",
        _ => "Unknown"
    };
}
