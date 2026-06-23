namespace SqlCertInspector;

/// <summary>
/// Results of an optional Kerberos authentication test (--test-kerberos).
/// Performs an actual SSPI/Negotiate handshake over the TDS connection to
/// determine whether Kerberos or NTLM is used, and which encryption type
/// (etype) the Kerberos ticket uses.
/// </summary>
public sealed class KerberosAuthResult
{
    /// <summary>
    /// Whether the authentication handshake completed successfully.
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// The authentication protocol that was negotiated: "Kerberos" or "NTLM".
    /// Null if the handshake failed before protocol selection.
    /// </summary>
    public string? Protocol { get; set; }

    /// <summary>
    /// The SPN used for the authentication attempt.
    /// </summary>
    public string Spn { get; set; } = string.Empty;

    /// <summary>
    /// True if the authentication fell back to NTLM instead of Kerberos.
    /// This typically happens when no SPN is registered or Kerberos is
    /// not available in the environment.
    /// </summary>
    public bool FellBackToNtlm { get; set; }

    /// <summary>
    /// Error message if the authentication failed. Null on success.
    /// </summary>
    public string? Error { get; set; }

    /// <summary>
    /// The Kerberos encryption type (etype) extracted from the AP-REQ token.
    /// Null if NTLM was used or the etype could not be determined.
    /// Common values: 17 = AES128, 18 = AES256, 23 = RC4-HMAC.
    /// </summary>
    public int? KerberosEtype { get; set; }

    /// <summary>
    /// Human-readable name for the Kerberos etype.
    /// </summary>
    public string? KerberosEtypeName { get; set; }

    /// <summary>
    /// True if the Kerberos ticket used RC4-HMAC (etype 23), which is
    /// deprecated per CVE-2026-20833.
    /// </summary>
    public bool UsesRc4 { get; set; }

    /// <summary>
    /// Maps a Kerberos etype number to a human-readable name.
    /// </summary>
    public static string GetEtypeName(int etype)
    {
        return etype switch
        {
            1  => "DES-CBC-CRC",
            3  => "DES-CBC-MD5",
            17 => "AES128-CTS-HMAC-SHA1-96",
            18 => "AES256-CTS-HMAC-SHA1-96",
            23 => "RC4-HMAC",
            24 => "RC4-HMAC-EXP",
            _  => $"Unknown ({etype})"
        };
    }
}
