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
    /// The client machine's supported Kerberos encryption types bitmask,
    /// read from the registry. Null if the registry key is not set (OS defaults apply).
    /// </summary>
    public int? ClientSupportedEtypes { get; set; }

    /// <summary>
    /// Human-readable list of encryption types the client machine supports.
    /// </summary>
    public List<string>? ClientEtypeNames { get; set; }

    /// <summary>
    /// The service account's supported encryption types bitmask from AD
    /// (msDS-SupportedEncryptionTypes). Null if not configured.
    /// </summary>
    public int? ServiceAccountEtypes { get; set; }

    /// <summary>
    /// Human-readable list of encryption types in the intersection of
    /// client and service account capabilities. Null if either side is unknown.
    /// </summary>
    public List<string>? NegotiableEtypeNames { get; set; }

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

    /* Bitmask constants matching msDS-SupportedEncryptionTypes and the
       registry SupportedEncryptionTypes value */
    private const int BitDes      = 0x1;
    private const int BitDesCbc   = 0x2;
    private const int BitRc4      = 0x4;
    private const int BitAes128   = 0x8;
    private const int BitAes256   = 0x10;

    /// <summary>
    /// Converts an encryption types bitmask to a list of human-readable names.
    /// </summary>
    public static List<string> BitmaskToNames(int bitmask)
    {
        var names = new List<string>();
        if ((bitmask & BitDes)    != 0) names.Add("DES-CBC-CRC");
        if ((bitmask & BitDesCbc) != 0) names.Add("DES-CBC-MD5");
        if ((bitmask & BitRc4)    != 0) names.Add("RC4-HMAC");
        if ((bitmask & BitAes128) != 0) names.Add("AES128");
        if ((bitmask & BitAes256) != 0) names.Add("AES256");
        return names;
    }

    /// <summary>
    /// Reads the local machine's Kerberos supported encryption types from the
    /// registry. Returns null if the registry key is not set (OS defaults apply).
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static int? ReadClientSupportedEtypes()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters");
            if (key == null) return null;

            var value = key.GetValue("SupportedEncryptionTypes");
            if (value is int intVal) return intVal;
            if (value is long longVal) return (int)longVal;
            return null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Computes the intersection bitmask of client and service account etypes.
    /// When either side is null, uses the Windows default (RC4+AES128+AES256 = 0x1C).
    /// </summary>
    public static int ComputeIntersection(int? clientEtypes, int? serviceAccountEtypes)
    {
        int clientBits = clientEtypes ?? 0x1C; /* default: RC4 + AES128 + AES256 */
        int serviceBits = serviceAccountEtypes ?? 0x1C;
        return clientBits & serviceBits;
    }
}
