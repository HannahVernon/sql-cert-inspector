using System.Text;

namespace SqlCertInspector;

/// <summary>
/// Builds a minimal TDS LOGIN7 packet for SSPI (Kerberos/NTLM) authentication.
/// Only the fields required for the SSPI handshake are populated; all other
/// fields (database, language, etc.) use empty/default values.
/// 
/// LOGIN7 format (MS-TDS 2.2.6.4):
///   Fixed header: 94 bytes
///   Variable-length data: client name, username (empty), password (empty), etc.
///   SSPI blob: appended at the end, referenced by ibSSPI/cbSSPI in the header
/// </summary>
public static class TdsLogin7Builder
{
    public const byte TypeLogin7 = 0x10;

    /* TDS 7.4 version bytes (SQL Server 2012+) */
    private const uint TdsVersion74 = 0x74000004;

    /* Fixed header size per MS-TDS spec */
    private const int FixedHeaderSize = 94;

    /// <summary>
    /// Builds a LOGIN7 payload (not including the TDS packet header) with an SSPI token.
    /// The caller wraps this in a TDS packet using TdsPacket.Build().
    /// </summary>
    public static byte[] Build(byte[] sspiToken)
    {
        /* Variable-length fields — all empty except SSPI.
           Each field has an offset (2 bytes) and length (2 bytes) in the fixed header.
           Fields in order: HostName, UserName, Password, AppName, ServerName,
           Extension (unused), CltIntName, Language, Database, ClientID (6 bytes in header),
           SSPI (offset + length), AtchDBFile, ChangePassword */

        string clientHostname = Environment.MachineName;
        string appName = "sql-cert-inspector";
        string clientInterface = "sql-cert-inspector";

        /* Calculate offsets — all variable data starts after the 94-byte fixed header */
        int offset = FixedHeaderSize;

        /* HostName */
        int ibHostName = offset;
        int cchHostName = clientHostname.Length;
        offset += cchHostName * 2;

        /* UserName (empty for SSPI) */
        int ibUserName = offset;
        int cchUserName = 0;

        /* Password (empty for SSPI) */
        int ibPassword = offset;
        int cchPassword = 0;

        /* AppName */
        int ibAppName = offset;
        int cchAppName = appName.Length;
        offset += cchAppName * 2;

        /* ServerName (empty) */
        int ibServerName = offset;
        int cchServerName = 0;

        /* Extension (unused, offset points to end of variable data) */
        int ibExtension = 0;
        int cbExtension = 0;

        /* CltIntName */
        int ibCltIntName = offset;
        int cchCltIntName = clientInterface.Length;
        offset += cchCltIntName * 2;

        /* Language (empty) */
        int ibLanguage = offset;
        int cchLanguage = 0;

        /* Database (empty) */
        int ibDatabase = offset;
        int cchDatabase = 0;

        /* SSPI token — placed at the current offset */
        int ibSSPI = offset;
        int cbSSPI = sspiToken.Length;

        /* If cbSSPI > 65535, the spec says set cbSSPI to 0xFFFF and append
           the actual length as a 4-byte value after the fixed header. We
           don't expect tokens that large for Kerberos, but handle it. */
        bool longSspi = cbSSPI > 0xFFFF;
        int cbSSPIHeader = longSspi ? 0xFFFF : cbSSPI;

        offset += cbSSPI;

        /* AtchDBFile (empty) */
        int ibAtchDBFile = offset;
        int cchAtchDBFile = 0;

        /* ChangePassword (empty) */
        int ibChangePassword = offset;
        int cchChangePassword = 0;

        /* Total length including the length field itself (first 4 bytes) */
        int totalLength = offset;

        var payload = new byte[totalLength];
        using var ms = new MemoryStream(payload);
        using var bw = new BinaryWriter(ms, Encoding.Unicode);

        /* Length (4 bytes, little-endian) — includes itself */
        bw.Write(totalLength);

        /* TDSVersion (4 bytes) */
        bw.Write(TdsVersion74);

        /* PacketSize (4 bytes) — 4096 is typical minimum */
        bw.Write(4096);

        /* ClientProgVer (4 bytes) */
        bw.Write(0);

        /* ClientPID (4 bytes) */
        bw.Write(Environment.ProcessId);

        /* ConnectionID (4 bytes) */
        bw.Write(0);

        /* OptionFlags1: USE_DB_OFF | INIT_DB_FATAL_OFF | SET_LANG_ON */
        bw.Write((byte)0x00);

        /* OptionFlags2: INTEGRATED_SECURITY_ON (bit 7) */
        bw.Write((byte)0x80);

        /* TypeFlags */
        bw.Write((byte)0x00);

        /* OptionFlags3 */
        bw.Write((byte)0x00);

        /* ClientTimZone (4 bytes) */
        bw.Write(0);

        /* ClientLCID (4 bytes) */
        bw.Write(0x00000409); /* en-US */

        /* Now the offset/length pairs for variable-length fields */
        /* HostName */
        bw.Write((ushort)ibHostName);
        bw.Write((ushort)cchHostName);

        /* UserName */
        bw.Write((ushort)ibUserName);
        bw.Write((ushort)cchUserName);

        /* Password */
        bw.Write((ushort)ibPassword);
        bw.Write((ushort)cchPassword);

        /* AppName */
        bw.Write((ushort)ibAppName);
        bw.Write((ushort)cchAppName);

        /* ServerName */
        bw.Write((ushort)ibServerName);
        bw.Write((ushort)cchServerName);

        /* Extension (unused) */
        bw.Write((ushort)ibExtension);
        bw.Write((ushort)cbExtension);

        /* CltIntName */
        bw.Write((ushort)ibCltIntName);
        bw.Write((ushort)cchCltIntName);

        /* Language */
        bw.Write((ushort)ibLanguage);
        bw.Write((ushort)cchLanguage);

        /* Database */
        bw.Write((ushort)ibDatabase);
        bw.Write((ushort)cchDatabase);

        /* ClientID (6 bytes — MAC address, all zeros is fine) */
        bw.Write(new byte[6]);

        /* SSPI */
        bw.Write((ushort)ibSSPI);
        bw.Write((ushort)cbSSPIHeader);

        /* AtchDBFile */
        bw.Write((ushort)ibAtchDBFile);
        bw.Write((ushort)cchAtchDBFile);

        /* ChangePassword */
        bw.Write((ushort)ibChangePassword);
        bw.Write((ushort)cchChangePassword);

        /* cbSSPILong (4 bytes) — only meaningful when cbSSPI header = 0xFFFF */
        bw.Write(longSspi ? cbSSPI : 0);

        /* Now write the variable-length data in order */
        /* HostName (UTF-16LE) */
        bw.Write(Encoding.Unicode.GetBytes(clientHostname));

        /* AppName (UTF-16LE) */
        bw.Write(Encoding.Unicode.GetBytes(appName));

        /* CltIntName (UTF-16LE) */
        bw.Write(Encoding.Unicode.GetBytes(clientInterface));

        /* SSPI token (raw bytes) */
        bw.Write(sspiToken);

        bw.Flush();

        return payload;
    }
}
