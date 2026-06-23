using System.Net.Security;
using System.Runtime.Versioning;

namespace SqlCertInspector;

/// <summary>
/// Performs an actual Kerberos/NTLM authentication test against a SQL Server
/// instance over an existing TLS-wrapped TDS connection. Uses the .NET
/// <see cref="NegotiateAuthentication"/> API (available in .NET 7+) to perform
/// the SSPI handshake, then inspects the result to determine which protocol
/// (Kerberos vs NTLM) and encryption type were used.
/// </summary>
[SupportedOSPlatform("windows")]
public static class KerberosAuthTester
{
    /* TDS packet types for the LOGIN7 exchange */
    private const byte TdsTypeLogin7 = 0x10;
    private const byte TdsTypeSspiMessage = 0xED;
    private const byte TdsTypeResponse = 0x04;

    /* TDS token types within response packets */
    private const byte TokenError = 0xAA;
    private const byte TokenLoginAck = 0xAD;
    private const byte TokenSspi = 0xED;

    /// <summary>
    /// Attempts SSPI (Kerberos/NTLM) authentication over the provided TLS stream.
    /// The stream must be positioned after a successful TLS handshake.
    /// </summary>
    public static async Task<KerberosAuthResult> TestAsync(
        Stream tlsStream, string hostname, int port, string? instanceName,
        int timeoutSeconds, CancellationToken ct = default)
    {
        var result = new KerberosAuthResult();

        /* Build the target SPN — matches what SQL Server clients use */
        string spn = instanceName != null
            ? $"MSSQLSvc/{hostname}:{instanceName}"
            : $"MSSQLSvc/{hostname}:{port}";
        result.Spn = spn;

        try
        {
            var authOptions = new NegotiateAuthenticationClientOptions
            {
                Package = "Negotiate",
                TargetName = spn,
                RequiredProtectionLevel = System.Net.Security.ProtectionLevel.None
            };

            using var negotiateAuth = new NegotiateAuthentication(authOptions);

            /* Get initial SPNEGO token (client hello) */
            var initialToken = negotiateAuth.GetOutgoingBlob(
                ReadOnlySpan<byte>.Empty, out var statusCode);

            if (initialToken == null || initialToken.Length == 0)
            {
                result.Success = false;
                result.Error = $"NegotiateAuthentication failed to produce initial token (status: {statusCode}).";
                return result;
            }

            /* Send LOGIN7 with the SSPI token */
            byte[] login7Payload = TdsLogin7Builder.Build(initialToken);
            byte[] login7Packet = TdsPacket.Build(TdsTypeLogin7, TdsPacket.StatusEom, login7Payload);

            using var sendCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            sendCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

            await tlsStream.WriteAsync(login7Packet, sendCts.Token);
            await tlsStream.FlushAsync(sendCts.Token);

            /* Read server response — may be SSPI challenge or login ack/error */
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

            var (responseType, responseStatus, responsePayload) =
                await TdsPacket.ReadAsync(tlsStream, readCts.Token);

            /* Handle multi-round SSPI negotiation */
            int maxRounds = 5;
            int round = 0;

            while (round < maxRounds)
            {
                round++;

                /* Check if response contains an SSPI challenge token */
                byte[]? serverChallenge = ExtractSspiToken(responseType, responsePayload);

                if (serverChallenge != null)
                {
                    /* Process the server's challenge */
                    var responseToken = negotiateAuth.GetOutgoingBlob(
                        serverChallenge, out statusCode);

                    if (responseToken != null && responseToken.Length > 0)
                    {
                        /* Send SSPI continuation */
                        byte[] sspiPacket = TdsPacket.Build(
                            TdsTypeSspiMessage, TdsPacket.StatusEom, responseToken);
                        await tlsStream.WriteAsync(sspiPacket, readCts.Token);
                        await tlsStream.FlushAsync(readCts.Token);

                        /* Read next response */
                        (responseType, responseStatus, responsePayload) =
                            await TdsPacket.ReadAsync(tlsStream, readCts.Token);
                        continue;
                    }
                }

                /* No more SSPI tokens — should be a final login response */
                break;
            }

            /* Parse the final response for login ack or error */
            ParseLoginResponse(responsePayload, result);

            /* Determine the authentication protocol */
            result.Protocol = negotiateAuth.Package;

            if (string.Equals(result.Protocol, "NTLM", StringComparison.OrdinalIgnoreCase))
            {
                result.FellBackToNtlm = true;
            }

            /* Extract Kerberos etype from the initial token if Kerberos was used */
            if (string.Equals(result.Protocol, "Kerberos", StringComparison.OrdinalIgnoreCase) &&
                initialToken.Length > 0)
            {
                int? etype = ExtractKerberosEtype(initialToken);
                if (etype != null)
                {
                    result.KerberosEtype = etype.Value;
                    result.KerberosEtypeName = KerberosAuthResult.GetEtypeName(etype.Value);
                    result.UsesRc4 = etype.Value == 23;
                }
            }

            result.Success = true;
        }
        catch (OperationCanceledException)
        {
            result.Success = false;
            result.Error = "Authentication timed out.";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }

        return result;
    }

    /// <summary>
    /// Extracts the SSPI challenge token from a TDS response packet.
    /// Returns null if the response does not contain an SSPI token.
    /// </summary>
    private static byte[]? ExtractSspiToken(byte responseType, byte[] payload)
    {
        if (responseType != TdsTypeResponse || payload.Length < 3)
            return null;

        /* Walk the TDS token stream looking for SSPI token (0xED) */
        int offset = 0;
        while (offset < payload.Length)
        {
            byte tokenType = payload[offset];

            if (tokenType == TokenSspi)
            {
                /* SSPI token: type (1) + length (2, little-endian) + data */
                if (offset + 3 > payload.Length) return null;
                int tokenLen = payload[offset + 1] | (payload[offset + 2] << 8);
                if (offset + 3 + tokenLen > payload.Length) return null;

                byte[] token = new byte[tokenLen];
                Buffer.BlockCopy(payload, offset + 3, token, 0, tokenLen);
                return token;
            }

            /* Skip other tokens — most use 2-byte length after the type byte */
            if (tokenType == TokenError || tokenType == TokenLoginAck)
            {
                if (offset + 3 > payload.Length) break;
                int tokenLen = payload[offset + 1] | (payload[offset + 2] << 8);
                offset += 3 + tokenLen;
            }
            else
            {
                /* Unknown token — cannot safely skip, bail */
                break;
            }
        }

        return null;
    }

    /// <summary>
    /// Parses a TDS LOGIN7 response for error or login ack tokens.
    /// </summary>
    private static void ParseLoginResponse(byte[] payload, KerberosAuthResult result)
    {
        int offset = 0;
        while (offset < payload.Length)
        {
            byte tokenType = payload[offset];

            if (tokenType == TokenError)
            {
                /* Error token: type (1) + length (2) + error data */
                if (offset + 3 > payload.Length) break;
                int tokenLen = payload[offset + 1] | (payload[offset + 2] << 8);
                if (offset + 3 + tokenLen > payload.Length) break;

                /* Error number is at offset+3 (4 bytes, little-endian) */
                if (tokenLen >= 4)
                {
                    int errorNum = BitConverter.ToInt32(payload, offset + 3);
                    /* Error message starts at offset+11, preceded by 2-byte length */
                    if (tokenLen >= 11)
                    {
                        int msgOffset = offset + 3 + 8; /* number(4) + state(1) + severity(1) + msgLen(2) */
                        if (msgOffset + 2 <= offset + 3 + tokenLen)
                        {
                            int msgLen = BitConverter.ToUInt16(payload, msgOffset);
                            msgOffset += 2;
                            if (msgOffset + msgLen * 2 <= offset + 3 + tokenLen)
                            {
                                string errorMsg = System.Text.Encoding.Unicode.GetString(
                                    payload, msgOffset, msgLen * 2);
                                result.Error = $"SQL Server error {errorNum}: {errorMsg}";
                            }
                        }
                    }

                    if (result.Error == null)
                    {
                        result.Error = $"SQL Server error {errorNum}";
                    }
                }

                offset += 3 + tokenLen;
            }
            else if (tokenType == TokenLoginAck)
            {
                /* Login ack means authentication succeeded */
                result.Success = true;
                if (offset + 3 > payload.Length) break;
                int tokenLen = payload[offset + 1] | (payload[offset + 2] << 8);
                offset += 3 + tokenLen;
            }
            else if (tokenType == TokenSspi)
            {
                /* Skip SSPI tokens in the final response */
                if (offset + 3 > payload.Length) break;
                int tokenLen = payload[offset + 1] | (payload[offset + 2] << 8);
                offset += 3 + tokenLen;
            }
            else
            {
                /* Try to skip unknown variable-length tokens */
                if (offset + 3 > payload.Length) break;
                int tokenLen = payload[offset + 1] | (payload[offset + 2] << 8);
                offset += 3 + tokenLen;
            }
        }
    }

    /// <summary>
    /// Attempts to extract the Kerberos encryption type (etype) from a SPNEGO/Kerberos
    /// token. Parses the ASN.1 DER structure to find the etype field in the AP-REQ.
    /// Returns null if the token is not Kerberos or the etype cannot be extracted.
    /// </summary>
    internal static int? ExtractKerberosEtype(byte[] token)
    {
        try
        {
            /* SPNEGO wraps the Kerberos token in a GSSAPI/SPNEGO envelope.
               OID 1.2.840.113554.1.2.2 = Kerberos 5
               OID 1.2.840.48018.1.2.2 = MS Kerberos 5
               
               Structure: SPNEGO NegTokenInit -> mechToken -> AP-REQ -> Ticket -> enc-part -> etype
               
               We search for the AP-REQ application tag [14] (0x6E) and then find
               the etype within the encrypted part of the ticket.
               
               AP-REQ structure (RFC 4120 section 5.5.1):
                 [0] pvno (INTEGER 5)
                 [1] msg-type (INTEGER 14)
                 [2] ap-options (BIT STRING)
                 [3] ticket (application [1]) -> Ticket:
                   [0] tkt-vno (INTEGER 5)
                   [1] realm (GeneralString)
                   [2] sname (PrincipalName)
                   [3] enc-part (EncryptedData):
                     [0] etype (INTEGER) <-- THIS IS WHAT WE WANT
            */

            return FindEtypeInToken(token, 0, token.Length);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Recursively searches ASN.1 DER-encoded data for the Kerberos etype.
    /// Looks for the pattern: SEQUENCE containing context-tag [0] with an INTEGER
    /// inside an EncryptedData structure (which appears in a Ticket's enc-part).
    /// </summary>
    private static int? FindEtypeInToken(byte[] data, int offset, int end)
    {
        while (offset < end)
        {
            if (offset + 2 > end) break;

            byte tag = data[offset];
            var (tagLen, headerLen) = ReadAsn1Length(data, offset + 1, end);
            if (tagLen < 0 || offset + headerLen + 1 + tagLen > end) break;

            int contentStart = offset + 1 + headerLen;
            int contentEnd = contentStart + tagLen;

            /* Application [14] = AP-REQ */
            if (tag == 0x6E)
            {
                var result = FindEtypeInApReq(data, contentStart, contentEnd);
                if (result != null) return result;
            }

            /* Constructed tags or OCTET STRING (0x04) — recurse.
               The Kerberos AP-REQ is wrapped in an OCTET STRING inside
               the SPNEGO NegTokenInit mechToken field. */
            if ((tag & 0x20) != 0 || tag == 0x04)
            {
                var result = FindEtypeInToken(data, contentStart, contentEnd);
                if (result != null) return result;
            }

            offset = contentEnd;
        }

        return null;
    }

    /// <summary>
    /// Finds the etype within an AP-REQ structure by looking for the ticket's
    /// enc-part EncryptedData sequence.
    /// </summary>
    private static int? FindEtypeInApReq(byte[] data, int offset, int end)
    {
        /* Walk the AP-REQ looking for context tag [3] (ticket) */
        while (offset < end)
        {
            if (offset + 2 > end) break;

            byte tag = data[offset];
            var (tagLen, headerLen) = ReadAsn1Length(data, offset + 1, end);
            if (tagLen < 0) break;

            int contentStart = offset + 1 + headerLen;
            int contentEnd = contentStart + tagLen;
            if (contentEnd > end) break;

            /* Context [3] in AP-REQ = ticket */
            if (tag == 0xA3)
            {
                return FindEtypeInTicket(data, contentStart, contentEnd);
            }

            /* Recurse into constructed tags */
            if ((tag & 0x20) != 0)
            {
                var result = FindEtypeInApReq(data, contentStart, contentEnd);
                if (result != null) return result;
            }

            offset = contentEnd;
        }
        return null;
    }

    /// <summary>
    /// Finds the etype within a Ticket structure by looking for context tag [3]
    /// (enc-part) which contains an EncryptedData with etype at [0].
    /// </summary>
    private static int? FindEtypeInTicket(byte[] data, int offset, int end)
    {
        while (offset < end)
        {
            if (offset + 2 > end) break;

            byte tag = data[offset];
            var (tagLen, headerLen) = ReadAsn1Length(data, offset + 1, end);
            if (tagLen < 0) break;

            int contentStart = offset + 1 + headerLen;
            int contentEnd = contentStart + tagLen;
            if (contentEnd > end) break;

            /* Context [3] in Ticket = enc-part (EncryptedData) */
            if (tag == 0xA3)
            {
                return FindEtypeInEncryptedData(data, contentStart, contentEnd);
            }

            if ((tag & 0x20) != 0)
            {
                var result = FindEtypeInTicket(data, contentStart, contentEnd);
                if (result != null) return result;
            }

            offset = contentEnd;
        }
        return null;
    }

    /// <summary>
    /// Extracts the etype INTEGER from an EncryptedData sequence.
    /// EncryptedData ::= SEQUENCE { [0] etype INTEGER, ... }
    /// </summary>
    private static int? FindEtypeInEncryptedData(byte[] data, int offset, int end)
    {
        while (offset < end)
        {
            if (offset + 2 > end) break;

            byte tag = data[offset];
            var (tagLen, headerLen) = ReadAsn1Length(data, offset + 1, end);
            if (tagLen < 0) break;

            int contentStart = offset + 1 + headerLen;
            int contentEnd = contentStart + tagLen;
            if (contentEnd > end) break;

            /* SEQUENCE — look inside for context [0] */
            if (tag == 0x30)
            {
                var result = FindEtypeInEncryptedData(data, contentStart, contentEnd);
                if (result != null) return result;
            }

            /* Context [0] = etype — contains an INTEGER */
            if (tag == 0xA0)
            {
                return ReadAsn1Integer(data, contentStart, contentEnd);
            }

            offset = contentEnd;
        }
        return null;
    }

    /// <summary>
    /// Reads an ASN.1 INTEGER from the given range.
    /// </summary>
    private static int? ReadAsn1Integer(byte[] data, int offset, int end)
    {
        if (offset >= end) return null;
        byte tag = data[offset];
        if (tag != 0x02) return null; /* Not an INTEGER */

        var (len, headerLen) = ReadAsn1Length(data, offset + 1, end);
        if (len < 0 || len > 4) return null;

        int contentStart = offset + 1 + headerLen;
        if (contentStart + len > end) return null;

        int value = 0;
        for (int i = 0; i < len; i++)
        {
            value = (value << 8) | data[contentStart + i];
        }

        /* Handle sign extension for negative values (shouldn't happen for etypes) */
        if (len > 0 && (data[contentStart] & 0x80) != 0)
        {
            /* Sign extend */
            for (int i = len; i < 4; i++)
            {
                value |= 0xFF << (i * 8);
            }
        }

        return value;
    }

    /// <summary>
    /// Reads an ASN.1 DER length field. Returns (length, headerBytes).
    /// </summary>
    private static (int length, int headerBytes) ReadAsn1Length(byte[] data, int offset, int end)
    {
        if (offset >= end) return (-1, 0);

        byte first = data[offset];
        if ((first & 0x80) == 0)
        {
            /* Short form: length in 7 bits */
            return (first, 1);
        }

        int numBytes = first & 0x7F;
        if (numBytes == 0 || numBytes > 4 || offset + 1 + numBytes > end)
        {
            return (-1, 0);
        }

        int length = 0;
        for (int i = 0; i < numBytes; i++)
        {
            length = (length << 8) | data[offset + 1 + i];
        }

        return (length, 1 + numBytes);
    }
}
