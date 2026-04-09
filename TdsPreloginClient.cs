using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace SqlCertInspector;

/// <summary>
/// Connects to a SQL Server instance at the TDS protocol level, performs the
/// PRELOGIN exchange and TLS handshake, and extracts the server certificate
/// and connection security metadata — all without sending a LOGIN packet.
/// </summary>
public sealed class TdsPreloginClient : IDisposable
{
    /* PRELOGIN option tokens */
    private const byte TokenVersion = 0x00;
    private const byte TokenEncryption = 0x01;
    private const byte TokenInstOpt = 0x02;
    private const byte TokenThreadId = 0x03;
    private const byte TokenMars = 0x04;
    private const byte TokenTerminator = 0xFF;

    /* Encryption option values */
    private const byte EncryptOff = 0x00;
    private const byte EncryptOn = 0x01;
    private const byte EncryptNotSupported = 0x02;
    private const byte EncryptRequired = 0x03;
    private const byte EncryptClientCertificate = 0x80;

    private TcpClient? _tcpClient;
    private NetworkStream? _networkStream;

    public async Task<ConnectionSecurityInfo> InspectAsync(
        string host, int port, string serverDisplayName, int timeoutSeconds,
        bool showFullChain, CancellationToken ct = default)
    {
        var info = new ConnectionSecurityInfo
        {
            ServerName = serverDisplayName,
            ResolvedHost = host,
            ResolvedPort = port
        };

        /* TCP connect */
        _tcpClient = new TcpClient();
        try
        {
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
            await _tcpClient.ConnectAsync(host, port, connectCts.Token);
        }
        catch (OperationCanceledException)
        {
            throw new ConnectionException(
                $"TCP connection to {host}:{port} timed out after {timeoutSeconds} seconds. " +
                "Verify the server is reachable and the port is correct.");
        }
        catch (SocketException ex)
        {
            throw new ConnectionException(
                $"TCP connection to {host}:{port} failed. " +
                $"Socket error: {ex.SocketErrorCode} — {ex.Message}\n" +
                "Verify the server is reachable, the port is correct, and no firewall is blocking the connection.");
        }

        _networkStream = _tcpClient.GetStream();
        _networkStream.ReadTimeout = timeoutSeconds * 1000;
        _networkStream.WriteTimeout = timeoutSeconds * 1000;

        /* Send PRELOGIN requesting encryption */
        byte[] preloginPayload = BuildPreloginPayload();
        byte[] preloginPacket = TdsPacket.Build(
            TdsPacket.TypePreLogin, TdsPacket.StatusEom, preloginPayload);
        await _networkStream.WriteAsync(preloginPacket, ct);
        await _networkStream.FlushAsync(ct);

        /* Read PRELOGIN response */
        var (type, status, responsePayload) = await TdsPacket.ReadAsync(_networkStream, ct);
        if (type != TdsPacket.TypePreLogin)
        {
            throw new ConnectionException(
                $"Expected TDS PRELOGIN response (type 0x12), but received type 0x{type:X2}. " +
                "This may not be a SQL Server instance.");
        }

        ParsePreloginResponse(responsePayload, info);

        /* Check if encryption is supported */
        if (info.EncryptionMode == "NOT_SUP" || info.EncryptionMode == "OFF")
        {
            info.IsEncrypted = false;
            return info;
        }

        info.IsEncrypted = true;

        /* Perform TLS handshake wrapped in TDS PRELOGIN packets */
        var tdsStream = new TdsPreloginStream(_networkStream);
        var sslStream = new SslStream(
            tdsStream,
            leaveInnerStreamOpen: true,
            userCertificateValidationCallback: (_, cert, chain, errors) => true /* Accept any cert — we're inspecting, not validating trust */
        );

        try
        {
            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.None, /* Let the OS negotiate */
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            };

            using var tlsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            tlsCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
            await sslStream.AuthenticateAsClientAsync(sslOptions, tlsCts.Token);
        }
        catch (OperationCanceledException)
        {
            throw new ConnectionException(
                $"TLS handshake with {host}:{port} timed out after {timeoutSeconds} seconds.");
        }
        catch (AuthenticationException ex)
        {
            throw new ConnectionException(
                $"TLS handshake with {host}:{port} failed: {ex.Message}");
        }

        /* Extract TLS metadata */
        info.TlsProtocolVersion = sslStream.SslProtocol.ToString();
        info.CipherSuite = sslStream.NegotiatedCipherSuite.ToString();
#pragma warning disable SYSLIB0045
        info.KeyExchangeAlgorithm = sslStream.KeyExchangeAlgorithm.ToString();
        info.KeyExchangeStrength = sslStream.KeyExchangeStrength;
        info.HashAlgorithm = sslStream.HashAlgorithm.ToString();
        info.HashStrength = sslStream.HashStrength;
#pragma warning restore SYSLIB0045

        /* Extract certificate */
        var remoteCert = sslStream.RemoteCertificate;
        if (remoteCert != null)
        {
            var x509 = new X509Certificate2(remoteCert);
            info.Certificate = CertificateAnalyzer.Analyze(x509, host, showFullChain);
        }

        return info;
    }

    private static byte[] BuildPreloginPayload()
    {
        /*
         * PRELOGIN payload structure:
         *   Option tokens (type + offset + length) terminated by 0xFF
         *   Followed by option data
         *
         * We send: VERSION + ENCRYPTION + TERMINATOR
         */

        /* Calculate offsets */
        int optionHeaderSize = (2 * 5) + 1; /* 2 options * 5 bytes each + 1 terminator */
        int versionDataOffset = optionHeaderSize;
        int versionDataLength = 6; /* 4 bytes version + 2 bytes sub-build */
        int encryptionDataOffset = versionDataOffset + versionDataLength;
        int encryptionDataLength = 1;

        int totalLength = optionHeaderSize + versionDataLength + encryptionDataLength;
        byte[] payload = new byte[totalLength];
        int pos = 0;

        /* VERSION token header */
        payload[pos++] = TokenVersion;
        payload[pos++] = (byte)(versionDataOffset >> 8);
        payload[pos++] = (byte)(versionDataOffset & 0xFF);
        payload[pos++] = (byte)(versionDataLength >> 8);
        payload[pos++] = (byte)(versionDataLength & 0xFF);

        /* ENCRYPTION token header */
        payload[pos++] = TokenEncryption;
        payload[pos++] = (byte)(encryptionDataOffset >> 8);
        payload[pos++] = (byte)(encryptionDataOffset & 0xFF);
        payload[pos++] = (byte)(encryptionDataLength >> 8);
        payload[pos++] = (byte)(encryptionDataLength & 0xFF);

        /* Terminator */
        payload[pos++] = TokenTerminator;

        /* VERSION data: pretend to be SQL Server 16.0.0.0 (doesn't matter) */
        payload[pos++] = 16;
        payload[pos++] = 0;
        payload[pos++] = 0;
        payload[pos++] = 0;
        payload[pos++] = 0;
        payload[pos++] = 0;

        /* ENCRYPTION data: request encryption */
        payload[pos++] = EncryptOn;

        return payload;
    }

    private static void ParsePreloginResponse(byte[] payload, ConnectionSecurityInfo info)
    {
        int pos = 0;

        /* Parse option headers */
        var options = new Dictionary<byte, (int offset, int length)>();
        while (pos < payload.Length)
        {
            byte token = payload[pos++];
            if (token == TokenTerminator) break;

            if (pos + 4 > payload.Length) break;
            int offset = (payload[pos] << 8) | payload[pos + 1];
            int length = (payload[pos + 2] << 8) | payload[pos + 3];
            pos += 4;

            options[token] = (offset, length);
        }

        /* Parse VERSION */
        if (options.TryGetValue(TokenVersion, out var ver) && ver.offset + ver.length <= payload.Length && ver.length >= 6)
        {
            int major = payload[ver.offset];
            int minor = payload[ver.offset + 1];
            int buildHi = payload[ver.offset + 2];
            int buildLo = payload[ver.offset + 3];
            int build = (buildHi << 8) | buildLo;
            int subBuild = (payload[ver.offset + 4] << 8) | payload[ver.offset + 5];
            info.SqlServerVersion = $"{major}.{minor}.{build}.{subBuild}";
        }

        /* Parse ENCRYPTION */
        if (options.TryGetValue(TokenEncryption, out var enc) && enc.offset < payload.Length)
        {
            byte encVal = payload[enc.offset];
            info.EncryptionMode = encVal switch
            {
                EncryptOff => "OFF",
                EncryptOn => "ON",
                EncryptNotSupported => "NOT_SUP",
                EncryptRequired => "REQUIRED",
                EncryptClientCertificate => "CLIENT_CERT",
                _ => $"UNKNOWN(0x{encVal:X2})"
            };
        }
    }

    public void Dispose()
    {
        _networkStream?.Dispose();
        _tcpClient?.Dispose();
    }
}

public class ConnectionException : Exception
{
    public ConnectionException(string message) : base(message) { }
    public ConnectionException(string message, Exception inner) : base(message, inner) { }
}
