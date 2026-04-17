using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace SqlCertInspector;

/// <summary>
/// Connects to a SQL Server instance at the TDS protocol level, performs the
/// PRELOGIN exchange and TLS handshake, and extracts the server certificate
/// and connection security metadata — all without sending a LOGIN packet.
/// Supports both TDS 7.x (PRELOGIN first) and TDS 8.0 Strict (TLS first) flows.
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
        bool showFullChain, bool encryptStrict = false, CancellationToken ct = default)
    {
        var info = new ConnectionSecurityInfo
        {
            ServerName = serverDisplayName,
            ResolvedHost = host,
            ResolvedPort = port
        };

        /* Resolve hostname to IP addresses */
        IPAddress[] addresses = await ResolveAddressesAsync(host, info, ct);

        /* TCP connect — parallel race when multiple IPs, direct when single */
        await ConnectTcpAsync(addresses, host, port, timeoutSeconds, info, ct);

        _networkStream = _tcpClient!.GetStream();
        _networkStream.ReadTimeout = timeoutSeconds * 1000;
        _networkStream.WriteTimeout = timeoutSeconds * 1000;

        if (encryptStrict)
        {
            await InspectTds8StrictAsync(host, port, timeoutSeconds, showFullChain, info, ct);
        }
        else
        {
            await InspectTds7Async(host, port, timeoutSeconds, showFullChain, info, ct);
        }

        return info;
    }

    /// <summary>
    /// TDS 7.x flow: PRELOGIN (cleartext) → TLS handshake (wrapped in TDS packets).
    /// Throws <see cref="ProtocolMismatchException"/> if the server appears to expect TDS 8.0.
    /// </summary>
    private async Task InspectTds7Async(
        string host, int port, int timeoutSeconds, bool showFullChain,
        ConnectionSecurityInfo info, CancellationToken ct)
    {
        info.TdsProtocol = TdsProtocolVersion.Tds7;

        /* Send PRELOGIN requesting encryption */
        byte[] preloginPayload = BuildPreloginPayload();
        byte[] preloginPacket = TdsPacket.Build(
            TdsPacket.TypePreLogin, TdsPacket.StatusEom, preloginPayload);

        try
        {
            await _networkStream!.WriteAsync(preloginPacket, ct);
            await _networkStream.FlushAsync(ct);
        }
        catch (IOException ex)
        {
            throw new ProtocolMismatchException(
                TdsProtocolVersion.Tds7,
                "Failed to send TDS PRELOGIN — the server may require strict encryption (TDS 8.0).",
                ex);
        }

        /* Read PRELOGIN response */
        byte type;
        byte[] responsePayload;
        try
        {
            byte status;
            (type, status, responsePayload) = await TdsPacket.ReadAsync(_networkStream, ct);
        }
        catch (IOException ex)
        {
            throw new ProtocolMismatchException(
                TdsProtocolVersion.Tds7,
                "Connection closed while reading TDS PRELOGIN response — the server may require strict encryption (TDS 8.0).",
                ex);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("connection was closed"))
        {
            throw new ProtocolMismatchException(
                TdsProtocolVersion.Tds7,
                "Connection closed while reading TDS PRELOGIN response — the server may require strict encryption (TDS 8.0).",
                ex);
        }

        if (type != TdsPacket.TypeTabularResult)
        {
            throw new ConnectionException(
                $"Expected TDS PRELOGIN response (type 0x04), but received type 0x{type:X2}. " +
                "This may not be a SQL Server instance.");
        }

        ParsePreloginResponse(responsePayload, info);

        /* Check if encryption is supported */
        if (info.EncryptionMode == "NOT_SUP" || info.EncryptionMode == "OFF")
        {
            info.IsEncrypted = false;
            return;
        }

        info.IsEncrypted = true;

        /* Perform TLS handshake wrapped in TDS PRELOGIN packets */
        var tdsStream = new TdsPreloginStream(_networkStream);
        using var sslStream = new SslStream(
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

        ExtractTlsMetadata(sslStream, info);
        ExtractCertificate(sslStream, host, showFullChain, info);
    }

    /// <summary>
    /// TDS 8.0 Strict flow: TLS handshake first (plain, like HTTPS), then PRELOGIN inside
    /// the encrypted tunnel. Throws <see cref="ProtocolMismatchException"/> if the server
    /// appears to expect TDS 7.x.
    /// </summary>
    private async Task InspectTds8StrictAsync(
        string host, int port, int timeoutSeconds, bool showFullChain,
        ConnectionSecurityInfo info, CancellationToken ct)
    {
        info.TdsProtocol = TdsProtocolVersion.Tds8Strict;
        info.IsEncrypted = true;

        /* TDS 8.0: TLS handshake directly on the TCP socket (no TDS wrapping) */
        using var sslStream = new SslStream(
            _networkStream!,
            leaveInnerStreamOpen: true,
            userCertificateValidationCallback: (_, cert, chain, errors) => true
        );

        try
        {
            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                ApplicationProtocols = [new SslApplicationProtocol("tds/8.0")]
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
            throw new ProtocolMismatchException(
                TdsProtocolVersion.Tds8Strict,
                $"TLS handshake failed — the server may not support strict encryption (TDS 8.0): {ex.Message}",
                ex);
        }
        catch (IOException ex)
        {
            throw new ProtocolMismatchException(
                TdsProtocolVersion.Tds8Strict,
                $"Connection error during TLS handshake — the server may not support strict encryption (TDS 8.0): {ex.Message}",
                ex);
        }

        ExtractTlsMetadata(sslStream, info);
        ExtractCertificate(sslStream, host, showFullChain, info);

        /* Send PRELOGIN inside the TLS tunnel to get server version */
        try
        {
            byte[] preloginPayload = BuildPreloginPayload();
            byte[] preloginPacket = TdsPacket.Build(
                TdsPacket.TypePreLogin, TdsPacket.StatusEom, preloginPayload);

            await sslStream.WriteAsync(preloginPacket, ct);
            await sslStream.FlushAsync(ct);

            var (type, status, responsePayload) = await TdsPacket.ReadAsync(sslStream, ct);
            if (type == TdsPacket.TypeTabularResult)
            {
                ParsePreloginResponse(responsePayload, info);
            }

            /* Override encryption mode — TDS 8.0 always means full encryption */
            info.EncryptionMode = "STRICT";
        }
        catch
        {
            /* PRELOGIN inside tunnel is best-effort — we already have the certificate.
               If it fails, we just won't have the SQL Server version. */
            info.EncryptionMode = "STRICT";
        }
    }

    private static void ExtractTlsMetadata(SslStream sslStream, ConnectionSecurityInfo info)
    {
        info.TlsProtocolVersion = sslStream.SslProtocol.ToString();
        info.CipherSuite = sslStream.NegotiatedCipherSuite.ToString();
#pragma warning disable SYSLIB0045
        info.KeyExchangeAlgorithm = sslStream.KeyExchangeAlgorithm.ToString();
        info.KeyExchangeStrength = sslStream.KeyExchangeStrength;
        info.HashAlgorithm = sslStream.HashAlgorithm.ToString();
        info.HashStrength = sslStream.HashStrength;
#pragma warning restore SYSLIB0045
    }

    private static void ExtractCertificate(
        SslStream sslStream, string host, bool showFullChain, ConnectionSecurityInfo info)
    {
        var remoteCert = sslStream.RemoteCertificate;
        if (remoteCert != null)
        {
            using var x509 = new X509Certificate2(remoteCert);
            info.Certificate = CertificateAnalyzer.Analyze(x509, host, showFullChain, info.ResolvedHostname);
        }
    }

    private async Task<IPAddress[]> ResolveAddressesAsync(
        string host, ConnectionSecurityInfo info, CancellationToken ct)
    {
        if (IPAddress.TryParse(host, out var directIp))
        {
            return [directIp];
        }

        /* Use DnsResolver for record type info when on Windows */
        if (OperatingSystem.IsWindows())
        {
            var dnsResult = DnsResolver.ResolveHost(host);
            if (dnsResult.WasSuffixExpanded && dnsResult.ResolvedFqdn != null)
            {
                info.ResolvedHostname = dnsResult.ResolvedFqdn;
            }
        }

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(host, ct);

            if (addresses.Length == 0)
            {
                throw new ConnectionException(
                    $"DNS resolution for '{host}' returned no IP addresses.");
            }

            info.ResolvedIPs = addresses.Select(a => a.ToString()).ToArray();
            return addresses;
        }
        catch (SocketException ex)
        {
            throw new ConnectionException(
                $"DNS resolution for '{host}' failed: {ex.Message}");
        }
    }

    private async Task ConnectTcpAsync(
        IPAddress[] addresses, string host, int port, int timeoutSeconds,
        ConnectionSecurityInfo info, CancellationToken ct)
    {
        if (addresses.Length == 1)
        {
            _tcpClient = new TcpClient();
            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
                await _tcpClient.ConnectAsync(addresses[0], port, connectCts.Token);
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

            if (info.ResolvedIPs != null)
            {
                info.ConnectedIP = addresses[0].ToString();
            }
        }
        else
        {
            _tcpClient = await ConnectParallelAsync(addresses, host, port, timeoutSeconds, ct);
            var connectedAddr = ((IPEndPoint)_tcpClient.Client.RemoteEndPoint!).Address;
            info.ConnectedIP = connectedAddr.IsIPv4MappedToIPv6
                ? connectedAddr.MapToIPv4().ToString()
                : connectedAddr.ToString();
        }
    }

    /// <summary>
    /// Races TCP connections to all IP addresses simultaneously.
    /// Returns the first successful TcpClient; disposes all losers.
    /// </summary>
    internal static async Task<TcpClient> ConnectParallelAsync(
        IPAddress[] addresses, string host, int port, int timeoutSeconds, CancellationToken ct)
    {
        using var raceCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        raceCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        var clients = new TcpClient[addresses.Length];
        var tasks = new Task[addresses.Length];

        for (int i = 0; i < addresses.Length; i++)
        {
            clients[i] = new TcpClient();
            var client = clients[i];
            var addr = addresses[i];
            tasks[i] = client.ConnectAsync(addr, port, raceCts.Token).AsTask();
        }

        /* Find the first successful connection */
        var errors = new List<Exception>();
        var remaining = new List<(int index, Task task)>();
        for (int i = 0; i < tasks.Length; i++)
        {
            remaining.Add((i, tasks[i]));
        }

        TcpClient? winner = null;

        while (remaining.Count > 0 && winner == null)
        {
            var completedTask = await Task.WhenAny(remaining.Select(r => r.task));

            var entry = remaining.First(r => r.task == completedTask);
            remaining.Remove(entry);

            if (completedTask.IsCompletedSuccessfully)
            {
                winner = clients[entry.index];
            }
            else if (completedTask.Exception != null)
            {
                errors.Add(completedTask.Exception.InnerException ?? completedTask.Exception);
            }
            else
            {
                /* Cancelled */
                errors.Add(new OperationCanceledException());
            }
        }

        /* Cancel and dispose all losers */
        if (winner != null)
        {
            try { await raceCts.CancelAsync(); } catch { /* best effort */ }

            for (int i = 0; i < clients.Length; i++)
            {
                if (clients[i] != winner)
                {
                    try { clients[i].Dispose(); } catch { /* best effort */ }
                }
            }

            return winner;
        }

        /* All failed — dispose everything and throw aggregate error */
        for (int i = 0; i < clients.Length; i++)
        {
            try { clients[i].Dispose(); } catch { /* best effort */ }
        }

        var ipList = string.Join(", ", addresses.Select(a => a.ToString()));
        bool allTimedOut = errors.All(e => e is OperationCanceledException);

        if (allTimedOut)
        {
            throw new ConnectionException(
                $"TCP connection to {host}:{port} timed out after {timeoutSeconds} seconds. " +
                $"Attempted all resolved IPs ({ipList}) simultaneously — none responded. " +
                "Verify the server is reachable and the port is correct.");
        }

        throw new ConnectionException(
            $"TCP connection to {host}:{port} failed across all resolved IPs ({ipList}). " +
            $"Errors: {string.Join("; ", errors.Select(e => e.Message))}\n" +
            "Verify the server is reachable, the port is correct, and no firewall is blocking the connection.");
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
        if (options.TryGetValue(TokenVersion, out var ver) && ver.length >= 6 &&
            ver.offset >= 0 && ver.offset <= payload.Length - ver.length)
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
        if (options.TryGetValue(TokenEncryption, out var enc) && enc.length >= 1 &&
            enc.offset >= 0 && enc.offset < payload.Length)
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

/// <summary>
/// Thrown when a TDS protocol mismatch is detected, indicating the server
/// expects a different protocol version (TDS 7.x vs TDS 8.0 Strict).
/// </summary>
public class ProtocolMismatchException : ConnectionException
{
    public TdsProtocolVersion AttemptedProtocol { get; }

    public ProtocolMismatchException(TdsProtocolVersion attempted, string message)
        : base(message)
    {
        AttemptedProtocol = attempted;
    }

    public ProtocolMismatchException(TdsProtocolVersion attempted, string message, Exception inner)
        : base(message, inner)
    {
        AttemptedProtocol = attempted;
    }
}
