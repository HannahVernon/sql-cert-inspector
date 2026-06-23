using System.CommandLine;
using System.Reflection;
using SqlCertInspector;

var serverOption = new Option<string>("--server", "-s")
{
    Description = "SQL Server target (server, server\\instance, server,port, or ip,port)",
    Required = true
};

var portOption = new Option<int?>("--port", "-p")
{
    Description = "TCP port (alternative to ,port or \\instance syntax)"
};

var timeoutOption = new Option<int>("--timeout", "-t")
{
    Description = "Connection timeout in seconds",
    DefaultValueFactory = _ => 5
};

var jsonOption = new Option<bool>("--json")
{
    Description = "Output in JSON format"
};

var chainOption = new Option<bool>("--show-full-certificate-chain")
{
    Description = "Display the full certificate chain (intermediate and root CA)"
};

var noColorOption = new Option<bool>("--no-color")
{
    Description = "Disable colored console output"
};

var skipKerberosOption = new Option<bool>("--skip-kerberos")
{
    Description = "Skip Kerberos SPN diagnostics (DNS diagnostics still run)"
};

var skipDnsOption = new Option<bool>("--skip-dns")
{
    Description = "Skip DNS diagnostics (Kerberos SPN lookups still run using the raw hostname)"
};

var fullSpnDiagnosticsOption = new Option<bool>("--full-spn-diagnostics")
{
    Description = "Check all SPN variants including portless base SPNs (normally only port/instance-specific SPNs are checked)"
};

var outputOption = new Option<string?>("--output", "-o")
{
    Description = "Write JSON output to a file. If no filename is given, auto-generates from --server value.",
    Arity = System.CommandLine.ArgumentArity.ZeroOrOne
};

var encryptStrictOption = new Option<bool>("--encrypt-strict", "--tds8")
{
    Description = "Connect using TDS 8.0 strict encryption (TLS before PRELOGIN, like HTTPS)"
};

var testSanConnectivityOption = new Option<bool>("--test-san-connectivity")
{
    Description = "Perform a full certificate inspection for each DNS name in the certificate's SANs"
};

var testKerberosOption = new Option<bool>("--test-kerberos")
{
    Description = "Perform an actual Kerberos authentication test to verify SPN, detect NTLM fallback, and check for RC4 etype (Windows only)"
};

var rootCommand = new RootCommand(
    "sql-cert-inspector — Inspect the TLS certificate used by a SQL Server instance.");

/* Required */
rootCommand.Options.Add(serverOption);
/* Optional — alphabetical */
rootCommand.Options.Add(encryptStrictOption);
rootCommand.Options.Add(fullSpnDiagnosticsOption);
rootCommand.Options.Add(jsonOption);
rootCommand.Options.Add(noColorOption);
rootCommand.Options.Add(outputOption);
rootCommand.Options.Add(portOption);
rootCommand.Options.Add(chainOption);
rootCommand.Options.Add(skipDnsOption);
rootCommand.Options.Add(skipKerberosOption);
rootCommand.Options.Add(testSanConnectivityOption);
rootCommand.Options.Add(testKerberosOption);
rootCommand.Options.Add(timeoutOption);

rootCommand.SetAction(async (parseResult, cancellationToken) =>
{
    bool outputSpecified = parseResult.GetResult(outputOption) != null;
    var options = new CommandLineOptions
    {
        Server = parseResult.GetValue(serverOption)!,
        Port = parseResult.GetValue(portOption),
        Timeout = Math.Clamp(parseResult.GetValue(timeoutOption), 1, 120),
        Json = parseResult.GetValue(jsonOption),
        ShowFullCertificateChain = parseResult.GetValue(chainOption),
        NoColor = parseResult.GetValue(noColorOption),
        SkipKerberos = parseResult.GetValue(skipKerberosOption),
        SkipDns = parseResult.GetValue(skipDnsOption),
        FullSpnDiagnostics = parseResult.GetValue(fullSpnDiagnosticsOption),
        TestSanConnectivity = parseResult.GetValue(testSanConnectivityOption),
        TestKerberos = parseResult.GetValue(testKerberosOption),
        OutputFileSpecified = outputSpecified,
        OutputFile = outputSpecified ? parseResult.GetValue(outputOption) : null,
        EncryptStrict = parseResult.GetValue(encryptStrictOption)
    };

    Environment.ExitCode = await RunAsync(options);
});

return rootCommand.Parse(args).Invoke();

static async Task<int> RunAsync(CommandLineOptions options)
{
    /* Version header for console output */
    if (!options.Json && !options.OutputFileSpecified)
    {
        string version = typeof(ServerEndpointResolver).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ?? "unknown";
        /* Strip the commit hash after '+' for a cleaner display */
        int plusIndex = version.IndexOf('+');
        if (plusIndex >= 0) version = version[..plusIndex];
        Console.Error.WriteLine($"sql-cert-inspector v{version}, by Hannah Vernon");
    }

    /* Parse the server endpoint */
    ServerEndpointResolver.ResolvedEndpoint endpoint;
    try
    {
        endpoint = ServerEndpointResolver.Parse(options.Server, options.Port);
    }
    catch (ArgumentException ex)
    {
        WriteError(options, $"Invalid arguments: {ex.Message}");
        return ExitCodes.InvalidArguments;
    }

    /* Resolve named instance via SQL Browser */
    int port;
    if (endpoint.NeedsBrowserLookup)
    {
        try
        {
            WriteInfo(options, $"Resolving instance '{endpoint.InstanceName}' via SQL Server Browser service on {endpoint.Host}:1434 (UDP)...");
            port = SqlBrowserClient.ResolveInstancePort(endpoint.Host, endpoint.InstanceName!, options.Timeout);
            WriteInfo(options, $"Resolved to TCP port {port}.");
        }
        catch (SqlBrowserException ex)
        {
            WriteError(options, ex.Message);
            return ExitCodes.BrowserResolutionFailure;
        }
    }
    else
    {
        port = endpoint.ExplicitPort!.Value;
    }

    /* Connect and inspect */
    string displayName = endpoint.InstanceName != null
        ? $"{endpoint.Host}\\{endpoint.InstanceName}"
        : endpoint.Host;

    WriteInfo(options, $"Connecting to {displayName} on TCP port {port}...");

    ConnectionSecurityInfo securityInfo;
    try
    {
        using var client = new TdsPreloginClient();
        securityInfo = await client.InspectAsync(
            endpoint.Host, port, displayName, options.Timeout,
            options.ShowFullCertificateChain, options.EncryptStrict);

        if (endpoint.InstanceName != null)
        {
            securityInfo.InstanceName = endpoint.InstanceName;
        }
    }
    catch (ProtocolMismatchException pmEx)
    {
        /* Protocol mismatch — retry with the alternate protocol */
        bool retryStrict = pmEx.AttemptedProtocol == TdsProtocolVersion.Tds7;
        string retryProtocol = retryStrict ? "TDS 8.0 (Strict)" : "TDS 7.x";

        WriteInfo(options, $"{pmEx.Message}");
        WriteInfo(options, $"Retrying with {retryProtocol}...");

        try
        {
            using var retryClient = new TdsPreloginClient();
            securityInfo = await retryClient.InspectAsync(
                endpoint.Host, port, displayName, options.Timeout,
                options.ShowFullCertificateChain, retryStrict);

            securityInfo.UsedFallback = true;

            if (endpoint.InstanceName != null)
            {
                securityInfo.InstanceName = endpoint.InstanceName;
            }
        }
        catch (ConnectionException retryEx)
        {
            WriteError(options, $"Fallback to {retryProtocol} also failed: {retryEx.Message}");
            return ExitCodes.ConnectionFailure;
        }
    }
    catch (ConnectionException ex)
    {
        WriteError(options, ex.Message);
        return ExitCodes.ConnectionFailure;
    }
    catch (Exception ex)
    {
        WriteError(options, $"Unexpected error: {ex.Message}");
        return ExitCodes.UnexpectedError;
    }

    /* Kerberos and DNS diagnostics */
    bool runDns = !options.SkipDns;
    bool runKerberos = !options.SkipKerberos;

    if ((runDns || runKerberos) && OperatingSystem.IsWindows())
    {
        string scope = (runDns, runKerberos) switch
        {
            (true, true)   => "Kerberos and DNS",
            (true, false)  => "DNS",
            (false, true)  => "Kerberos SPN",
            _              => ""
        };
        WriteInfo(options, $"Running {scope} diagnostics...");
        try
        {
            securityInfo.Kerberos = KerberosInspector.Inspect(
                endpoint.Host, port, endpoint.InstanceName,
                endpoint.IsPortExplicit, options.FullSpnDiagnostics,
                skipDns: !runDns, skipKerberos: !runKerberos);
        }
        catch (Exception ex)
        {
            WriteInfo(options, $"Diagnostics failed: {ex.Message}");
        }
    }

    /* Cross-reference certificate SANs with DNS/Kerberos data */
    if (securityInfo.Certificate != null)
    {
        CertificateAnalyzer.CrossReferenceSans(securityInfo.Certificate, securityInfo.Kerberos);

        /* SPN lookup per SAN hostname (--full-spn-diagnostics) */
        if (options.FullSpnDiagnostics && securityInfo.Kerberos != null && OperatingSystem.IsWindows())
        {
            try
            {
                KerberosInspector.CrossReferenceSanSpns(
                    securityInfo.Kerberos, securityInfo.Certificate,
                    port, endpoint.Host);
            }
            catch (Exception ex)
            {
                WriteInfo(options, $"SAN SPN cross-reference failed: {ex.Message}");
            }
        }
    }

    /* SAN connectivity tests (--test-san-connectivity) */
    if (options.TestSanConnectivity && securityInfo.Certificate != null &&
        securityInfo.Certificate.SubjectAlternativeNames.Count > 0)
    {
        await RunSanConnectivityTests(options, securityInfo, endpoint.Host, port);
    }

    /* Kerberos authentication test (--test-kerberos) */
    if (options.TestKerberos && securityInfo.IsEncrypted && OperatingSystem.IsWindows())
    {
        WriteInfo(options, "Running Kerberos authentication test...");
        try
        {
            securityInfo.KerberosAuthTest = await RunKerberosAuthTest(
                endpoint.Host, port, endpoint.InstanceName,
                options.Timeout, options.EncryptStrict);
        }
        catch (Exception ex)
        {
            securityInfo.KerberosAuthTest = new KerberosAuthResult
            {
                Success = false,
                Error = ex.Message,
                Spn = endpoint.InstanceName != null
                    ? $"MSSQLSvc/{endpoint.Host}:{endpoint.InstanceName}"
                    : $"MSSQLSvc/{endpoint.Host}:{port}"
            };
        }
    }

    /* Report */
    if (!options.Json && !options.OutputFileSpecified)
    {
        Console.WriteLine();
    }

    if (!securityInfo.IsEncrypted)
    {
        if (options.OutputFileSpecified)
        {
            int writeResult = WriteOutputFile(options, securityInfo);
            if (writeResult != ExitCodes.Success) return writeResult;
        }
        else if (options.Json)
        {
            JsonReporter.Report(securityInfo);
        }
        else
        {
            ConsoleReporter.Report(securityInfo, options.NoColor);
        }
        return ExitCodes.EncryptionNotEnabled;
    }

    if (options.OutputFileSpecified)
    {
        int writeResult = WriteOutputFile(options, securityInfo);
        if (writeResult != ExitCodes.Success) return writeResult;
    }
    else if (options.Json)
    {
        JsonReporter.Report(securityInfo);
    }
    else
    {
        ConsoleReporter.Report(securityInfo, options.NoColor);
    }

    /* Return non-zero if there are error-severity warnings */
    if (securityInfo.Certificate?.Warnings.Any(w => w.Severity == WarningSeverity.Error) == true)
    {
        return ExitCodes.ConnectionFailure;
    }

    return ExitCodes.Success;
}

static void WriteError(CommandLineOptions options, string message)
{
    if (options.Json && !options.OutputFileSpecified)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { error = message },
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }
    else
    {
        bool useColor = !options.NoColor && !Console.IsErrorRedirected;
        if (useColor) Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.WriteLine($"ERROR: {message}");
        if (useColor) Console.ResetColor();
    }
}

static void WriteInfo(CommandLineOptions options, string message)
{
    if (!options.Json && !options.OutputFileSpecified)
    {
        bool useColor = !options.NoColor && !Console.IsErrorRedirected;
        if (useColor) Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Error.WriteLine(message);
        if (useColor) Console.ResetColor();
    }
}

/// <summary>
/// Writes JSON output to a file. Returns an exit code (Success or FileWriteError).
/// </summary>
static int WriteOutputFile(CommandLineOptions options, ConnectionSecurityInfo securityInfo)
{
    string fileName = options.OutputFile ?? OutputFileHelper.GenerateOutputFileName(options.Server);

    /* Canonicalize the path to prevent directory traversal (CWE-22) */
    string canonicalPath = Path.GetFullPath(fileName);

    try
    {
        string json = JsonReporter.GenerateJson(securityInfo);
        File.WriteAllText(canonicalPath, json);
        Console.Error.WriteLine($"Output written to: {Path.GetFileName(canonicalPath)}");
        return ExitCodes.Success;
    }
    catch (UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"ERROR: Cannot write output file '{Path.GetFileName(canonicalPath)}': access denied.");
        return ExitCodes.FileWriteError;
    }
    catch (DirectoryNotFoundException)
    {
        Console.Error.WriteLine($"ERROR: Cannot write output file '{Path.GetFileName(canonicalPath)}': directory not found.");
        return ExitCodes.FileWriteError;
    }
    catch (IOException ex)
    {
        Console.Error.WriteLine($"ERROR: Cannot write output file '{Path.GetFileName(canonicalPath)}': {ex.GetType().Name}");
        return ExitCodes.FileWriteError;
    }
}

/// <summary>
/// Runs a full TDS PRELOGIN + TLS inspection for each DNS SAN hostname that differs
/// from the primary connection hostname. Prevents recursion by not running SAN tests
/// on sub-inspections.
/// </summary>
static async Task RunSanConnectivityTests(
    CommandLineOptions options, ConnectionSecurityInfo primaryInfo,
    string primaryHostname, int port)
{
    var sanHostnames = primaryInfo.Certificate!.SubjectAlternativeNames
        .Where(s => s.StartsWith("DNS:", StringComparison.OrdinalIgnoreCase))
        .Select(s => s[4..])
        .Where(h => !h.StartsWith("*")) /* skip wildcard SANs */
        .Where(h => !string.Equals(h, primaryHostname, StringComparison.OrdinalIgnoreCase))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    if (sanHostnames.Count == 0) return;

    string primaryThumbprint = primaryInfo.Certificate.ThumbprintSha256;
    primaryInfo.SanConnectivityResults = new List<SanConnectivityResult>();

    WriteInfo(options, $"Testing SAN connectivity for {sanHostnames.Count} hostname(s)...");

    foreach (string sanHost in sanHostnames)
    {
        WriteInfo(options, $"  Inspecting {sanHost}:{port}...");

        var result = new SanConnectivityResult { SanHostname = sanHost };

        try
        {
            using var client = new TdsPreloginClient();
            var sanInfo = await client.InspectAsync(
                sanHost, port, sanHost, options.Timeout,
                showFullChain: false, options.EncryptStrict);

            result.Connected = true;
            result.SecurityInfo = sanInfo;
            result.SameCertificate = sanInfo.Certificate != null &&
                string.Equals(sanInfo.Certificate.ThumbprintSha256, primaryThumbprint,
                    StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            result.Connected = false;
            result.Error = ex.Message;
        }

        primaryInfo.SanConnectivityResults.Add(result);
    }
}

/// <summary>
/// Opens a fresh connection to the SQL Server, performs PRELOGIN + TLS,
/// then sends a LOGIN7 with SSPI to test Kerberos authentication.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
static async Task<KerberosAuthResult> RunKerberosAuthTest(
    string host, int port, string? instanceName,
    int timeoutSeconds, bool encryptStrict)
{
    using var tcpClient = new System.Net.Sockets.TcpClient();
    var addresses = await System.Net.Dns.GetHostAddressesAsync(host);
    if (addresses.Length == 0)
        throw new ConnectionException($"DNS resolution for '{host}' returned no addresses.");

    using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
    await tcpClient.ConnectAsync(addresses[0], port, connectCts.Token);

    var networkStream = tcpClient.GetStream();
    networkStream.ReadTimeout = timeoutSeconds * 1000;
    networkStream.WriteTimeout = timeoutSeconds * 1000;

    Stream authStream;

    if (encryptStrict)
    {
        /* TDS 8.0: TLS directly on TCP */
        var sslStream = new System.Net.Security.SslStream(
            networkStream, leaveInnerStreamOpen: true,
            userCertificateValidationCallback: (_, _, _, _) => true);

        var sslOptions = new System.Net.Security.SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = System.Security.Authentication.SslProtocols.None,
            CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
            ApplicationProtocols = [new System.Net.Security.SslApplicationProtocol("tds/8.0")]
        };

        await sslStream.AuthenticateAsClientAsync(sslOptions, connectCts.Token);

        /* Send PRELOGIN inside TLS tunnel (required for TDS 8.0 before LOGIN7) */
        byte[] prePayload = BuildPreloginForAuth();
        byte[] prePacket = TdsPacket.Build(TdsPacket.TypePreLogin, TdsPacket.StatusEom, prePayload);
        await sslStream.WriteAsync(prePacket, connectCts.Token);
        await sslStream.FlushAsync(connectCts.Token);

        try
        {
            await TdsPacket.ReadAsync(sslStream, connectCts.Token);
        }
        catch { /* best-effort */ }

        authStream = sslStream;
    }
    else
    {
        /* TDS 7.x: PRELOGIN cleartext, then TLS wrapped in TDS packets */
        byte[] prePayload = BuildPreloginForAuth();
        byte[] prePacket = TdsPacket.Build(TdsPacket.TypePreLogin, TdsPacket.StatusEom, prePayload);
        await networkStream.WriteAsync(prePacket, connectCts.Token);
        await networkStream.FlushAsync(connectCts.Token);

        var (type, _, _) = await TdsPacket.ReadAsync(networkStream, connectCts.Token);
        if (type != TdsPacket.TypeTabularResult)
        {
            throw new ConnectionException(
                $"Expected PRELOGIN response (type 0x04), received 0x{type:X2}.");
        }

        /* TLS handshake wrapped in TDS packets */
        var tdsStream = new TdsPreloginStream(networkStream);
        var sslStream = new System.Net.Security.SslStream(
            tdsStream, leaveInnerStreamOpen: true,
            userCertificateValidationCallback: (_, _, _, _) => true);

        var sslOptions = new System.Net.Security.SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = System.Security.Authentication.SslProtocols.None,
            CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
        };

        await sslStream.AuthenticateAsClientAsync(sslOptions, connectCts.Token);

        /* After TLS handshake, SQL Server expects TDS packets directly on the
           SslStream (no more TdsPreloginStream wrapping for LOGIN7) */
        authStream = sslStream;
    }

    return await KerberosAuthTester.TestAsync(
        authStream, host, port, instanceName, timeoutSeconds);
}

/// <summary>
/// Builds a minimal PRELOGIN payload for the auth test connection.
/// </summary>
static byte[] BuildPreloginForAuth()
{
    /* Version + Encryption + Terminator */
    int optionSize = 2 * 5 + 1; /* 2 options x 5 bytes each + terminator */
    int versionDataLen = 6;
    int encryptDataLen = 1;
    int dataOffset = optionSize;

    byte[] payload = new byte[optionSize + versionDataLen + encryptDataLen];
    int pos = 0;

    /* Version option */
    payload[pos++] = 0x00; /* TOKEN_VERSION */
    payload[pos++] = (byte)(dataOffset >> 8);
    payload[pos++] = (byte)(dataOffset & 0xFF);
    payload[pos++] = (byte)(versionDataLen >> 8);
    payload[pos++] = (byte)(versionDataLen & 0xFF);

    /* Encryption option */
    int encOffset = dataOffset + versionDataLen;
    payload[pos++] = 0x01; /* TOKEN_ENCRYPTION */
    payload[pos++] = (byte)(encOffset >> 8);
    payload[pos++] = (byte)(encOffset & 0xFF);
    payload[pos++] = (byte)(encryptDataLen >> 8);
    payload[pos++] = (byte)(encryptDataLen & 0xFF);

    /* Terminator */
    payload[pos++] = 0xFF;

    /* Version data: 0.0.0.0 build 0 */
    payload[dataOffset] = 0;
    payload[dataOffset + 1] = 0;
    payload[dataOffset + 2] = 0;
    payload[dataOffset + 3] = 0;
    payload[dataOffset + 4] = 0;
    payload[dataOffset + 5] = 0;

    /* Encryption: ON (0x01) */
    payload[encOffset] = 0x01;

    return payload;
}

