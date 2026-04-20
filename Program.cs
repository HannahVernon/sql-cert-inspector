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
    Description = "Skip Kerberos and DNS diagnostics"
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

var rootCommand = new RootCommand(
    "sql-cert-inspector — Inspect the TLS certificate used by a SQL Server instance.");

rootCommand.Options.Add(serverOption);
rootCommand.Options.Add(portOption);
rootCommand.Options.Add(timeoutOption);
rootCommand.Options.Add(jsonOption);
rootCommand.Options.Add(chainOption);
rootCommand.Options.Add(noColorOption);
rootCommand.Options.Add(skipKerberosOption);
rootCommand.Options.Add(outputOption);
rootCommand.Options.Add(encryptStrictOption);

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
    if (!options.SkipKerberos && OperatingSystem.IsWindows())
    {
        WriteInfo(options, "Running Kerberos and DNS diagnostics...");
        try
        {
            securityInfo.Kerberos = KerberosInspector.Inspect(endpoint.Host, port, endpoint.InstanceName);
        }
        catch (Exception ex)
        {
            WriteInfo(options, $"Kerberos diagnostics failed: {ex.Message}");
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

