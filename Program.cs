using System.CommandLine;
using System.CommandLine.Invocation;
using System.Reflection;
using SqlCertInspector;

var serverOption = new Option<string>(
    name: "--server",
    description: "SQL Server target (server, server\\instance, server,port, or ip,port)")
{
    IsRequired = true
};
serverOption.AddAlias("-s");

var portOption = new Option<int?>(
    name: "--port",
    description: "TCP port (alternative to ,port or \\instance syntax)");
portOption.AddAlias("-p");

var timeoutOption = new Option<int>(
    name: "--timeout",
    getDefaultValue: () => 5,
    description: "Connection timeout in seconds");
timeoutOption.AddAlias("-t");

var jsonOption = new Option<bool>(
    name: "--json",
    description: "Output in JSON format");

var chainOption = new Option<bool>(
    name: "--show-full-certificate-chain",
    description: "Display the full certificate chain (intermediate and root CA)");

var noColorOption = new Option<bool>(
    name: "--no-color",
    description: "Disable colored console output");

var skipKerberosOption = new Option<bool>(
    name: "--skip-kerberos",
    description: "Skip Kerberos and DNS diagnostics");

var outputOption = new Option<string?>(
    name: "--output",
    description: "Write JSON output to a file. If no filename is given, auto-generates from --server value.")
{
    Arity = System.CommandLine.ArgumentArity.ZeroOrOne
};
outputOption.AddAlias("-o");

var encryptStrictOption = new Option<bool>(
    name: "--encrypt-strict",
    description: "Connect using TDS 8.0 strict encryption (TLS before PRELOGIN, like HTTPS)");
encryptStrictOption.AddAlias("--tds8");

var rootCommand = new RootCommand(
    "sql-cert-inspector — Inspect the TLS certificate used by a SQL Server instance.")
{
    serverOption,
    portOption,
    timeoutOption,
    jsonOption,
    chainOption,
    noColorOption,
    skipKerberosOption,
    outputOption,
    encryptStrictOption
};

rootCommand.SetHandler(async (InvocationContext context) =>
{
    bool outputSpecified = context.ParseResult.FindResultFor(outputOption) != null;
    var options = new CommandLineOptions
    {
        Server = context.ParseResult.GetValueForOption(serverOption)!,
        Port = context.ParseResult.GetValueForOption(portOption),
        Timeout = Math.Clamp(context.ParseResult.GetValueForOption(timeoutOption), 1, 120),
        Json = context.ParseResult.GetValueForOption(jsonOption),
        ShowFullCertificateChain = context.ParseResult.GetValueForOption(chainOption),
        NoColor = context.ParseResult.GetValueForOption(noColorOption),
        SkipKerberos = context.ParseResult.GetValueForOption(skipKerberosOption),
        OutputFileSpecified = outputSpecified,
        OutputFile = outputSpecified ? context.ParseResult.GetValueForOption(outputOption) : null,
        EncryptStrict = context.ParseResult.GetValueForOption(encryptStrictOption)
    };

    context.ExitCode = await RunAsync(options);
});

return await rootCommand.InvokeAsync(args);

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

    try
    {
        string json = JsonReporter.GenerateJson(securityInfo);
        File.WriteAllText(fileName, json);
        Console.Error.WriteLine($"Output written to: {fileName}");
        return ExitCodes.Success;
    }
    catch (UnauthorizedAccessException ex)
    {
        Console.Error.WriteLine($"ERROR: Cannot write output file '{fileName}': {ex.Message}");
        return ExitCodes.FileWriteError;
    }
    catch (DirectoryNotFoundException ex)
    {
        Console.Error.WriteLine($"ERROR: Cannot write output file '{fileName}': {ex.Message}");
        return ExitCodes.FileWriteError;
    }
    catch (IOException ex)
    {
        Console.Error.WriteLine($"ERROR: Cannot write output file '{fileName}': {ex.Message}");
        return ExitCodes.FileWriteError;
    }
}

