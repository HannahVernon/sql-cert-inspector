using System.CommandLine;
using System.CommandLine.Invocation;
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
    description: "Connection timeout in seconds (default: 5)");
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

var rootCommand = new RootCommand(
    "sql-cert-inspector — Inspect the TLS certificate used by a SQL Server instance.")
{
    serverOption,
    portOption,
    timeoutOption,
    jsonOption,
    chainOption,
    noColorOption,
    skipKerberosOption
};

rootCommand.SetHandler(async (InvocationContext context) =>
{
    var options = new CommandLineOptions
    {
        Server = context.ParseResult.GetValueForOption(serverOption)!,
        Port = context.ParseResult.GetValueForOption(portOption),
        Timeout = Math.Clamp(context.ParseResult.GetValueForOption(timeoutOption), 1, 120),
        Json = context.ParseResult.GetValueForOption(jsonOption),
        ShowFullCertificateChain = context.ParseResult.GetValueForOption(chainOption),
        NoColor = context.ParseResult.GetValueForOption(noColorOption),
        SkipKerberos = context.ParseResult.GetValueForOption(skipKerberosOption)
    };

    context.ExitCode = await RunAsync(options);
});

return await rootCommand.InvokeAsync(args);

static async Task<int> RunAsync(CommandLineOptions options)
{
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
            options.ShowFullCertificateChain);

        if (endpoint.InstanceName != null)
        {
            securityInfo.InstanceName = endpoint.InstanceName;
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
            securityInfo.Kerberos = KerberosInspector.Inspect(endpoint.Host, port, endpoint.InstanceName != null);
        }
        catch (Exception ex)
        {
            WriteInfo(options, $"Kerberos diagnostics failed: {ex.Message}");
        }
    }

    /* Report */
    if (!options.Json)
    {
        Console.WriteLine();
    }

    if (!securityInfo.IsEncrypted)
    {
        if (options.Json)
        {
            JsonReporter.Report(securityInfo);
        }
        else
        {
            ConsoleReporter.Report(securityInfo, options.NoColor);
        }
        return ExitCodes.EncryptionNotEnabled;
    }

    if (options.Json)
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
    if (options.Json)
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
    if (!options.Json)
    {
        bool useColor = !options.NoColor && !Console.IsErrorRedirected;
        if (useColor) Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Error.WriteLine(message);
        if (useColor) Console.ResetColor();
    }
}

