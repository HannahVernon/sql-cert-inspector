namespace SqlCertInspector;

/// <summary>
/// Parsed command-line options.
/// </summary>
public sealed class CommandLineOptions
{
    public string Server { get; set; } = string.Empty;
    public int? Port { get; set; }
    public int Timeout { get; set; } = 5;
    public bool Json { get; set; }
    public bool ShowFullCertificateChain { get; set; }
    public bool NoColor { get; set; }
    public bool SkipKerberos { get; set; }

    /// <summary>
    /// When true, the --output option was specified on the command line.
    /// </summary>
    public bool OutputFileSpecified { get; set; }

    /// <summary>
    /// Output file path for JSON results. Null when auto-generating from server name.
    /// </summary>
    public string? OutputFile { get; set; }
}
