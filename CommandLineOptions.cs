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
}
