namespace SqlCertInspector;

/// <summary>
/// Exit codes returned by the application.
/// </summary>
public static class ExitCodes
{
    /// <summary>Connected successfully, certificate displayed.</summary>
    public const int Success = 0;

    /// <summary>Could not reach the server (TCP connection failed).</summary>
    public const int ConnectionFailure = 1;

    /// <summary>Server does not encrypt the connection.</summary>
    public const int EncryptionNotEnabled = 2;

    /// <summary>Could not resolve named instance via SQL Browser service.</summary>
    public const int BrowserResolutionFailure = 3;

    /// <summary>Invalid command-line arguments.</summary>
    public const int InvalidArguments = 4;

    /// <summary>An unexpected error occurred.</summary>
    public const int UnexpectedError = 5;
}
