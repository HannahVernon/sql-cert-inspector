namespace SqlCertInspector;

/// <summary>
/// Helpers for the --output file feature.
/// </summary>
public static class OutputFileHelper
{
    private static readonly char[] s_invalidChars = ['\\', '/', ':', '*', '?', '"', '<', '>', '|'];

    /// <summary>
    /// Generates the output filename from the --server value by replacing characters
    /// that are illegal in file names with a hyphen.
    /// </summary>
    public static string GenerateOutputFileName(string serverName)
    {
        var result = serverName.ToCharArray();
        for (int i = 0; i < result.Length; i++)
        {
            if (Array.IndexOf(s_invalidChars, result[i]) >= 0)
            {
                result[i] = '-';
            }
        }

        string sanitized = new string(result).Trim('-');
        if (string.IsNullOrWhiteSpace(sanitized))
        {
            sanitized = "output";
        }

        return sanitized + ".json";
    }
}
