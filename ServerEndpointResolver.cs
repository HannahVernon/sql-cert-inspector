namespace SqlCertInspector;

/// <summary>
/// Parses the --server argument into host, instance, and port components.
/// Validates that --port is not used alongside instance or port-in-server-string.
/// </summary>
public static class ServerEndpointResolver
{
    public sealed class ResolvedEndpoint
    {
        public string Host { get; set; } = string.Empty;
        public string? InstanceName { get; set; }
        public int? ExplicitPort { get; set; }
        public bool NeedsBrowserLookup => InstanceName != null && ExplicitPort == null;
    }

    /// <summary>
    /// Parses the server string and optional port parameter into a <see cref="ResolvedEndpoint"/>.
    /// </summary>
    /// <param name="server">The --server value (e.g., "host", "host\instance", "host,1434", "10.0.0.1,1433").</param>
    /// <param name="portOverride">The --port value, if specified.</param>
    /// <returns>A resolved endpoint with parsed components.</returns>
    /// <exception cref="ArgumentException">Thrown when the input is invalid or conflicting.</exception>
    public static ResolvedEndpoint Parse(string server, int? portOverride)
    {
        if (string.IsNullOrWhiteSpace(server))
        {
            throw new ArgumentException("Server name cannot be empty.");
        }

        var result = new ResolvedEndpoint();

        /* Check for comma-separated port: "host,port" */
        int commaIndex = server.IndexOf(',');
        int backslashIndex = server.IndexOf('\\');

        if (commaIndex >= 0 && backslashIndex >= 0)
        {
            throw new ArgumentException(
                $"Invalid server string '{server}': cannot use both instance name (\\) and port (,) syntax. " +
                "Use either 'server\\instance' or 'server,port', not both.");
        }

        if (commaIndex >= 0)
        {
            /* server,port format */
            result.Host = server[..commaIndex].Trim();
            string portStr = server[(commaIndex + 1)..].Trim();

            if (!int.TryParse(portStr, out int port) || port < 1 || port > 65535)
            {
                throw new ArgumentException(
                    $"Invalid port '{portStr}' in server string '{server}'. Port must be between 1 and 65535.");
            }

            result.ExplicitPort = port;

            if (portOverride.HasValue)
            {
                throw new ArgumentException(
                    $"Cannot use --port {portOverride.Value} when a port is already specified in the server string '{server}'. " +
                    "Use one or the other, not both.");
            }
        }
        else if (backslashIndex >= 0)
        {
            /* server\instance format */
            result.Host = server[..backslashIndex].Trim();
            result.InstanceName = server[(backslashIndex + 1)..].Trim();

            if (string.IsNullOrEmpty(result.InstanceName))
            {
                throw new ArgumentException(
                    $"Invalid server string '{server}': instance name is empty after backslash.");
            }

            if (portOverride.HasValue)
            {
                throw new ArgumentException(
                    $"Cannot use --port {portOverride.Value} with a named instance '{server}'. " +
                    "The port is resolved via the SQL Server Browser service. " +
                    "If the Browser service is unavailable, use 'server,port' syntax instead of 'server\\instance'.");
            }
        }
        else
        {
            /* Plain host — use port override or default 1433 */
            result.Host = server.Trim();
            result.ExplicitPort = portOverride ?? 1433;
        }

        if (string.IsNullOrEmpty(result.Host))
        {
            throw new ArgumentException("Server hostname cannot be empty.");
        }

        return result;
    }
}
