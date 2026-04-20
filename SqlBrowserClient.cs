using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SqlCertInspector;

/// <summary>
/// Queries the SQL Server Browser service (UDP 1434) to resolve a named
/// instance to its TCP port number.
/// </summary>
public static class SqlBrowserClient
{
    private const int BrowserPort = 1434;
    private const byte InstanceInfoRequest = 0x04;

    /// <summary>
    /// Resolves the TCP port for a named SQL Server instance via the Browser service.
    /// When the hostname resolves to multiple IPs, queries all of them in parallel.
    /// </summary>
    /// <param name="host">The hostname or IP address of the SQL Server.</param>
    /// <param name="instanceName">The instance name to resolve.</param>
    /// <param name="timeoutSeconds">UDP receive timeout in seconds.</param>
    /// <returns>The resolved TCP port number.</returns>
    /// <exception cref="SqlBrowserException">Thrown when the Browser service is unreachable or the instance is not found.</exception>
    public static int ResolveInstancePort(string host, string instanceName, int timeoutSeconds)
    {
        /* Resolve hostname to IP addresses for parallel Browser queries */
        IPAddress[] addresses;
        if (IPAddress.TryParse(host, out var directIp))
        {
            addresses = [directIp];
        }
        else
        {
            try
            {
                addresses = Dns.GetHostAddresses(host);
            }
            catch (SocketException ex)
            {
                throw new SqlBrowserException(
                    $"DNS resolution for '{host}' failed: {ex.Message}", ex);
            }

            if (addresses.Length == 0)
            {
                throw new SqlBrowserException(
                    $"DNS resolution for '{host}' returned no IP addresses.");
            }
        }

        if (addresses.Length == 1)
        {
            return QueryBrowser(addresses[0], host, instanceName, timeoutSeconds);
        }

        return QueryBrowserParallel(addresses, host, instanceName, timeoutSeconds);
    }

    /// <summary>
    /// Sends a Browser query to a single IP address.
    /// </summary>
    private static int QueryBrowser(IPAddress address, string host, string instanceName, int timeoutSeconds)
    {
        byte[] request = BuildInstanceRequest(instanceName);
        byte[] response;

        try
        {
            using var udpClient = new UdpClient();
            udpClient.Client.ReceiveTimeout = timeoutSeconds * 1000;
            udpClient.Connect(address, BrowserPort);
            udpClient.Send(request, request.Length);

            var remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);
            response = udpClient.Receive(ref remoteEndpoint);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
        {
            throw new SqlBrowserException(
                $"SQL Server Browser service on {host}:{BrowserPort} (UDP) did not respond " +
                $"for instance '{instanceName}'. This usually means the instance does not exist on this server.\n\n" +
                $"If the Browser service is not running, you will also see this timeout.\n\n" +
                $"To bypass instance resolution, specify the port directly:\n" +
                $"  sql-cert-inspector --server {host},<port>  OR  --server {host} --port <port>",
                ex);
        }
        catch (SocketException ex)
        {
            throw new SqlBrowserException(
                $"Could not connect to SQL Server Browser service on {host}:{BrowserPort} (UDP). " +
                $"The Browser service may not be running, or a firewall may be blocking UDP port {BrowserPort}. " +
                $"Socket error: {ex.SocketErrorCode} — {ex.Message}\n\n" +
                $"To bypass instance resolution, specify the port directly:\n" +
                $"  sql-cert-inspector --server {host},<port>  OR  --server {host} --port <port>",
                ex);
        }

        return ParseInstanceResponse(response, host, instanceName);
    }

    /// <summary>
    /// Sends Browser queries to all IP addresses in parallel, returns the first valid response.
    /// </summary>
    private static int QueryBrowserParallel(IPAddress[] addresses, string host, string instanceName, int timeoutSeconds)
    {
        byte[] request = BuildInstanceRequest(instanceName);
        var tasks = new Task<byte[]?>[addresses.Length];

        for (int i = 0; i < addresses.Length; i++)
        {
            var addr = addresses[i];
            tasks[i] = Task.Run(() =>
            {
                try
                {
                    using var udpClient = new UdpClient();
                    udpClient.Client.ReceiveTimeout = timeoutSeconds * 1000;
                    udpClient.Connect(addr, BrowserPort);
                    udpClient.Send(request, request.Length);

                    var remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);
                    return (byte[]?)udpClient.Receive(ref remoteEndpoint);
                }
                catch
                {
                    return null;
                }
            });
        }

        /* Wait for all tasks with an explicit timeout as a safety net.
           Individual tasks are bounded by ReceiveTimeout, but we add a ceiling
           to guard against platform-level hangs (security audit P2). */
        int waitMilliseconds = Math.Clamp((timeoutSeconds + 5) * 1000, 5000, 125000);
        Task.WaitAll(tasks, waitMilliseconds);

        /* Use the first successful response */
        foreach (var task in tasks)
        {
            if (task.Result != null)
            {
                return ParseInstanceResponse(task.Result, host, instanceName);
            }
        }

        var ipList = string.Join(", ", addresses.Select(a => a.ToString()));
        throw new SqlBrowserException(
            $"SQL Server Browser service did not respond on any of the resolved IPs ({ipList}) " +
            $"for instance '{instanceName}' on {host}.\n\n" +
            $"This usually means the instance does not exist, or the Browser service is not running.\n\n" +
            $"To bypass instance resolution, specify the port directly:\n" +
            $"  sql-cert-inspector --server {host},<port>  OR  --server {host} --port <port>");
    }

    private static byte[] BuildInstanceRequest(string instanceName)
    {
        byte[] instanceBytes = Encoding.ASCII.GetBytes(instanceName);
        byte[] request = new byte[1 + instanceBytes.Length + 1];
        request[0] = InstanceInfoRequest;
        Buffer.BlockCopy(instanceBytes, 0, request, 1, instanceBytes.Length);
        request[^1] = 0x00;
        return request;
    }

    private static int ParseInstanceResponse(byte[] response, string host, string instanceName)
    {
        if (response.Length < 3)
        {
            throw new SqlBrowserException(
                $"SQL Server Browser on {host} returned an empty or invalid response " +
                $"for instance '{instanceName}'. The instance may not exist on this server.");
        }

        /* Validate response type byte */
        const byte SvrResp = 0x05;
        if (response[0] != SvrResp)
        {
            throw new SqlBrowserException(
                $"SQL Server Browser on {host} returned unexpected response type 0x{response[0]:X2} " +
                $"(expected 0x05) for instance '{instanceName}'.");
        }

        /* Read declared data length (2-byte little-endian at bytes 1-2) and
           use the smaller of declared vs actual to avoid reading past valid data */
        int declaredLength = response[1] | (response[2] << 8);
        int availableLength = response.Length - 3;
        int dataLength = Math.Min(declaredLength, availableLength);
        if (dataLength <= 0)
        {
            throw new SqlBrowserException(
                $"SQL Server Browser on {host} returned an empty data section " +
                $"for instance '{instanceName}'. The instance may not exist on this server.");
        }

        string responseText = Encoding.ASCII.GetString(response, 3, dataLength);
        string[] parts = responseText.Split(';');

        for (int i = 0; i < parts.Length - 1; i++)
        {
            if (parts[i].Equals("tcp", StringComparison.OrdinalIgnoreCase) && i + 1 < parts.Length)
            {
                if (int.TryParse(parts[i + 1], out int port) && port > 0 && port <= 65535)
                {
                    return port;
                }
            }
        }

        throw new SqlBrowserException(
            $"SQL Server Browser on {host} responded for instance '{instanceName}', " +
            $"but no TCP port was found in the response. The instance may not be configured for TCP/IP connections.");
    }
}

public class SqlBrowserException : Exception
{
    public SqlBrowserException(string message) : base(message) { }
    public SqlBrowserException(string message, Exception inner) : base(message, inner) { }
}
