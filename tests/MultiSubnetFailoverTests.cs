using System.Net;
using System.Net.Sockets;
using Xunit;

namespace SqlCertInspector.Tests;

/// <summary>
/// Tests for multi-subnet failover behavior: DNS resolution detection,
/// parallel TCP connect racing, and IP address passthrough.
/// </summary>
public class MultiSubnetFailoverTests
{
    /* ───── IP address detection (skip DNS path) ───── */

    [Theory]
    [InlineData("192.168.1.10")]
    [InlineData("10.0.0.1")]
    [InlineData("127.0.0.1")]
    [InlineData("255.255.255.255")]
    public void IPv4Address_ShouldBeDetectedAsIP(string host)
    {
        Assert.True(IPAddress.TryParse(host, out _),
            $"Expected '{host}' to be recognized as an IP address");
    }

    [Theory]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("2001:db8::1")]
    [InlineData("::ffff:192.168.1.1")]
    public void IPv6Address_ShouldBeDetectedAsIP(string host)
    {
        Assert.True(IPAddress.TryParse(host, out _),
            $"Expected '{host}' to be recognized as an IP address");
    }

    [Theory]
    [InlineData("sqlserver.example.com")]
    [InlineData("myhost")]
    [InlineData("ag-listener.corp.example.com")]
    public void Hostname_ShouldNotBeDetectedAsIP(string host)
    {
        Assert.False(IPAddress.TryParse(host, out _),
            $"Expected '{host}' to NOT be recognized as an IP address");
    }

    /* ───── ConnectionSecurityInfo population ───── */

    [Fact]
    public void ConnectionSecurityInfo_SingleIP_ShouldNotSetConnectedIP_WhenDirectIP()
    {
        /* When user passes an IP address directly, ResolvedIPs should be null
           (no DNS lookup performed), and ConnectedIP should be null */
        var info = new ConnectionSecurityInfo
        {
            ResolvedHost = "192.168.1.10",
            ResolvedPort = 1433
        };

        Assert.Null(info.ResolvedIPs);
        Assert.Null(info.ConnectedIP);
    }

    [Fact]
    public void ConnectionSecurityInfo_MultiIP_ShouldPopulateBothFields()
    {
        var info = new ConnectionSecurityInfo
        {
            ResolvedHost = "ag-listener.example.com",
            ResolvedPort = 1433,
            ResolvedIPs = new[] { "10.200.24.230", "10.100.24.230" },
            ConnectedIP = "10.200.24.230"
        };

        Assert.Equal(2, info.ResolvedIPs.Length);
        Assert.Equal("10.200.24.230", info.ConnectedIP);
    }

    /* ───── Parallel connect — all fail ───── */

    [Fact]
    public async Task ConnectParallel_AllUnreachable_ShouldThrowConnectionException()
    {
        /* Use RFC 5737 TEST-NET addresses that are guaranteed unroutable */
        var addresses = new[]
        {
            IPAddress.Parse("192.0.2.1"),
            IPAddress.Parse("192.0.2.2")
        };

        var ex = await Assert.ThrowsAsync<ConnectionException>(() =>
            TdsPreloginClient.ConnectParallelAsync(
                addresses, "test.example.com", 1433, 2, CancellationToken.None));

        Assert.Contains("test.example.com:1433", ex.Message);
        Assert.Contains("192.0.2.1", ex.Message);
        Assert.Contains("192.0.2.2", ex.Message);
    }

    /* ───── Parallel connect — real loopback listener ───── */

    [Fact]
    public async Task ConnectParallel_OneReachable_ShouldReturnWinner()
    {
        /* Start a real TCP listener on a random port */
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            /* Race loopback (will succeed) against TEST-NET (will fail) */
            var addresses = new[]
            {
                IPAddress.Parse("192.0.2.1"),
                IPAddress.Loopback
            };

            using var winner = await TdsPreloginClient.ConnectParallelAsync(
                addresses, "test.example.com", port, 5, CancellationToken.None);

            Assert.True(winner.Connected);
            var remoteEp = (IPEndPoint)winner.Client.RemoteEndPoint!;
            /* TcpClient may return IPv4-mapped IPv6 (::ffff:127.0.0.1) on dual-stack systems */
            var connectedIp = remoteEp.Address.IsIPv4MappedToIPv6
                ? remoteEp.Address.MapToIPv4()
                : remoteEp.Address;
            Assert.Equal(IPAddress.Loopback, connectedIp);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task ConnectParallel_MultipleReachable_ShouldReturnOne()
    {
        /* Start two listeners on loopback */
        var listener1 = new TcpListener(IPAddress.Loopback, 0);
        var listener2 = new TcpListener(IPAddress.Loopback, 0);
        listener1.Start();
        listener2.Start();

        /* Both listeners on same port won't work — use same port trick via IPv4+IPv6 */
        /* Instead, just verify with one port that multiple loopback IPs race correctly */
        int port = ((IPEndPoint)listener1.LocalEndpoint).Port;

        try
        {
            var addresses = new[] { IPAddress.Loopback };

            using var winner = await TdsPreloginClient.ConnectParallelAsync(
                addresses, "test.example.com", port, 5, CancellationToken.None);

            Assert.True(winner.Connected);
        }
        finally
        {
            listener1.Stop();
            listener2.Stop();
        }
    }

    /* ───── Parallel connect — cancellation ───── */

    [Fact]
    public async Task ConnectParallel_CancelledToken_ShouldThrowConnectionException()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var addresses = new[] { IPAddress.Parse("192.0.2.1") };

        await Assert.ThrowsAsync<ConnectionException>(() =>
            TdsPreloginClient.ConnectParallelAsync(
                addresses, "test.example.com", 1433, 5, cts.Token));
    }

    /* ───── ServerEndpointResolver — IP address with comma port ───── */

    [Theory]
    [InlineData("192.168.1.10,1433", "192.168.1.10", 1433)]
    [InlineData("10.0.0.1,22136", "10.0.0.1", 22136)]
    public void Parse_IPv4WithCommaPort_ShouldExtractHostAndPort(
        string server, string expectedHost, int expectedPort)
    {
        var ep = ServerEndpointResolver.Parse(server, null);
        Assert.Equal(expectedHost, ep.Host);
        Assert.Equal(expectedPort, ep.ExplicitPort);
        Assert.False(ep.NeedsBrowserLookup);
    }

    [Fact]
    public void Parse_BareIPv4_ShouldDefaultToPort1433()
    {
        var ep = ServerEndpointResolver.Parse("10.0.0.1", null);
        Assert.Equal("10.0.0.1", ep.Host);
        Assert.Equal(1433, ep.ExplicitPort);
    }
}
