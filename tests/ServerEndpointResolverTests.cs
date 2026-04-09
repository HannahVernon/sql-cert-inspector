using SqlCertInspector;

namespace SqlCertInspectorTests;

public class ServerEndpointResolverTests
{
    [Fact]
    public void Parse_PlainHost_DefaultsToPort1433()
    {
        var result = ServerEndpointResolver.Parse("myserver", null);

        Assert.Equal("myserver", result.Host);
        Assert.Null(result.InstanceName);
        Assert.Equal(1433, result.ExplicitPort);
        Assert.False(result.NeedsBrowserLookup);
    }

    [Fact]
    public void Parse_PlainHost_WithPortOverride()
    {
        var result = ServerEndpointResolver.Parse("myserver", 5000);

        Assert.Equal("myserver", result.Host);
        Assert.Null(result.InstanceName);
        Assert.Equal(5000, result.ExplicitPort);
    }

    [Fact]
    public void Parse_HostCommaPort()
    {
        var result = ServerEndpointResolver.Parse("myserver,1434", null);

        Assert.Equal("myserver", result.Host);
        Assert.Null(result.InstanceName);
        Assert.Equal(1434, result.ExplicitPort);
    }

    [Fact]
    public void Parse_HostBackslashInstance()
    {
        var result = ServerEndpointResolver.Parse(@"myserver\SQLEXPRESS", null);

        Assert.Equal("myserver", result.Host);
        Assert.Equal("SQLEXPRESS", result.InstanceName);
        Assert.Null(result.ExplicitPort);
        Assert.True(result.NeedsBrowserLookup);
    }

    [Fact]
    public void Parse_FqdnWithInstance()
    {
        var result = ServerEndpointResolver.Parse(@"db.corp.example.com\PROD", null);

        Assert.Equal("db.corp.example.com", result.Host);
        Assert.Equal("PROD", result.InstanceName);
    }

    [Fact]
    public void Parse_IpAddressCommaPort()
    {
        var result = ServerEndpointResolver.Parse("192.168.1.10,22136", null);

        Assert.Equal("192.168.1.10", result.Host);
        Assert.Equal(22136, result.ExplicitPort);
    }

    [Fact]
    public void Parse_HostCommaPort_WithPortOverride_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => ServerEndpointResolver.Parse("myserver,1434", 5000));

        Assert.Contains("Cannot use --port", ex.Message);
    }

    [Fact]
    public void Parse_HostInstance_WithPortOverride_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => ServerEndpointResolver.Parse(@"myserver\INST", 5000));

        Assert.Contains("Cannot use --port", ex.Message);
    }

    [Fact]
    public void Parse_InstanceAndPort_InServerString_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => ServerEndpointResolver.Parse(@"myserver\INST,1434", null));

        Assert.Contains("cannot use both", ex.Message);
    }

    [Fact]
    public void Parse_EmptyServer_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => ServerEndpointResolver.Parse("", null));
    }

    [Fact]
    public void Parse_WhitespaceServer_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => ServerEndpointResolver.Parse("   ", null));
    }

    [Fact]
    public void Parse_EmptyInstanceName_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => ServerEndpointResolver.Parse(@"myserver\", null));

        Assert.Contains("instance name is empty", ex.Message);
    }

    [Fact]
    public void Parse_InvalidPort_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => ServerEndpointResolver.Parse("myserver,99999", null));

        Assert.Contains("Invalid port", ex.Message);
    }

    [Fact]
    public void Parse_NonNumericPort_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => ServerEndpointResolver.Parse("myserver,abc", null));

        Assert.Contains("Invalid port", ex.Message);
    }

    [Fact]
    public void Parse_ZeroPort_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => ServerEndpointResolver.Parse("myserver,0", null));
    }

    [Fact]
    public void Parse_TrimWhitespace()
    {
        var result = ServerEndpointResolver.Parse("  myserver , 1434 ", null);

        Assert.Equal("myserver", result.Host);
        Assert.Equal(1434, result.ExplicitPort);
    }
}
