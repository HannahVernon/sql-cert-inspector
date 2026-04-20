namespace SqlCertInspector.Tests;

/// <summary>
/// Tests for the --output file feature: filename generation, JSON file writing, and exit codes.
/// </summary>
public class OutputFileTests
{
    [Theory]
    [InlineData(@"server\instance", "server-instance.json")]
    [InlineData("server,1433", "server,1433.json")]
    [InlineData("myserver", "myserver.json")]
    [InlineData(@"host\inst:extra", "host-inst-extra.json")]
    [InlineData("a<b>c", "a-b-c.json")]
    [InlineData("server|name", "server-name.json")]
    [InlineData(@"host\inst*bad?name", "host-inst-bad-name.json")]
    [InlineData("a\"b", "a-b.json")]
    [InlineData("simple", "simple.json")]
    public void GenerateOutputFileName_ReplacesIllegalChars(string serverName, string expected)
    {
        string result = OutputFileHelper.GenerateOutputFileName(serverName);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(@"\\\", "output.json")]
    [InlineData("***", "output.json")]
    [InlineData("", "output.json")]
    [InlineData("   ", "output.json")]
    [InlineData("..", "output.json")]
    [InlineData("..\\..\\etc", "etc.json")]
    [InlineData("a..b", "a.b.json")]
    [InlineData("....", "output.json")]
    public void GenerateOutputFileName_FallsBackToDefault(string serverName, string expected)
    {
        string result = OutputFileHelper.GenerateOutputFileName(serverName);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void CommandLineOptions_OutputFileSpecified_DefaultsFalse()
    {
        var options = new CommandLineOptions();
        Assert.False(options.OutputFileSpecified);
        Assert.Null(options.OutputFile);
    }

    [Fact]
    public void ExitCodes_FileWriteError_Is6()
    {
        Assert.Equal(6, ExitCodes.FileWriteError);
    }

    [Fact]
    public void JsonReporter_GenerateJson_ReturnsValidJson()
    {
        var info = new ConnectionSecurityInfo
        {
            ServerName = "testserver",
            ResolvedHost = "testserver.example.com",
            ResolvedPort = 1433,
            IsEncrypted = false,
            EncryptionMode = "OFF"
        };

        string json = JsonReporter.GenerateJson(info);

        Assert.False(string.IsNullOrWhiteSpace(json));
        Assert.Contains("\"serverName\"", json);
        Assert.Contains("testserver", json);

        /* Verify it parses as valid JSON */
        var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.NotNull(doc);
    }

    [Fact]
    public void JsonReporter_GenerateJson_IncludesMetaSection()
    {
        var info = new ConnectionSecurityInfo
        {
            ServerName = "testserver\\INST",
            ResolvedHost = "testserver.example.com",
            ResolvedPort = 1433,
            IsEncrypted = false,
            EncryptionMode = "OFF"
        };

        string json = JsonReporter.GenerateJson(info);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("meta", out var meta));
        Assert.True(meta.TryGetProperty("toolVersion", out var version));
        Assert.False(string.IsNullOrWhiteSpace(version.GetString()));
        Assert.True(meta.TryGetProperty("timestamp", out _));
        Assert.Equal("testserver\\INST", meta.GetProperty("target").GetString());
    }
}
