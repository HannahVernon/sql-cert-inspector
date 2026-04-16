using SqlCertInspector;

namespace SqlCertInspector.Tests;

/// <summary>
/// Tests for TDS protocol version enum and display strings.
/// </summary>
public class TdsProtocolVersionTests
{
    [Fact]
    public void Tds7_DisplayString_Returns7x()
    {
        Assert.Equal("7.x", TdsProtocolVersion.Tds7.ToDisplayString());
    }

    [Fact]
    public void Tds8Strict_DisplayString_Returns80Strict()
    {
        Assert.Equal("8.0 (Strict)", TdsProtocolVersion.Tds8Strict.ToDisplayString());
    }

    [Fact]
    public void Default_TdsProtocol_IsTds7()
    {
        var info = new ConnectionSecurityInfo();
        Assert.Equal(TdsProtocolVersion.Tds7, info.TdsProtocol);
    }

    [Fact]
    public void UsedFallback_DefaultsFalse()
    {
        var info = new ConnectionSecurityInfo();
        Assert.False(info.UsedFallback);
    }
}

/// <summary>
/// Tests for the ProtocolMismatchException type.
/// </summary>
public class ProtocolMismatchExceptionTests
{
    [Fact]
    public void Stores_AttemptedProtocol_Tds7()
    {
        var ex = new ProtocolMismatchException(TdsProtocolVersion.Tds7, "test");
        Assert.Equal(TdsProtocolVersion.Tds7, ex.AttemptedProtocol);
        Assert.Equal("test", ex.Message);
    }

    [Fact]
    public void Stores_AttemptedProtocol_Tds8()
    {
        var inner = new Exception("inner");
        var ex = new ProtocolMismatchException(TdsProtocolVersion.Tds8Strict, "test8", inner);
        Assert.Equal(TdsProtocolVersion.Tds8Strict, ex.AttemptedProtocol);
        Assert.Equal("test8", ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void IsConnectionException()
    {
        var ex = new ProtocolMismatchException(TdsProtocolVersion.Tds7, "test");
        Assert.IsType<ProtocolMismatchException>(ex);
        Assert.IsAssignableFrom<ConnectionException>(ex);
    }
}

/// <summary>
/// Tests for the --encrypt-strict CLI option model.
/// </summary>
public class EncryptStrictOptionTests
{
    [Fact]
    public void EncryptStrict_DefaultsFalse()
    {
        var options = new CommandLineOptions();
        Assert.False(options.EncryptStrict);
    }

    [Fact]
    public void EncryptStrict_CanBeSetTrue()
    {
        var options = new CommandLineOptions { EncryptStrict = true };
        Assert.True(options.EncryptStrict);
    }
}

/// <summary>
/// Tests for JSON output shape with TDS protocol fields.
/// </summary>
public class TdsProtocolJsonTests
{
    [Fact]
    public void JsonOutput_IncludesTdsProtocol()
    {
        var info = new ConnectionSecurityInfo
        {
            ServerName = "testserver",
            ResolvedHost = "testserver",
            ResolvedPort = 1433,
            IsEncrypted = false,
            TdsProtocol = TdsProtocolVersion.Tds8Strict,
            EncryptionMode = "STRICT"
        };

        var writer = new System.IO.StringWriter();
        Console.SetOut(writer);

        try
        {
            JsonReporter.Report(info);
        }
        finally
        {
            Console.SetOut(new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
        }

        string json = writer.ToString();
        Assert.Contains("\"tdsProtocol\": \"8.0 (Strict)\"", json);
    }

    [Fact]
    public void JsonOutput_OmitsUsedFallback_WhenFalse()
    {
        var info = new ConnectionSecurityInfo
        {
            ServerName = "testserver",
            ResolvedHost = "testserver",
            ResolvedPort = 1433,
            IsEncrypted = false,
            UsedFallback = false
        };

        var writer = new System.IO.StringWriter();
        Console.SetOut(writer);

        try
        {
            JsonReporter.Report(info);
        }
        finally
        {
            Console.SetOut(new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
        }

        string json = writer.ToString();
        Assert.DoesNotContain("usedFallback", json);
    }

    [Fact]
    public void JsonOutput_IncludesUsedFallback_WhenTrue()
    {
        var info = new ConnectionSecurityInfo
        {
            ServerName = "testserver",
            ResolvedHost = "testserver",
            ResolvedPort = 1433,
            IsEncrypted = false,
            UsedFallback = true,
            TdsProtocol = TdsProtocolVersion.Tds7
        };

        var writer = new System.IO.StringWriter();
        Console.SetOut(writer);

        try
        {
            JsonReporter.Report(info);
        }
        finally
        {
            Console.SetOut(new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
        }

        string json = writer.ToString();
        Assert.Contains("\"usedFallback\": true", json);
    }
}
