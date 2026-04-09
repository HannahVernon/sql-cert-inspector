using SqlCertInspector;

namespace SqlCertInspectorTests;

public class CertificateAnalyzerTests
{
    [Theory]
    [InlineData("CN=myserver.example.com, O=Contoso", "myserver.example.com")]
    [InlineData("CN=myserver, O=Contoso", "myserver")]
    [InlineData("O=Contoso, CN=myserver.example.com", "myserver.example.com")]
    [InlineData("cn=case-insensitive.com, O=Test", "case-insensitive.com")]
    public void ExtractCN_ParsesCorrectly(string subject, string expectedCn)
    {
        Assert.Equal(expectedCn, CertificateAnalyzer.ExtractCN(subject));
    }

    [Theory]
    [InlineData("O=NoCnHere")]
    [InlineData("")]
    public void ExtractCN_ReturnsEmpty_WhenNoCN(string subject)
    {
        Assert.Equal(string.Empty, CertificateAnalyzer.ExtractCN(subject));
    }

    [Theory]
    [InlineData("myserver.example.com", "myserver.example.com", true)]
    [InlineData("MYSERVER.EXAMPLE.COM", "myserver.example.com", true)]
    [InlineData("other.example.com", "myserver.example.com", false)]
    [InlineData("foo.example.com", "*.example.com", true)]
    [InlineData("bar.example.com", "*.example.com", true)]
    [InlineData("example.com", "*.example.com", false)]
    [InlineData("sub.foo.example.com", "*.example.com", false)]
    [InlineData("myserver", "myserver", true)]
    public void MatchesHostname_WorksCorrectly(string host, string pattern, bool expected)
    {
        Assert.Equal(expected, CertificateAnalyzer.MatchesHostname(host, pattern));
    }

    [Fact]
    public void HostnameMatchesCertificate_MatchesCN()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=db.corp.example.com, O=Contoso"
        };

        Assert.True(CertificateAnalyzer.HostnameMatchesCertificate("db.corp.example.com", info));
        Assert.False(CertificateAnalyzer.HostnameMatchesCertificate("other.corp.example.com", info));
    }

    [Fact]
    public void HostnameMatchesCertificate_MatchesSAN()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=primary.example.com, O=Contoso",
            SubjectAlternativeNames = new List<string>
            {
                "DNS:primary.example.com",
                "DNS:secondary.example.com",
                "DNS:ag-listener.example.com"
            }
        };

        Assert.True(CertificateAnalyzer.HostnameMatchesCertificate("primary.example.com", info));
        Assert.True(CertificateAnalyzer.HostnameMatchesCertificate("secondary.example.com", info));
        Assert.True(CertificateAnalyzer.HostnameMatchesCertificate("ag-listener.example.com", info));
        Assert.False(CertificateAnalyzer.HostnameMatchesCertificate("unknown.example.com", info));
    }

    [Fact]
    public void HostnameMatchesCertificate_MatchesIpSan()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=db.example.com",
            SubjectAlternativeNames = new List<string>
            {
                "DNS:db.example.com",
                "IP:10.0.0.5"
            }
        };

        Assert.True(CertificateAnalyzer.HostnameMatchesCertificate("10.0.0.5", info));
        Assert.False(CertificateAnalyzer.HostnameMatchesCertificate("10.0.0.6", info));
    }

    [Fact]
    public void HostnameMatchesCertificate_WildcardSAN()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=*.example.com",
            SubjectAlternativeNames = new List<string>
            {
                "DNS:*.example.com"
            }
        };

        Assert.True(CertificateAnalyzer.HostnameMatchesCertificate("db.example.com", info));
        Assert.True(CertificateAnalyzer.HostnameMatchesCertificate("web.example.com", info));
        Assert.False(CertificateAnalyzer.HostnameMatchesCertificate("sub.db.example.com", info));
    }

    [Fact]
    public void HealthCheck_ExpiredCertificate()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=expired.example.com",
            ValidFrom = DateTime.UtcNow.AddYears(-2),
            ValidTo = DateTime.UtcNow.AddDays(-10),
            DaysUntilExpiry = -10,
            KeyAlgorithm = "RSA",
            KeySizeBits = 2048,
            SignatureAlgorithm = "sha256RSA"
        };

        CertificateAnalyzer.RunHealthChecks(info, "expired.example.com");

        Assert.Contains(info.Warnings, w =>
            w.Severity == WarningSeverity.Error && w.Message.Contains("EXPIRED"));
    }

    [Fact]
    public void HealthCheck_ExpiringWithin30Days()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=expiring.example.com",
            ValidFrom = DateTime.UtcNow.AddYears(-1),
            ValidTo = DateTime.UtcNow.AddDays(15),
            DaysUntilExpiry = 15,
            KeyAlgorithm = "RSA",
            KeySizeBits = 2048,
            SignatureAlgorithm = "sha256RSA"
        };

        CertificateAnalyzer.RunHealthChecks(info, "expiring.example.com");

        Assert.Contains(info.Warnings, w =>
            w.Severity == WarningSeverity.Warning && w.Message.Contains("expires in"));
    }

    [Fact]
    public void HealthCheck_SelfSigned()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=selfsigned.example.com",
            Issuer = "CN=selfsigned.example.com",
            IsSelfSigned = true,
            ValidFrom = DateTime.UtcNow.AddYears(-1),
            ValidTo = DateTime.UtcNow.AddYears(1),
            DaysUntilExpiry = 365,
            KeyAlgorithm = "RSA",
            KeySizeBits = 2048,
            SignatureAlgorithm = "sha256RSA"
        };

        CertificateAnalyzer.RunHealthChecks(info, "selfsigned.example.com");

        Assert.Contains(info.Warnings, w =>
            w.Severity == WarningSeverity.Warning && w.Message.Contains("self-signed"));
    }

    [Fact]
    public void HealthCheck_HostnameMismatch()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=primary.example.com",
            ValidFrom = DateTime.UtcNow.AddYears(-1),
            ValidTo = DateTime.UtcNow.AddYears(1),
            DaysUntilExpiry = 365,
            KeyAlgorithm = "RSA",
            KeySizeBits = 2048,
            SignatureAlgorithm = "sha256RSA"
        };

        CertificateAnalyzer.RunHealthChecks(info, "secondary.example.com");

        Assert.Contains(info.Warnings, w =>
            w.Severity == WarningSeverity.Warning && w.Message.Contains("does not match"));
    }

    [Fact]
    public void HealthCheck_WeakRsaKey()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=weak.example.com",
            ValidFrom = DateTime.UtcNow.AddYears(-1),
            ValidTo = DateTime.UtcNow.AddYears(1),
            DaysUntilExpiry = 365,
            KeyAlgorithm = "RSA",
            KeySizeBits = 1024,
            SignatureAlgorithm = "sha256RSA"
        };

        CertificateAnalyzer.RunHealthChecks(info, "weak.example.com");

        Assert.Contains(info.Warnings, w =>
            w.Severity == WarningSeverity.Warning && w.Message.Contains("Weak RSA"));
    }

    [Fact]
    public void HealthCheck_Sha1Signature()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=sha1.example.com",
            ValidFrom = DateTime.UtcNow.AddYears(-1),
            ValidTo = DateTime.UtcNow.AddYears(1),
            DaysUntilExpiry = 365,
            KeyAlgorithm = "RSA",
            KeySizeBits = 2048,
            SignatureAlgorithm = "sha1RSA"
        };

        CertificateAnalyzer.RunHealthChecks(info, "sha1.example.com");

        Assert.Contains(info.Warnings, w =>
            w.Severity == WarningSeverity.Warning && w.Message.Contains("SHA-1"));
    }

    [Fact]
    public void HealthCheck_Md5Signature()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=md5.example.com",
            ValidFrom = DateTime.UtcNow.AddYears(-1),
            ValidTo = DateTime.UtcNow.AddYears(1),
            DaysUntilExpiry = 365,
            KeyAlgorithm = "RSA",
            KeySizeBits = 2048,
            SignatureAlgorithm = "md5RSA"
        };

        CertificateAnalyzer.RunHealthChecks(info, "md5.example.com");

        Assert.Contains(info.Warnings, w =>
            w.Severity == WarningSeverity.Error && w.Message.Contains("MD5"));
    }

    [Fact]
    public void HealthCheck_ValidCert_NoWarnings()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=valid.example.com",
            Issuer = "CN=CA Root, O=Contoso",
            ValidFrom = DateTime.UtcNow.AddYears(-1),
            ValidTo = DateTime.UtcNow.AddYears(1),
            DaysUntilExpiry = 365,
            KeyAlgorithm = "RSA",
            KeySizeBits = 4096,
            SignatureAlgorithm = "sha256RSA",
            SubjectAlternativeNames = new List<string> { "DNS:valid.example.com" }
        };

        CertificateAnalyzer.RunHealthChecks(info, "valid.example.com");

        Assert.Empty(info.Warnings);
    }

    [Fact]
    public void HealthCheck_NotYetValid()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=future.example.com",
            ValidFrom = DateTime.UtcNow.AddDays(30),
            ValidTo = DateTime.UtcNow.AddYears(1),
            DaysUntilExpiry = 365,
            KeyAlgorithm = "RSA",
            KeySizeBits = 2048,
            SignatureAlgorithm = "sha256RSA"
        };

        CertificateAnalyzer.RunHealthChecks(info, "future.example.com");

        Assert.Contains(info.Warnings, w =>
            w.Severity == WarningSeverity.Warning && w.Message.Contains("not yet valid"));
    }
}
