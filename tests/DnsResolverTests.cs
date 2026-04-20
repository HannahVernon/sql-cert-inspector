using SqlCertInspector;

namespace SqlCertInspectorTests;

/// <summary>
/// Tests for DnsResolver P/Invoke wrapper and DNS-related behavior changes.
/// </summary>
public class DnsResolverTests
{
    [Fact]
    public void ResolveHost_IpAddress_SkipsDns()
    {
        var result = DnsResolver.ResolveHost("192.168.1.1");

        Assert.True(result.SkippedDns);
        Assert.Empty(result.Addresses);
        Assert.Empty(result.RecordTypes);
        Assert.Empty(result.CnameChain);
        Assert.Null(result.CanonicalName);
        Assert.False(result.WasSuffixExpanded);
    }

    [Fact]
    public void ResolveHost_IPv6Address_SkipsDns()
    {
        var result = DnsResolver.ResolveHost("::1");

        Assert.True(result.SkippedDns);
        Assert.Empty(result.Addresses);
    }

    [Fact]
    public void ResolveHost_Localhost_ReturnsARecords()
    {
        var result = DnsResolver.ResolveHost("localhost");

        Assert.False(result.SkippedDns);
        Assert.NotEmpty(result.Addresses);
        Assert.Null(result.CanonicalName);
    }

    [Fact]
    public void DnsResult_CanonicalName_NullWhenNoCname()
    {
        var result = new DnsResult();
        Assert.Null(result.CanonicalName);
    }

    [Fact]
    public void DnsResult_CanonicalName_ReturnsLastInChain()
    {
        var result = new DnsResult();
        result.CnameChain.Add("intermediate.example.com");
        result.CnameChain.Add("final.example.com");

        Assert.Equal("final.example.com", result.CanonicalName);
    }

    [Fact]
    public void DnsResult_RecordTypes_ReflectsQueryResults()
    {
        var result = new DnsResult();
        result.RecordTypes.Add("A");
        result.RecordTypes.Add("CNAME");

        Assert.Contains("A", result.RecordTypes);
        Assert.Contains("CNAME", result.RecordTypes);
        Assert.DoesNotContain("AAAA", result.RecordTypes);
    }
}

/// <summary>
/// Tests for certificate hostname matching with resolved FQDN.
/// </summary>
public class CertificateFqdnMatchingTests
{
    [Fact]
    public void HealthCheck_ShortName_NoWarningWhenFqdnMatchesSans()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=myserver.corp.example.com",
            SubjectAlternativeNames = { "DNS:myserver.corp.example.com" },
            ValidFrom = DateTime.UtcNow.AddDays(-30),
            ValidTo = DateTime.UtcNow.AddDays(335),
            KeyAlgorithm = "RSA",
            KeySizeBits = 4096,
            SignatureAlgorithm = "sha256RSA"
        };

        /* Short name "myserver" doesn't match SANs, but resolved FQDN does */
        CertificateAnalyzer.RunHealthChecks(info, "myserver", "myserver.corp.example.com");

        Assert.DoesNotContain(info.Warnings, w => w.Message.Contains("does not match"));
    }

    [Fact]
    public void HealthCheck_ShortName_WarningWhenFqdnAlsoDoesNotMatch()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=otherserver.corp.example.com",
            SubjectAlternativeNames = { "DNS:otherserver.corp.example.com" },
            ValidFrom = DateTime.UtcNow.AddDays(-30),
            ValidTo = DateTime.UtcNow.AddDays(335),
            KeyAlgorithm = "RSA",
            KeySizeBits = 4096,
            SignatureAlgorithm = "sha256RSA"
        };

        /* Neither short name nor FQDN match */
        CertificateAnalyzer.RunHealthChecks(info, "myserver", "myserver.corp.example.com");

        Assert.Contains(info.Warnings, w => w.Message.Contains("does not match"));
    }

    [Fact]
    public void HealthCheck_NullFqdn_BehavesAsBeforeWhenMatches()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=myserver.corp.example.com",
            SubjectAlternativeNames = { "DNS:myserver.corp.example.com" },
            ValidFrom = DateTime.UtcNow.AddDays(-30),
            ValidTo = DateTime.UtcNow.AddDays(335),
            KeyAlgorithm = "RSA",
            KeySizeBits = 4096,
            SignatureAlgorithm = "sha256RSA"
        };

        CertificateAnalyzer.RunHealthChecks(info, "myserver.corp.example.com", null);

        Assert.DoesNotContain(info.Warnings, w => w.Message.Contains("does not match"));
    }

    [Fact]
    public void HealthCheck_NullFqdn_WarnsOnMismatch()
    {
        var info = new CertificateInfo
        {
            Subject = "CN=otherserver.corp.example.com",
            SubjectAlternativeNames = { "DNS:otherserver.corp.example.com" },
            ValidFrom = DateTime.UtcNow.AddDays(-30),
            ValidTo = DateTime.UtcNow.AddDays(335),
            KeyAlgorithm = "RSA",
            KeySizeBits = 4096,
            SignatureAlgorithm = "sha256RSA"
        };

        CertificateAnalyzer.RunHealthChecks(info, "myserver.corp.example.com", null);

        Assert.Contains(info.Warnings, w => w.Message.Contains("does not match"));
    }
}

/// <summary>
/// Tests for Kerberos SPN generation with FQDN from short name input.
/// </summary>
public class SpnFqdnTests
{
    [Fact]
    public void BuildExpectedSpns_WithFqdn_GeneratesBothFqdnAndShortVariants()
    {
        /* When a short name resolves to an FQDN, Inspect passes the FQDN to BuildExpectedSpns */
        var spns = KerberosInspector.BuildExpectedSpns(
            "myserver.corp.example.com", 1433, "INST1");

        /* Named instances should have FQDN + Port, FQDN + Instance, Short + Port, Short + Instance — no base SPNs */
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/myserver.corp.example.com:1433" && s.Label == "FQDN + Port");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/myserver.corp.example.com:INST1" && s.Label == "FQDN + Instance");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/myserver:1433" && s.Label == "Short + Port");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/myserver:INST1" && s.Label == "Short + Instance");
        Assert.DoesNotContain(spns, s => s.Label.Contains("base"));
    }

    [Fact]
    public void BuildExpectedSpns_ShortNameOnly_NoShortVariants()
    {
        /* When input IS the short name (no dots), hasShortName is false */
        var spns = KerberosInspector.BuildExpectedSpns("myserver", 1433, null);

        Assert.Single(spns);
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/myserver:1433");
        /* No "Short +" labels since hostname IS the short name */
        Assert.DoesNotContain(spns, s => s.Label.StartsWith("Short"));
        /* No base SPNs by default */
        Assert.DoesNotContain(spns, s => s.Label.Contains("base"));
    }
}

/// <summary>
/// Tests for Kerberos health check CNAME warning behavior.
/// </summary>
public class KerberosCnameTests
{
    [Fact]
    public void RunHealthChecks_TrueCname_EmitsWarning()
    {
        var diag = new KerberosDiagnostics
        {
            RequestedHostname = "alias.example.com",
            CnameTarget = "real-host.example.com",
            ExpectedSpns = new List<SpnExpectation>
            {
                MakeSpn("FQDN + Port", "MSSQLSvc/alias.example.com:1433", found: true, account: "svc-sql"),
                MakeSpn("FQDN (base)", "MSSQLSvc/alias.example.com", found: true, account: "svc-sql")
            }
        };

        KerberosInspector.RunHealthChecks(diag, 1433, isNamedInstance: false);

        Assert.Contains(diag.Warnings, w =>
            w.Severity == WarningSeverity.Warning && w.Message.Contains("CNAME"));
    }

    [Fact]
    public void RunHealthChecks_SuffixExpansion_NoCnameWarning()
    {
        /* Short name resolved via suffix expansion — NOT a CNAME */
        var diag = new KerberosDiagnostics
        {
            RequestedHostname = "myserver",
            ResolvedFqdn = "myserver.corp.example.com",
            CnameTarget = null, /* No CNAME record in DNS response */
            DnsRecordTypes = new List<string> { "A" },
            ExpectedSpns = new List<SpnExpectation>
            {
                MakeSpn("FQDN + Port", "MSSQLSvc/myserver.corp.example.com:1433", found: true, account: "svc-sql"),
                MakeSpn("FQDN (base)", "MSSQLSvc/myserver.corp.example.com", found: true, account: "svc-sql")
            }
        };

        KerberosInspector.RunHealthChecks(diag, 1433, isNamedInstance: false);

        Assert.DoesNotContain(diag.Warnings, w => w.Message.Contains("CNAME"));
    }

    [Fact]
    public void RunHealthChecks_FqdnInput_NoCnameWarning()
    {
        var diag = new KerberosDiagnostics
        {
            RequestedHostname = "myserver.corp.example.com",
            CnameTarget = null,
            DnsRecordTypes = new List<string> { "A" },
            ExpectedSpns = new List<SpnExpectation>
            {
                MakeSpn("FQDN + Port", "MSSQLSvc/myserver.corp.example.com:1433", found: true, account: "svc-sql"),
                MakeSpn("FQDN (base)", "MSSQLSvc/myserver.corp.example.com", found: true, account: "svc-sql")
            }
        };

        KerberosInspector.RunHealthChecks(diag, 1433, isNamedInstance: false);

        Assert.DoesNotContain(diag.Warnings, w => w.Message.Contains("CNAME"));
    }

    private static SpnExpectation MakeSpn(string label, string spn, bool found, string? account = null) =>
        new()
        {
            Label = label,
            Spn = spn,
            Result = new SpnLookupResult { Found = found, AccountName = account, AccountType = found ? "User" : null }
        };
}
