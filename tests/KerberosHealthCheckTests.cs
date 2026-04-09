using SqlCertInspector;

namespace SqlCertInspectorTests;

public class KerberosHealthCheckTests
{
    [Fact]
    public void NoSpnsFound_EmitsError()
    {
        var diag = new KerberosDiagnostics
        {
            RequestedHostname = "db.example.com",
            ExpectedSpns = new List<SpnExpectation>
            {
                MakeSpn("FQDN + Port", "MSSQLSvc/db.example.com:1433", found: false),
                MakeSpn("FQDN (base)", "MSSQLSvc/db.example.com", found: false)
            }
        };

        KerberosInspector.RunHealthChecks(diag, 1433, false);

        Assert.Contains(diag.Warnings, w =>
            w.Severity == WarningSeverity.Error && w.Message.Contains("No SPN registered"));
    }

    [Fact]
    public void PortSpnFound_BaseAbsent_NamedInstance_EmitsInfo()
    {
        var diag = new KerberosDiagnostics
        {
            RequestedHostname = "db.example.com",
            ExpectedSpns = new List<SpnExpectation>
            {
                MakeSpn("FQDN + Port", "MSSQLSvc/db.example.com:22136", found: true, account: "svc-sql"),
                MakeSpn("FQDN + Instance", "MSSQLSvc/db.example.com:SQLPROD", found: true, account: "svc-sql"),
                MakeSpn("FQDN (base)", "MSSQLSvc/db.example.com", found: false)
            }
        };

        KerberosInspector.RunHealthChecks(diag, 22136, isNamedInstance: true);

        Assert.Contains(diag.Warnings, w =>
            w.Severity == WarningSeverity.Info && w.Message.Contains("expected configuration"));
    }

    [Fact]
    public void OnlyBaseSpn_NonDefaultPort_EmitsWarning()
    {
        var diag = new KerberosDiagnostics
        {
            RequestedHostname = "db.example.com",
            ExpectedSpns = new List<SpnExpectation>
            {
                MakeSpn("FQDN + Port", "MSSQLSvc/db.example.com:5000", found: false),
                MakeSpn("FQDN (base)", "MSSQLSvc/db.example.com", found: true, account: "svc-sql")
            }
        };

        KerberosInspector.RunHealthChecks(diag, 5000, isNamedInstance: false);

        Assert.Contains(diag.Warnings, w =>
            w.Severity == WarningSeverity.Warning && w.Message.Contains("port-specific SPN is recommended"));
    }

    [Fact]
    public void SpnsOnDifferentAccounts_EmitsWarning()
    {
        var diag = new KerberosDiagnostics
        {
            RequestedHostname = "db.example.com",
            ExpectedSpns = new List<SpnExpectation>
            {
                MakeSpn("FQDN + Port", "MSSQLSvc/db.example.com:1433", found: true, account: "svc-sql1"),
                MakeSpn("FQDN (base)", "MSSQLSvc/db.example.com", found: true, account: "svc-sql2")
            }
        };

        KerberosInspector.RunHealthChecks(diag, 1433, isNamedInstance: false);

        Assert.Contains(diag.Warnings, w =>
            w.Severity == WarningSeverity.Warning && w.Message.Contains("different accounts"));
    }

    [Fact]
    public void AllSpnsFound_SameAccount_NoWarnings()
    {
        var diag = new KerberosDiagnostics
        {
            RequestedHostname = "db.example.com",
            ExpectedSpns = new List<SpnExpectation>
            {
                MakeSpn("FQDN + Port", "MSSQLSvc/db.example.com:1433", found: true, account: "svc-sql"),
                MakeSpn("FQDN (base)", "MSSQLSvc/db.example.com", found: true, account: "svc-sql")
            }
        };

        KerberosInspector.RunHealthChecks(diag, 1433, isNamedInstance: false);

        Assert.Empty(diag.Warnings);
    }

    [Fact]
    public void DnsMismatch_EmitsWarning()
    {
        var diag = new KerberosDiagnostics
        {
            RequestedHostname = "db.example.com",
            ForwardReverseMismatch = true,
            ResolvedIpAddresses = new List<string> { "10.0.0.5" },
            ReverseHostname = "other.example.com",
            ExpectedSpns = new List<SpnExpectation>
            {
                MakeSpn("FQDN + Port", "MSSQLSvc/db.example.com:1433", found: true, account: "svc-sql"),
                MakeSpn("FQDN (base)", "MSSQLSvc/db.example.com", found: true, account: "svc-sql")
            }
        };

        KerberosInspector.RunHealthChecks(diag, 1433, isNamedInstance: false);

        Assert.Contains(diag.Warnings, w =>
            w.Severity == WarningSeverity.Warning && w.Message.Contains("Forward/reverse DNS mismatch"));
    }

    [Fact]
    public void CnameDetected_EmitsWarning()
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
    public void SpnLookupError_EmitsWarning_SkipsSpnChecks()
    {
        var diag = new KerberosDiagnostics
        {
            RequestedHostname = "db.example.com",
            SpnLookupError = "LDAP SPN lookup failed: Access denied",
            ExpectedSpns = new List<SpnExpectation>()
        };

        KerberosInspector.RunHealthChecks(diag, 1433, isNamedInstance: false);

        Assert.Single(diag.Warnings);
        Assert.Contains(diag.Warnings, w =>
            w.Severity == WarningSeverity.Warning && w.Message.Contains("LDAP SPN lookup failed"));
    }

    private static SpnExpectation MakeSpn(string label, string spn, bool found, string? account = null)
    {
        return new SpnExpectation
        {
            Label = label,
            Spn = spn,
            Result = new SpnLookupResult
            {
                Found = found,
                AccountName = account,
                AccountType = account != null ? "User" : null
            }
        };
    }
}
