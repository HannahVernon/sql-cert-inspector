using SqlCertInspector;

namespace SqlCertInspectorTests;

public class SpnBuildingTests
{
    [Fact]
    public void Fqdn_NamedInstance_Produces4Spns_NoBaseSpns()
    {
        var spns = KerberosInspector.BuildExpectedSpns(
            "db.corp.example.com", 22136, "SQLPROD");

        Assert.Equal(4, spns.Count);
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db.corp.example.com:22136" && s.Label == "FQDN + Port");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db.corp.example.com:SQLPROD" && s.Label == "FQDN + Instance");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db:22136" && s.Label == "Short + Port");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db:SQLPROD" && s.Label == "Short + Instance");
        /* Named instances should NOT produce base (portless) SPNs */
        Assert.DoesNotContain(spns, s => s.Label.Contains("base"));
    }

    [Fact]
    public void Fqdn_DefaultInstance_ImplicitPort_NoBaseSpnsByDefault()
    {
        var spns = KerberosInspector.BuildExpectedSpns(
            "db.corp.example.com", 1433, null, isPortExplicit: false);

        Assert.Equal(2, spns.Count);
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db.corp.example.com:1433");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db:1433");
        Assert.DoesNotContain(spns, s => s.Label.Contains("base"));
        Assert.DoesNotContain(spns, s => s.Label.Contains("Instance"));
    }

    [Fact]
    public void Fqdn_DefaultInstance_FullDiagnostics_IncludesBaseSpns()
    {
        var spns = KerberosInspector.BuildExpectedSpns(
            "db.corp.example.com", 1433, null,
            isPortExplicit: false, fullSpnDiagnostics: true);

        Assert.Equal(4, spns.Count);
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db.corp.example.com:1433");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db:1433");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db.corp.example.com" && s.Label == "FQDN (base)");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db" && s.Label == "Short (base)");
    }

    [Fact]
    public void Fqdn_DefaultInstance_ExplicitPort1433_NoBaseSpns()
    {
        var spns = KerberosInspector.BuildExpectedSpns(
            "db.corp.example.com", 1433, null, isPortExplicit: true);

        Assert.Equal(2, spns.Count);
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db.corp.example.com:1433");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db:1433");
        Assert.DoesNotContain(spns, s => s.Label.Contains("base"));
    }

    [Fact]
    public void Fqdn_DefaultInstance_ExplicitPort_FullDiagnostics_StillNoBaseSpns()
    {
        var spns = KerberosInspector.BuildExpectedSpns(
            "db.corp.example.com", 1433, null,
            isPortExplicit: true, fullSpnDiagnostics: true);

        Assert.Equal(2, spns.Count);
        Assert.DoesNotContain(spns, s => s.Label.Contains("base"));
    }

    [Fact]
    public void SinglePartHostname_NoShortOrBaseSpns()
    {
        var spns = KerberosInspector.BuildExpectedSpns(
            "localhost", 1433, null);

        Assert.Single(spns);
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/localhost:1433");
        Assert.DoesNotContain(spns, s => s.Label.StartsWith("Short"));
        Assert.DoesNotContain(spns, s => s.Label.Contains("base"));
    }

    [Fact]
    public void SinglePartHostname_NamedInstance_NoBaseSpns()
    {
        var spns = KerberosInspector.BuildExpectedSpns(
            "MYSERVER", 5000, "INST");

        Assert.Equal(2, spns.Count);
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/MYSERVER:5000");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/MYSERVER:INST");
        Assert.DoesNotContain(spns, s => s.Label.StartsWith("Short"));
        Assert.DoesNotContain(spns, s => s.Label.Contains("base"));
    }

    [Fact]
    public void IPv4Address_NoShortOrBaseSpns()
    {
        var spns = KerberosInspector.BuildExpectedSpns(
            "192.168.1.10", 1433, null);

        Assert.Single(spns);
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/192.168.1.10:1433");
        /* Must NOT produce MSSQLSvc/192:1433 */
        Assert.DoesNotContain(spns, s => s.Spn.Contains("MSSQLSvc/192:"));
        Assert.DoesNotContain(spns, s => s.Label.Contains("base"));
    }

    [Fact]
    public void IPv4Address_NamedInstance_NoBaseSpns()
    {
        var spns = KerberosInspector.BuildExpectedSpns(
            "10.200.24.228", 22136, "SQLPROD");

        Assert.Equal(2, spns.Count);
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/10.200.24.228:22136");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/10.200.24.228:SQLPROD");
        Assert.DoesNotContain(spns, s => s.Label.StartsWith("Short"));
        Assert.DoesNotContain(spns, s => s.Label.Contains("base"));
    }

    [Fact]
    public void IPv6Address_NoShortOrBaseSpns()
    {
        var spns = KerberosInspector.BuildExpectedSpns(
            "2001:db8::1", 1433, null);

        Assert.Single(spns);
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/2001:db8::1:1433");
    }

    [Fact]
    public void TwoPartHostname_ProducesShortSpns_NoBaseSpns()
    {
        var spns = KerberosInspector.BuildExpectedSpns(
            "db.local", 1433, null);

        Assert.Equal(2, spns.Count);
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db.local:1433");
        Assert.Contains(spns, s => s.Spn == "MSSQLSvc/db:1433");
        Assert.DoesNotContain(spns, s => s.Label.Contains("base"));
    }
}
