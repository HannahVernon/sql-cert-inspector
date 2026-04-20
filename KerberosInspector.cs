using System.DirectoryServices;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;

namespace SqlCertInspector;

/// <summary>
/// Performs Kerberos-related diagnostics: DNS forward/reverse resolution,
/// SPN lookup via LDAP, and health checks.
/// </summary>
[SupportedOSPlatform("windows")]
public static class KerberosInspector
{
    private const string SpnServiceClass = "MSSQLSvc";

    public static KerberosDiagnostics Inspect(
        string hostname, int port, string? instanceName,
        bool isPortExplicit = false, bool fullSpnDiagnostics = false,
        bool skipDns = false, bool skipKerberos = false)
    {
        var diag = new KerberosDiagnostics
        {
            RequestedHostname = hostname
        };

        /* DNS resolution */
        if (!skipDns)
        {
            var dnsResult = DnsResolver.ResolveHost(hostname);
            PopulateDnsResults(diag, dnsResult, hostname);
            PerformReverseLookup(diag);
        }

        /* SPN construction and lookup */
        if (!skipKerberos)
        {
            string spnHostname = diag.ResolvedFqdn ?? hostname;
            diag.ExpectedSpns = BuildExpectedSpns(
                spnHostname, port, instanceName, isPortExplicit, fullSpnDiagnostics);
            PerformSpnLookup(diag);
        }

        bool isNamedInstance = instanceName != null;
        RunHealthChecks(diag, port, isNamedInstance);

        return diag;
    }

    /// <summary>
    /// Builds the list of expected SPN variants for a given SQL Server endpoint.
    /// Visible for unit testing.
    /// </summary>
    public static List<SpnExpectation> BuildExpectedSpns(
        string hostname, int port, string? instanceName,
        bool isPortExplicit = false, bool fullSpnDiagnostics = false)
    {
        var spns = new List<SpnExpectation>();
        bool isNamedInstance = instanceName != null;

        /* Build the short (NetBIOS) hostname from the FQDN.
           Skip short-name SPNs when the hostname is an IP address. */
        string shortName = hostname.Split('.')[0];
        bool hasShortName = !IPAddress.TryParse(hostname, out _) &&
                            !string.Equals(shortName, hostname, StringComparison.OrdinalIgnoreCase);

        /* Base (portless) SPNs are only relevant for non-TCP protocols on default
           instances. For TCP connections (which this tool uses), the port-based SPN
           is what SQL Server registers and what clients use. Base SPNs are only
           included when --full-spn-diagnostics is specified, AND the connection is
           a default instance with an implicit (non-explicit) port. */
        bool includeBaseSpns = fullSpnDiagnostics && !isNamedInstance && !isPortExplicit;

        /* FQDN + Port — always present */
        spns.Add(new SpnExpectation
        {
            Label = "FQDN + Port",
            Spn = $"{SpnServiceClass}/{hostname}:{port}"
        });

        if (isNamedInstance)
        {
            spns.Add(new SpnExpectation
            {
                Label = "FQDN + Instance",
                Spn = $"{SpnServiceClass}/{hostname}:{instanceName}"
            });
        }

        if (hasShortName)
        {
            spns.Add(new SpnExpectation
            {
                Label = "Short + Port",
                Spn = $"{SpnServiceClass}/{shortName}:{port}"
            });

            if (isNamedInstance)
            {
                spns.Add(new SpnExpectation
                {
                    Label = "Short + Instance",
                    Spn = $"{SpnServiceClass}/{shortName}:{instanceName}"
                });
            }
        }

        if (includeBaseSpns)
        {
            spns.Add(new SpnExpectation
            {
                Label = "FQDN (base)",
                Spn = $"{SpnServiceClass}/{hostname}"
            });

            if (hasShortName)
            {
                spns.Add(new SpnExpectation
                {
                    Label = "Short (base)",
                    Spn = $"{SpnServiceClass}/{shortName}"
                });
            }
        }

        return spns;
    }

    /// <summary>
    /// Populates KerberosDiagnostics from a DnsResult (P/Invoke-based resolution).
    /// </summary>
    private static void PopulateDnsResults(KerberosDiagnostics diag, DnsResult dnsResult, string hostname)
    {
        if (dnsResult.Errors.Count > 0)
        {
            diag.DnsError = string.Join("; ", dnsResult.Errors);
        }

        diag.DnsRecordTypes = dnsResult.RecordTypes;

        foreach (var addr in dnsResult.Addresses)
        {
            diag.ResolvedIpAddresses.Add(addr);
        }

        /* True CNAME — the DNS response contained an actual CNAME record */
        if (dnsResult.CanonicalName != null)
        {
            diag.CnameTarget = dnsResult.CanonicalName;
        }

        /* Suffix expansion — short name resolved via DNS suffix search, no CNAME */
        if (dnsResult.WasSuffixExpanded && dnsResult.ResolvedFqdn != null)
        {
            diag.ResolvedFqdn = dnsResult.ResolvedFqdn;
        }

        if (dnsResult.Addresses.Count == 0 && dnsResult.Errors.Count == 0)
        {
            diag.DnsError = $"DNS resolution returned no addresses for '{hostname}'.";
        }
    }

    /// <summary>
    /// Performs reverse DNS lookup on the first resolved IP address.
    /// </summary>
    private static void PerformReverseLookup(KerberosDiagnostics diag)
    {
        if (diag.ResolvedIpAddresses.Count == 0 || diag.DnsError != null)
            return;

        string firstIp = diag.ResolvedIpAddresses[0];
        if (!IPAddress.TryParse(firstIp, out var ipAddr))
            return;

        try
        {
            var reverseEntry = Dns.GetHostEntry(ipAddr);
            diag.ReverseHostname = reverseEntry.HostName;

            /* Check forward/reverse match — compare against requested hostname,
               resolved FQDN, and CNAME target */
            string requested = diag.RequestedHostname;
            string? fqdn = diag.ResolvedFqdn;
            string? cname = diag.CnameTarget;

            bool matches = string.Equals(reverseEntry.HostName, requested, StringComparison.OrdinalIgnoreCase) ||
                           (fqdn != null && string.Equals(reverseEntry.HostName, fqdn, StringComparison.OrdinalIgnoreCase)) ||
                           (cname != null && string.Equals(reverseEntry.HostName, cname, StringComparison.OrdinalIgnoreCase));
            diag.ForwardReverseMismatch = !matches;
        }
        catch (SocketException)
        {
            diag.ReverseHostname = "(reverse lookup failed)";
            diag.ForwardReverseMismatch = true;
        }
    }

    private static void PerformSpnLookup(KerberosDiagnostics diag)
    {
        try
        {
            foreach (var expected in diag.ExpectedSpns)
            {
                expected.Result = LookupSpn(expected.Spn);
            }
        }
        catch (Exception ex)
        {
            diag.SpnLookupError = $"LDAP SPN lookup failed: {ex.Message}";
        }
    }

    private static SpnLookupResult LookupSpn(string spn)
    {
        var result = new SpnLookupResult();

        try
        {
            using var searcher = new DirectorySearcher
            {
                Filter = $"(servicePrincipalName={EscapeLdapFilter(spn)})",
                PropertiesToLoad = { "servicePrincipalName", "sAMAccountName", "objectClass", "distinguishedName" },
                SearchScope = SearchScope.Subtree,
                ServerTimeLimit = TimeSpan.FromSeconds(15),
                ClientTimeout = TimeSpan.FromSeconds(30)
            };

            var searchResult = searcher.FindOne();
            if (searchResult != null)
            {
                result.Found = true;
                result.AccountName = GetPropertyValue(searchResult, "sAMAccountName");

                var objectClasses = searchResult.Properties["objectClass"];
                if (objectClasses != null)
                {
                    if (objectClasses.Contains("computer"))
                        result.AccountType = "Computer";
                    else if (objectClasses.Contains("msDS-ManagedServiceAccount") ||
                             objectClasses.Contains("msDS-GroupManagedServiceAccount"))
                        result.AccountType = "Managed Service Account";
                    else if (objectClasses.Contains("user"))
                        result.AccountType = "User";
                    else
                        result.AccountType = "Unknown";
                }
            }
        }
        catch (Exception)
        {
            /* If LDAP search fails for this specific SPN, mark as not found
               but don't throw — the caller handles the overall error */
            result.Found = false;
        }

        return result;
    }

    private static string? GetPropertyValue(SearchResult result, string propertyName)
    {
        if (result.Properties.Contains(propertyName) && result.Properties[propertyName].Count > 0)
        {
            return result.Properties[propertyName][0]?.ToString();
        }
        return null;
    }

    /// <summary>
    /// Escapes special characters in LDAP filter values per RFC 4515.
    /// </summary>
    private static string EscapeLdapFilter(string value)
    {
        return value
            .Replace("\\", "\\5c")
            .Replace("*", "\\2a")
            .Replace("(", "\\28")
            .Replace(")", "\\29")
            .Replace("\0", "\\00");
    }

    internal static void RunHealthChecks(KerberosDiagnostics diag, int port, bool isNamedInstance)
    {
        /* DNS issues */
        if (diag.DnsError != null)
        {
            diag.Warnings.Add(new KerberosWarning(WarningSeverity.Error, diag.DnsError));
        }

        if (diag.ForwardReverseMismatch)
        {
            diag.Warnings.Add(new KerberosWarning(WarningSeverity.Warning,
                $"Forward/reverse DNS mismatch. '{diag.RequestedHostname}' resolves to " +
                $"{string.Join(", ", diag.ResolvedIpAddresses)}, but reverse lookup returns " +
                $"'{diag.ReverseHostname}'. Kerberos authentication may fail."));
        }

        if (diag.CnameTarget != null)
        {
            diag.Warnings.Add(new KerberosWarning(WarningSeverity.Warning,
                $"Hostname '{diag.RequestedHostname}' appears to be a CNAME pointing to " +
                $"'{diag.CnameTarget}'. Kerberos will use '{diag.RequestedHostname}' (the " +
                "requested hostname) for SPN construction, which may cause authentication " +
                $"failures if the SPN is registered under the canonical name '{diag.CnameTarget}'."));
        }

        /* SPN issues — only check when SPNs were actually looked up */
        if (diag.SpnLookupError != null)
        {
            diag.Warnings.Add(new KerberosWarning(WarningSeverity.Warning, diag.SpnLookupError));
            return;
        }

        if (diag.ExpectedSpns.Count == 0) return;

        /* Categorize SPNs: port/instance-specific vs base */
        var specificSpns = diag.ExpectedSpns.Where(s => s.Spn.Contains(':')).ToList();
        var baseSpns = diag.ExpectedSpns.Where(s => !s.Spn.Contains(':')).ToList();

        bool anySpecificFound = specificSpns.Any(s => s.Result?.Found == true);
        bool anyBaseFound = baseSpns.Any(s => s.Result?.Found == true);

        if (!anySpecificFound && !anyBaseFound)
        {
            string allSpns = string.Join(", ", diag.ExpectedSpns.Select(s => $"'{s.Spn}'"));
            diag.Warnings.Add(new KerberosWarning(WarningSeverity.Error,
                $"No SPN registered for this SQL Server instance. None of the expected SPNs " +
                $"({allSpns}) were found in Active Directory. " +
                "Kerberos authentication will NOT work — clients will fall back to NTLM."));

            /* Only suggest FQDN-based SPNs — short-name SPNs can cause conflicts
               in multi-domain environments and should be left to the administrator */
            foreach (var spn in specificSpns.Where(s =>
                s.Result?.Found != true && s.Label.StartsWith("FQDN", StringComparison.Ordinal)))
            {
                diag.SuggestedSetspnCommands.Add($"setspn -S {spn.Spn} <DOMAIN\\ServiceAccount>");
            }
        }
        else if (!anySpecificFound && anyBaseFound && port != 1433)
        {
            string missingSpecific = string.Join(", ", specificSpns.Select(s => $"'{s.Spn}'"));
            diag.Warnings.Add(new KerberosWarning(WarningSeverity.Warning,
                $"No port/instance-specific SPN found ({missingSpecific}), but a base SPN exists. " +
                $"Since this instance uses a non-default port ({port}), a port-specific SPN is recommended."));

            foreach (var spn in specificSpns.Where(s =>
                s.Result?.Found != true && s.Label.StartsWith("FQDN", StringComparison.Ordinal)))
            {
                diag.SuggestedSetspnCommands.Add($"setspn -S {spn.Spn} <DOMAIN\\ServiceAccount>");
            }
        }

        /* Check for SPNs registered to different accounts */
        var foundSpns = diag.ExpectedSpns
            .Where(s => s.Result?.Found == true && s.Result.AccountName != null)
            .ToList();

        var distinctAccounts = foundSpns
            .Select(s => s.Result!.AccountName!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (distinctAccounts.Count > 1)
        {
            string details = string.Join("; ", foundSpns.Select(s => $"'{s.Spn}' → {s.Result!.AccountName}"));
            diag.Warnings.Add(new KerberosWarning(WarningSeverity.Warning,
                $"SPNs are registered to different accounts: {details}. " +
                "This may cause unpredictable Kerberos authentication behavior."));
        }

        /* SAN SPN coverage warnings */
        if (diag.SanSpnCoverage != null)
        {
            var missingSanSpns = diag.SanSpnCoverage.Where(s => !s.Found).ToList();
            if (missingSanSpns.Count > 0)
            {
                foreach (var missing in missingSanSpns)
                {
                    diag.Warnings.Add(new KerberosWarning(WarningSeverity.Info,
                        $"SAN hostname '{missing.SanHostname}' has no SPN registered ({missing.Spn}). " +
                        "Kerberos authentication will fail for clients connecting via this name."));
                }
            }
        }
    }

    /// <summary>
    /// Performs SPN lookups for each DNS SAN hostname from the certificate that differs
    /// from the primary connection hostname. Call after both cert and Kerberos inspection complete.
    /// </summary>
    public static void CrossReferenceSanSpns(
        KerberosDiagnostics diag, CertificateInfo cert, int port, string connectionHostname)
    {
        if (diag.SpnLookupError != null) return;

        var sanHostnames = cert.SubjectAlternativeNames
            .Where(s => s.StartsWith("DNS:", StringComparison.OrdinalIgnoreCase))
            .Select(s => s[4..])
            .Where(h => !h.StartsWith("*")) /* skip wildcard SANs */
            .Where(h => !string.Equals(h, connectionHostname, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (sanHostnames.Count == 0) return;

        diag.SanSpnCoverage = new List<SanSpnCheck>();

        foreach (string sanHost in sanHostnames)
        {
            string spn = $"{SpnServiceClass}/{sanHost}:{port}";
            var result = LookupSpn(spn);

            diag.SanSpnCoverage.Add(new SanSpnCheck
            {
                SanHostname = sanHost,
                Spn = spn,
                Found = result.Found,
                AccountName = result.AccountName,
                AccountType = result.AccountType
            });
        }
    }
}
