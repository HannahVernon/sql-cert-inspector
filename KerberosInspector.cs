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

    public static KerberosDiagnostics Inspect(string hostname, int port)
    {
        var diag = new KerberosDiagnostics
        {
            RequestedHostname = hostname,
            ExpectedSpnWithPort = $"{SpnServiceClass}/{hostname}:{port}",
            ExpectedSpnWithoutPort = $"{SpnServiceClass}/{hostname}"
        };

        PerformDnsResolution(diag, hostname);
        PerformSpnLookup(diag);
        RunHealthChecks(diag, port);

        return diag;
    }

    private static void PerformDnsResolution(KerberosDiagnostics diag, string hostname)
    {
        try
        {
            /* Forward lookup */
            var hostEntry = Dns.GetHostEntry(hostname);
            foreach (var ip in hostEntry.AddressList)
            {
                diag.ResolvedIpAddresses.Add(ip.ToString());
            }

            /* Check if the resolved hostname differs (CNAME detection) */
            if (!string.Equals(hostEntry.HostName, hostname, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(hostEntry.HostName, hostname.Split('.')[0], StringComparison.OrdinalIgnoreCase))
            {
                diag.CnameTarget = hostEntry.HostName;
            }

            /* Reverse lookup on the first IP */
            if (hostEntry.AddressList.Length > 0)
            {
                try
                {
                    var reverseEntry = Dns.GetHostEntry(hostEntry.AddressList[0]);
                    diag.ReverseHostname = reverseEntry.HostName;

                    /* Check forward/reverse match */
                    bool matches = string.Equals(reverseEntry.HostName, hostname, StringComparison.OrdinalIgnoreCase) ||
                                   string.Equals(reverseEntry.HostName, hostEntry.HostName, StringComparison.OrdinalIgnoreCase);
                    diag.ForwardReverseMismatch = !matches;
                }
                catch (SocketException)
                {
                    diag.ReverseHostname = "(reverse lookup failed)";
                    diag.ForwardReverseMismatch = true;
                }
            }
        }
        catch (SocketException ex)
        {
            diag.DnsError = $"DNS resolution failed for '{hostname}': {ex.Message}";
        }
    }

    private static void PerformSpnLookup(KerberosDiagnostics diag)
    {
        try
        {
            diag.SpnWithPort = LookupSpn(diag.ExpectedSpnWithPort);
            diag.SpnWithoutPort = LookupSpn(diag.ExpectedSpnWithoutPort);
        }
        catch (Exception ex)
        {
            diag.SpnLookupError = $"LDAP SPN lookup failed: {ex.Message}";
        }
    }

    private static SpnLookupResult LookupSpn(string spn)
    {
        var result = new SpnLookupResult { Spn = spn };

        try
        {
            using var searcher = new DirectorySearcher
            {
                Filter = $"(servicePrincipalName={EscapeLdapFilter(spn)})",
                PropertiesToLoad = { "servicePrincipalName", "sAMAccountName", "objectClass", "distinguishedName" },
                SearchScope = SearchScope.Subtree
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

    private static void RunHealthChecks(KerberosDiagnostics diag, int port)
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
                $"'{diag.CnameTarget}'. Kerberos uses the original hostname for SPN construction, " +
                "which may cause authentication failures if the SPN is registered under the canonical name."));
        }

        /* SPN issues */
        if (diag.SpnLookupError != null)
        {
            diag.Warnings.Add(new KerberosWarning(WarningSeverity.Warning, diag.SpnLookupError));
            return;
        }

        bool portSpnFound = diag.SpnWithPort?.Found == true;
        bool baseSpnFound = diag.SpnWithoutPort?.Found == true;

        if (!portSpnFound && !baseSpnFound)
        {
            diag.Warnings.Add(new KerberosWarning(WarningSeverity.Error,
                $"No SPN registered for this SQL Server instance. Neither '{diag.ExpectedSpnWithPort}' " +
                $"nor '{diag.ExpectedSpnWithoutPort}' was found in Active Directory. " +
                "Kerberos authentication will NOT work — clients will fall back to NTLM."));
        }
        else if (!portSpnFound && baseSpnFound && port != 1433)
        {
            diag.Warnings.Add(new KerberosWarning(WarningSeverity.Warning,
                $"Port-specific SPN '{diag.ExpectedSpnWithPort}' is not registered, but " +
                $"base SPN '{diag.ExpectedSpnWithoutPort}' exists. Since this instance uses " +
                $"a non-default port ({port}), the port-specific SPN is recommended."));
        }

        /* Check for duplicate SPNs (same SPN on different accounts) */
        if (portSpnFound && baseSpnFound &&
            diag.SpnWithPort!.AccountName != null && diag.SpnWithoutPort!.AccountName != null &&
            !string.Equals(diag.SpnWithPort.AccountName, diag.SpnWithoutPort.AccountName, StringComparison.OrdinalIgnoreCase))
        {
            diag.Warnings.Add(new KerberosWarning(WarningSeverity.Warning,
                $"Port SPN and base SPN are registered to different accounts: " +
                $"'{diag.SpnWithPort.Spn}' → {diag.SpnWithPort.AccountName}, " +
                $"'{diag.SpnWithoutPort.Spn}' → {diag.SpnWithoutPort.AccountName}. " +
                "This may cause unpredictable Kerberos authentication behavior."));
        }
    }
}
