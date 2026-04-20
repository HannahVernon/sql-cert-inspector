using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace SqlCertInspector;

/// <summary>
/// Performs DNS resolution via P/Invoke to DnsQuery_W (dnsapi.dll),
/// providing actual DNS record type information (A, AAAA, CNAME).
/// </summary>
[SupportedOSPlatform("windows")]
public static class DnsResolver
{
    /* DNS record types */
    private const ushort DNS_TYPE_A = 1;
    private const ushort DNS_TYPE_CNAME = 5;
    private const ushort DNS_TYPE_AAAA = 28;

    /* DnsQuery options */
    private const int DNS_QUERY_STANDARD = 0x00000000;

    /* DnsFree type */
    private const int DnsFreeRecordList = 1;

    /// <summary>
    /// Resolves a hostname using the Windows DNS resolver, returning full record type information.
    /// </summary>
    public static DnsResult ResolveHost(string hostname)
    {
        var result = new DnsResult { QueriedName = hostname };

        bool isIpAddress = IPAddress.TryParse(hostname, out _);
        if (isIpAddress)
        {
            result.SkippedDns = true;
            return result;
        }

        bool hasNoDots = !hostname.Contains('.');

        /* Query A records — CNAME records in the chain are included automatically */
        QueryRecords(hostname, DNS_TYPE_A, result);

        /* Query AAAA records for IPv6 */
        QueryRecords(hostname, DNS_TYPE_AAAA, result);

        /* Detect suffix expansion vs true CNAME */
        if (hasNoDots && result.CnameChain.Count == 0 && result.Addresses.Count > 0)
        {
            /* No CNAME record in the response, but input was a short name.
               Use Dns.GetHostEntry to discover the FQDN from suffix expansion. */
            try
            {
                var hostEntry = Dns.GetHostEntry(hostname);
                if (!string.Equals(hostEntry.HostName, hostname, StringComparison.OrdinalIgnoreCase))
                {
                    result.ResolvedFqdn = hostEntry.HostName;
                    result.WasSuffixExpanded = true;

                    /* Identify which DNS suffix produced the match and check for ambiguity */
                    var suffixes = GetDnsSuffixSearchList();
                    result.ConfiguredSuffixes = suffixes;

                    if (suffixes.Count > 0)
                    {
                        IdentifyUsedSuffix(hostname, result, suffixes);
                    }
                }
            }
            catch (System.Net.Sockets.SocketException)
            {
                /* Suffix expansion detection failed — not critical */
            }
        }

        return result;
    }

    /// <summary>
    /// Retrieves the DNS suffix search list configured on this machine.
    /// Checks the SearchList policy (GPO), then the DHCP/manual search list,
    /// and falls back to the primary DNS suffix and per-adapter connection-specific suffixes.
    /// </summary>
    internal static List<string> GetDnsSuffixSearchList()
    {
        var suffixes = new List<string>();

        try
        {
            /* GPO-configured search list takes priority */
            using var policyKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient");
            string? policyList = policyKey?.GetValue("SearchList") as string;
            if (!string.IsNullOrWhiteSpace(policyList))
            {
                foreach (string s in policyList.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (!suffixes.Contains(s, StringComparer.OrdinalIgnoreCase))
                        suffixes.Add(s);
                }
                return suffixes;
            }

            /* Manual/DHCP search list */
            using var tcpipKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
            string? searchList = tcpipKey?.GetValue("SearchList") as string;
            if (!string.IsNullOrWhiteSpace(searchList))
            {
                foreach (string s in searchList.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (!suffixes.Contains(s, StringComparer.OrdinalIgnoreCase))
                        suffixes.Add(s);
                }
                return suffixes;
            }

            /* Fall back to primary DNS suffix + connection-specific suffixes */
            string? primaryDomain = tcpipKey?.GetValue("Domain") as string;
            if (!string.IsNullOrWhiteSpace(primaryDomain))
            {
                suffixes.Add(primaryDomain);
            }

            /* Per-adapter connection-specific suffixes */
            using var interfacesKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces");
            if (interfacesKey != null)
            {
                foreach (string subKeyName in interfacesKey.GetSubKeyNames())
                {
                    using var adapterKey = interfacesKey.OpenSubKey(subKeyName);
                    string? adapterDomain = adapterKey?.GetValue("Domain") as string;
                    if (!string.IsNullOrWhiteSpace(adapterDomain) &&
                        !suffixes.Contains(adapterDomain, StringComparer.OrdinalIgnoreCase))
                    {
                        suffixes.Add(adapterDomain);
                    }

                    string? dhcpDomain = adapterKey?.GetValue("DhcpDomain") as string;
                    if (!string.IsNullOrWhiteSpace(dhcpDomain) &&
                        !suffixes.Contains(dhcpDomain, StringComparer.OrdinalIgnoreCase))
                    {
                        suffixes.Add(dhcpDomain);
                    }
                }
            }
        }
        catch (System.Security.SecurityException)
        {
            /* Registry access denied — return what we have */
        }

        return suffixes;
    }

    /// <summary>
    /// Determines which DNS suffix produced the resolution and checks for ambiguity
    /// (same short name resolving to different IPs via different suffixes).
    /// </summary>
    private static void IdentifyUsedSuffix(string shortName, DnsResult result, List<string> suffixes)
    {
        string? resolvedFqdn = result.ResolvedFqdn;
        if (resolvedFqdn == null) return;

        /* Identify the matching suffix from the resolved FQDN */
        foreach (string suffix in suffixes)
        {
            string candidate = $"{shortName}.{suffix}";
            if (string.Equals(candidate, resolvedFqdn, StringComparison.OrdinalIgnoreCase))
            {
                result.UsedSuffix = suffix;
                break;
            }
        }

        /* Check for ambiguity — try each other suffix and see if any resolves to different IPs */
        if (suffixes.Count <= 1) return;

        var resolvedIps = new HashSet<string>(result.Addresses, StringComparer.OrdinalIgnoreCase);

        foreach (string suffix in suffixes)
        {
            if (string.Equals(suffix, result.UsedSuffix, StringComparison.OrdinalIgnoreCase))
                continue;

            string candidate = $"{shortName}.{suffix}";
            try
            {
                var addresses = Dns.GetHostAddresses(candidate);
                if (addresses.Length > 0)
                {
                    var candidateIps = addresses.Select(a => a.ToString()).ToHashSet(StringComparer.OrdinalIgnoreCase);
                    if (!candidateIps.SetEquals(resolvedIps))
                    {
                        result.AmbiguousSuffixes.Add(new DnsSuffixMatch
                        {
                            Suffix = suffix,
                            Fqdn = candidate,
                            ResolvedIps = addresses.Select(a => a.ToString()).ToList()
                        });
                    }
                }
            }
            catch (System.Net.Sockets.SocketException)
            {
                /* This suffix didn't resolve — not ambiguous */
            }
        }
    }

    private static void QueryRecords(string hostname, ushort recordType, DnsResult result)
    {
        IntPtr recordsPtr = IntPtr.Zero;

        try
        {
            int status = DnsQuery(hostname, recordType, DNS_QUERY_STANDARD,
                                  IntPtr.Zero, out recordsPtr, IntPtr.Zero);

            if (status != 0)
            {
                /* DNS_ERROR_RCODE_NAME_ERROR (9003) = name doesn't exist,
                   DNS_INFO_NO_RECORDS (9501) = name exists but no records of this type.
                   Both are non-fatal when querying AAAA on IPv4-only names, etc. */
                if (status != 9003 && status != 9501)
                {
                    result.Errors.Add($"DnsQuery failed for {hostname} (type {recordType}): error {status}");
                }
                return;
            }

            ParseRecords(recordsPtr, result);
        }
        finally
        {
            if (recordsPtr != IntPtr.Zero)
            {
                DnsFree(recordsPtr, DnsFreeRecordList);
            }
        }
    }

    private static void ParseRecords(IntPtr recordsPtr, DnsResult result)
    {
        IntPtr current = recordsPtr;
        const int maxRecords = 1000;
        int recordCount = 0;

        while (current != IntPtr.Zero && recordCount < maxRecords)
        {
            var header = Marshal.PtrToStructure<DNS_RECORD_HEADER>(current);

            switch (header.wType)
            {
                case DNS_TYPE_A:
                {
                    /* DNS_A_DATA is a single uint32 at offset after the header */
                    IntPtr dataPtr = current + Marshal.SizeOf<DNS_RECORD_HEADER>();
                    uint ipRaw = (uint)Marshal.ReadInt32(dataPtr);
                    var ipBytes = BitConverter.GetBytes(ipRaw);
                    var ip = new IPAddress(ipBytes);
                    string ipStr = ip.ToString();

                    if (!result.Addresses.Contains(ipStr))
                    {
                        result.Addresses.Add(ipStr);
                    }
                    if (!result.RecordTypes.Contains("A"))
                    {
                        result.RecordTypes.Add("A");
                    }
                    break;
                }
                case DNS_TYPE_AAAA:
                {
                    /* DNS_AAAA_DATA is 16 bytes at offset after the header */
                    IntPtr dataPtr = current + Marshal.SizeOf<DNS_RECORD_HEADER>();
                    byte[] ipBytes = new byte[16];
                    Marshal.Copy(dataPtr, ipBytes, 0, 16);
                    var ip = new IPAddress(ipBytes);
                    string ipStr = ip.ToString();

                    if (!result.Addresses.Contains(ipStr))
                    {
                        result.Addresses.Add(ipStr);
                    }
                    if (!result.RecordTypes.Contains("AAAA"))
                    {
                        result.RecordTypes.Add("AAAA");
                    }
                    break;
                }
                case DNS_TYPE_CNAME:
                {
                    /* DNS_PTR_DATA: a single pointer to a string */
                    IntPtr dataPtr = current + Marshal.SizeOf<DNS_RECORD_HEADER>();
                    IntPtr namePtr = Marshal.ReadIntPtr(dataPtr);
                    string? cname = Marshal.PtrToStringUni(namePtr);

                    if (cname != null && !result.CnameChain.Contains(cname, StringComparer.OrdinalIgnoreCase))
                    {
                        result.CnameChain.Add(cname);
                    }
                    if (!result.RecordTypes.Contains("CNAME"))
                    {
                        result.RecordTypes.Add("CNAME");
                    }
                    break;
                }
            }

            current = header.pNext;
            recordCount++;
        }
    }

    #region P/Invoke

    [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int DnsQuery(
        string name,
        ushort type,
        int options,
        IntPtr servers,
        out IntPtr results,
        IntPtr reserved);

    [DllImport("dnsapi.dll", EntryPoint = "DnsFree")]
    private static extern void DnsFree(IntPtr data, int freeType);

    /* DNS_RECORD header — the common fields before the type-specific data union.
       We only need enough to read the type and walk the linked list. */
    [StructLayout(LayoutKind.Sequential)]
    private struct DNS_RECORD_HEADER
    {
        public IntPtr pNext;
        public IntPtr pName;       /* PWSTR — owner name */
        public ushort wType;
        public ushort wDataLength;
        public uint flags;
        public uint dwTtl;
        public uint dwReserved;
        /* Type-specific data follows immediately after this struct */
    }

    #endregion
}

/// <summary>
/// Results from a DNS resolution query, including record types.
/// </summary>
public sealed class DnsResult
{
    /// <summary>The hostname that was queried.</summary>
    public string QueriedName { get; set; } = string.Empty;

    /// <summary>True when the input was already an IP address and DNS was skipped.</summary>
    public bool SkippedDns { get; set; }

    /// <summary>Resolved IP addresses (from A and AAAA records).</summary>
    public List<string> Addresses { get; set; } = new();

    /// <summary>DNS record types present in the response (e.g. "A", "AAAA", "CNAME").</summary>
    public List<string> RecordTypes { get; set; } = new();

    /// <summary>
    /// CNAME chain — ordered list of canonical name targets.
    /// Empty if the name resolved directly (no CNAME).
    /// </summary>
    public List<string> CnameChain { get; set; } = new();

    /// <summary>
    /// The final canonical name from the CNAME chain, or null if no CNAME was present.
    /// </summary>
    public string? CanonicalName => CnameChain.Count > 0 ? CnameChain[^1] : null;

    /// <summary>
    /// True when the input was a short (non-FQDN) name that was expanded via DNS suffix search.
    /// Distinct from a CNAME — no CNAME record exists in the response.
    /// </summary>
    public bool WasSuffixExpanded { get; set; }

    /// <summary>
    /// The FQDN determined by suffix expansion. Null when the input was already an FQDN
    /// or when a CNAME was used instead.
    /// </summary>
    public string? ResolvedFqdn { get; set; }

    /// <summary>
    /// The DNS suffix that produced the successful resolution. Null when suffix
    /// expansion was not used or the matching suffix could not be identified.
    /// </summary>
    public string? UsedSuffix { get; set; }

    /// <summary>
    /// DNS suffixes configured on this machine (from GPO, DHCP, or adapter settings).
    /// </summary>
    public List<string> ConfiguredSuffixes { get; set; } = new();

    /// <summary>
    /// Other DNS suffixes that also resolve the short name but to different IP addresses.
    /// Non-empty indicates an ambiguous short name that could connect to different servers
    /// depending on DNS suffix order.
    /// </summary>
    public List<DnsSuffixMatch> AmbiguousSuffixes { get; set; } = new();

    /// <summary>Non-fatal errors encountered during DNS queries.</summary>
    public List<string> Errors { get; set; } = new();
}

/// <summary>
/// Represents a DNS suffix that resolves a short name to a different set of IPs
/// than the primary resolution, indicating potential ambiguity.
/// </summary>
public sealed class DnsSuffixMatch
{
    public string Suffix { get; set; } = string.Empty;
    public string Fqdn { get; set; } = string.Empty;
    public List<string> ResolvedIps { get; set; } = new();
}
