namespace SqlCertInspector;

/// <summary>
/// Renders <see cref="ConnectionSecurityInfo"/> as colored plain text to the console.
/// Auto-detects redirected output and suppresses colors accordingly.
/// </summary>
public static class ConsoleReporter
{
    private static bool _colorsEnabled;

    public static void Report(ConnectionSecurityInfo info, bool noColor)
    {
        _colorsEnabled = !noColor && !Console.IsOutputRedirected;

        WriteHeader("Connection Details");
        WriteField("Server", info.ServerName);
        WriteField("Resolved Host", info.ResolvedHost);
        if (info.ResolvedHostname != null)
        {
            WriteField("Resolved FQDN", info.ResolvedHostname);
        }
        WriteField("Resolved Port", info.ResolvedPort.ToString());
        if (info.ResolvedIPs is { Length: > 1 })
        {
            WriteField("Resolved IPs", string.Join(", ", info.ResolvedIPs));
            WriteField("Connected via", info.ConnectedIP ?? "Unknown");
        }
        else if (info.ResolvedIPs is { Length: 1 })
        {
            WriteField("Resolved IP", info.ResolvedIPs[0]);
        }
        if (info.InstanceName != null)
        {
            WriteField("Instance Name", info.InstanceName);
        }
        if (info.SqlServerVersion != null)
        {
            WriteField("SQL Server Version", info.SqlServerVersion);
        }
        WriteField("Encryption Mode", info.EncryptionMode ?? "Unknown");
        WriteField("TDS Protocol", info.TdsProtocol.ToDisplayString());
        if (info.UsedFallback)
        {
            string guidance = info.TdsProtocol == TdsProtocolVersion.Tds8Strict
                ? "This server requires strict encryption (TDS 8.0). Use --encrypt-strict to connect directly and avoid a retry."
                : "This server does not support strict encryption. Omit --encrypt-strict to connect directly.";
            WriteColored($"  [INFO] {guidance}", ConsoleColor.Cyan);
            Console.WriteLine();
        }
        Console.WriteLine();

        if (!info.IsEncrypted)
        {
            WriteColored($"Connection to {info.ServerName} is NOT encrypted.", ConsoleColor.Red);
            Console.WriteLine();
            Console.WriteLine();
            WriteColored(
                "The server does not support or require encryption for client connections.",
                ConsoleColor.Yellow);
            Console.WriteLine();
            return;
        }

        WriteHeader("TLS Connection Security");
        WriteField("TLS Protocol", info.TlsProtocolVersion ?? "Unknown");
        WriteField("Cipher Suite", info.CipherSuite ?? "Unknown");
        WriteField("Key Exchange", FormatKeyExchange(info));
        WriteField("Hash Algorithm", FormatHash(info));
        Console.WriteLine();

        if (info.Certificate != null)
        {
            bool hasChain = info.Certificate.ChainCertificates is { Count: > 0 };

            if (!hasChain)
                ReportCertificate(info.Certificate, "Server Certificate");

            if (hasChain)
            {
                var chain = info.Certificate.ChainCertificates!;
                Console.WriteLine();
                WriteHeader("Certificate Chain");
                for (int i = 0; i < chain.Count; i++)
                {
                    string label = i == 0
                        ? "Leaf (Server)"
                        : i == chain.Count - 1
                            ? "Root CA"
                            : $"Intermediate CA ({i})";
                    ReportCertificate(chain[i], label);
                    if (i < chain.Count - 1) Console.WriteLine();
                }

                if (info.Certificate.ChainStatusMessages.Count > 0)
                {
                    Console.WriteLine();
                    WriteHeader("Chain Validation");
                    foreach (string msg in info.Certificate.ChainStatusMessages)
                    {
                        WriteColored($"  {msg}", ConsoleColor.Yellow);
                        Console.WriteLine();
                    }
                }
            }

            if (info.Certificate.Warnings.Count > 0)
            {
                Console.WriteLine();
                ReportWarnings(info.Certificate.Warnings);
            }
            else
            {
                Console.WriteLine();
                WriteColored("[PASS] No certificate issues detected.", ConsoleColor.Green);
                Console.WriteLine();
            }
        }

        /* Kerberos diagnostics */
        if (info.Kerberos != null)
        {
            Console.WriteLine();
            ReportKerberos(info.Kerberos);
        }

        /* SAN connectivity tests */
        if (info.SanConnectivityResults is { Count: > 0 })
        {
            Console.WriteLine();
            ReportSanConnectivity(info.SanConnectivityResults);
        }

        /* Kerberos authentication test */
        if (info.KerberosAuthTest != null)
        {
            Console.WriteLine();
            ReportKerberosAuthTest(info.KerberosAuthTest);
        }

        /* Show RC4 advisory links if any RC4 risk was detected */
        bool rc4Risk = false;
        if (info.Kerberos?.Warnings.Any(w => w.Message.Contains("RC4")) == true)
            rc4Risk = true;
        if (info.KerberosAuthTest is { UsesRc4: true })
            rc4Risk = true;
        if (info.KerberosAuthTest?.NegotiableEtypeNames?.Contains("RC4-HMAC") == true)
            rc4Risk = true;

        if (rc4Risk)
        {
            WriteRc4AdvisoryLinks();
        }
    }

    private static void ReportCertificate(CertificateInfo cert, string title)
    {
        WriteHeader(title);
        WriteField("Subject", cert.Subject);
        WriteField("Issuer", cert.Issuer);
        WriteField("Serial Number", cert.SerialNumber);
        WriteField("Thumbprint (SHA-1)", cert.ThumbprintSha1);
        WriteField("Fingerprint (SHA-256)", cert.ThumbprintSha256);
        WriteField("Valid From", $"{cert.ValidFrom:yyyy-MM-dd HH:mm:ss} UTC");
        WriteField("Valid To", FormatExpiry(cert));
        WriteField("Key Algorithm", $"{cert.KeyAlgorithm} ({cert.KeySizeBits} bits)");
        WriteField("Signature Algorithm", cert.SignatureAlgorithm);
        WriteField("Certificate Version", $"V{cert.Version}");
        WriteField("Self-Signed", cert.IsSelfSigned ? "Yes" : "No");
        WriteField("Is CA", cert.IsCA ? "Yes" : "No");

        if (cert.KeyUsage != null)
        {
            WriteField("Key Usage", cert.KeyUsage);
        }
        if (cert.EnhancedKeyUsage.Count > 0)
        {
            WriteField("Enhanced Key Usage", string.Join(", ", cert.EnhancedKeyUsage));
        }
        if (cert.SubjectAlternativeNames.Count > 0)
        {
            WriteField("SANs", string.Join(", ", cert.SubjectAlternativeNames));
        }
        else
        {
            WriteField("SANs", "(none)");
        }
    }

    private static void ReportWarnings(List<CertificateWarning> warnings)
    {
        WriteHeader("Certificate Health Checks");
        WriteWarningList(warnings);
    }

    private static void ReportKerberos(KerberosDiagnostics kerberos)
    {
        bool hasDnsData = kerberos.ResolvedIpAddresses.Count > 0 ||
                          kerberos.DnsError != null ||
                          kerberos.DnsRecordTypes.Count > 0;
        bool hasSpnData = kerberos.ExpectedSpns.Count > 0 ||
                          kerberos.SpnLookupError != null;

        if (hasDnsData)
        {
            WriteHeader("DNS Resolution");
            WriteField("Requested Hostname", kerberos.RequestedHostname);

            if (kerberos.DnsError != null)
            {
                WriteField("DNS Error", kerberos.DnsError);
            }
            else
            {
                if (kerberos.ResolvedFqdn != null)
                {
                    string fqdnDisplay = kerberos.ResolvedFqdn;
                    if (kerberos.DnsSuffixUsed != null)
                    {
                        fqdnDisplay += $"  (via DNS suffix: {kerberos.DnsSuffixUsed})";
                    }
                    WriteField("Resolved FQDN", fqdnDisplay);
                }

                if (kerberos.DnsRecordTypes.Count > 0)
                {
                    WriteField("Record Types", string.Join(", ", kerberos.DnsRecordTypes));
                }

                WriteField("Resolved IPs", kerberos.ResolvedIpAddresses.Count > 0
                    ? string.Join(", ", kerberos.ResolvedIpAddresses)
                    : "(none)");
                WriteField("Reverse Lookup", kerberos.ReverseHostname ?? "(not available)");
                WriteField("Forward/Reverse Match", kerberos.ForwardReverseMismatch ? "MISMATCH" : "OK");

                if (kerberos.CnameTarget != null)
                {
                    WriteField("CNAME Target", kerberos.CnameTarget);
                }
            }

            Console.WriteLine();
        }

        if (hasSpnData)
        {
            WriteHeader("Kerberos SPN Registration");

        if (kerberos.SpnLookupError != null)
        {
            WriteField("SPN Lookup Error", kerberos.SpnLookupError);
        }
        else
        {
            foreach (var expected in kerberos.ExpectedSpns)
            {
                string status;
                ConsoleColor color;
                if (expected.Result?.Found == true)
                {
                    string account = expected.Result.AccountName ?? "unknown";
                    string type = expected.Result.AccountType != null ? $" ({expected.Result.AccountType})" : "";
                    status = $"REGISTERED → {account}{type}";
                    color = ConsoleColor.Green;
                }
                else
                {
                    status = "NOT FOUND";
                    color = ConsoleColor.Yellow;
                }

                WriteFieldColored(expected.Label, expected.Spn, status, color);
            }

            /* Kerberos encryption types (CVE-2026-20833) */
            var firstFoundSpn = kerberos.ExpectedSpns
                .FirstOrDefault(s => s.Result?.Found == true);
            if (firstFoundSpn?.Result != null)
            {
                Console.WriteLine();
                int? etypes = firstFoundSpn.Result.SupportedEncryptionTypes;
                if (etypes == null)
                {
                    WriteFieldColored("Encryption Types",
                        "(msDS-SupportedEncryptionTypes not configured)",
                        "REVIEW — may default to RC4 (CVE-2026-20833)",
                        ConsoleColor.Yellow);
                }
                else
                {
                    var enabledTypes = new List<string>();
                    if ((etypes.Value & 0x1) != 0) enabledTypes.Add("DES-CBC-CRC");
                    if ((etypes.Value & 0x2) != 0) enabledTypes.Add("DES-CBC-MD5");
                    if ((etypes.Value & 0x4) != 0) enabledTypes.Add("RC4-HMAC");
                    if ((etypes.Value & 0x8) != 0) enabledTypes.Add("AES128");
                    if ((etypes.Value & 0x10) != 0) enabledTypes.Add("AES256");
                    if (enabledTypes.Count == 0) enabledTypes.Add("(none/default)");

                    bool hasRc4 = (etypes.Value & 0x4) != 0;
                    ConsoleColor etypeColor = hasRc4 ? ConsoleColor.Yellow : ConsoleColor.Green;
                    WriteFieldColored("Encryption Types",
                        $"0x{etypes.Value:X} ({string.Join(", ", enabledTypes)})",
                        hasRc4 ? "RC4 ENABLED — deprecated per CVE-2026-20833" : "OK",
                        etypeColor);
                }
            }

            /* SAN SPN coverage (--full-spn-diagnostics) */
            if (kerberos.SanSpnCoverage is { Count: > 0 })
            {
                Console.WriteLine();
                WriteHeader("SAN SPN Coverage");
                foreach (var sanSpn in kerberos.SanSpnCoverage)
                {
                    string status;
                    ConsoleColor color;
                    if (sanSpn.Found)
                    {
                        string account = sanSpn.AccountName ?? "unknown";
                        string type = sanSpn.AccountType != null ? $" ({sanSpn.AccountType})" : "";
                        status = $"REGISTERED → {account}{type}";
                        color = ConsoleColor.Green;
                    }
                    else
                    {
                        status = "NOT FOUND";
                        color = ConsoleColor.Yellow;
                    }

                    WriteFieldColored(sanSpn.SanHostname, sanSpn.Spn, status, color);
                }
            }

            /* CNAME target SPNs — shown when the requested hostname is a CNAME */
            if (kerberos.CnameTargetSpns is { Count: > 0 })
            {
                Console.WriteLine();
                WriteHeader($"CNAME Target SPN Registration ({kerberos.CnameTarget})");
                foreach (var expected in kerberos.CnameTargetSpns)
                {
                    string status;
                    ConsoleColor color;
                    if (expected.Result?.Found == true)
                    {
                        string account = expected.Result.AccountName ?? "unknown";
                        string type = expected.Result.AccountType != null ? $" ({expected.Result.AccountType})" : "";
                        status = $"REGISTERED → {account}{type}";
                        color = ConsoleColor.Green;
                    }
                    else
                    {
                        status = "NOT FOUND";
                        color = ConsoleColor.Yellow;
                    }

                    WriteFieldColored(expected.Label, expected.Spn, status, color);
                }
            }
        }
        } /* end if (hasSpnData) */

        if (kerberos.Warnings.Count > 0)
        {
            Console.WriteLine();
            WriteHeader("Kerberos Health Checks");
            WriteWarningList(kerberos.Warnings);

            if (kerberos.SuggestedSetspnCommands.Count > 0)
            {
                Console.WriteLine();
                WriteColored("  To register the missing SPN(s), run:", ConsoleColor.White);
                Console.WriteLine();
                foreach (string cmd in kerberos.SuggestedSetspnCommands)
                {
                    WriteColored($"    {cmd}", ConsoleColor.White);
                    Console.WriteLine();
                }
            }
        }
        else if (hasDnsData || hasSpnData)
        {
            Console.WriteLine();
            WriteColored("[PASS] No diagnostic issues detected.", ConsoleColor.Green);
            Console.WriteLine();
        }
    }

    private static void WriteFieldColored(string label, string spn, string status, ConsoleColor statusColor)
    {
        string paddedLabel = $"  {label,-25}";
        if (_colorsEnabled)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(paddedLabel);
            Console.ResetColor();
            Console.Write($" {spn}  ");
            Console.ForegroundColor = statusColor;
            Console.Write(status);
            Console.ResetColor();
            Console.WriteLine();
        }
        else
        {
            Console.WriteLine($"{paddedLabel} {spn}  {status}");
        }
    }

    private static void WriteWarningList(IEnumerable<KerberosWarning> warnings)
    {
        foreach (var warning in warnings)
        {
            WriteWarningLine(warning.Severity, warning.Message);
        }
    }

    private static void WriteWarningList(List<CertificateWarning> warnings)
    {
        foreach (var warning in warnings)
        {
            WriteWarningLine(warning.Severity, warning.Message);
        }
    }

    private static void WriteWarningLine(WarningSeverity severity, string message)
    {
        string icon = severity switch
        {
            WarningSeverity.Error => "[FAIL]",
            WarningSeverity.Warning => "[WARN]",
            WarningSeverity.Info => "[INFO]",
            _ => "?"
        };
        ConsoleColor color = severity switch
        {
            WarningSeverity.Error => ConsoleColor.Red,
            WarningSeverity.Warning => ConsoleColor.Yellow,
            WarningSeverity.Info => ConsoleColor.Cyan,
            _ => ConsoleColor.Gray
        };
        WriteColored($"  {icon} {message}", color);
        Console.WriteLine();
    }

    private static string FormatExpiry(CertificateInfo cert)
    {
        string expiry = $"{cert.ValidTo:yyyy-MM-dd HH:mm:ss} UTC";
        if (cert.DaysUntilExpiry < 0)
        {
            expiry += $" (EXPIRED {Math.Abs(cert.DaysUntilExpiry)} days ago)";
        }
        else
        {
            expiry += $" ({cert.DaysUntilExpiry} days remaining)";
        }
        return expiry;
    }

    private static string FormatKeyExchange(ConnectionSecurityInfo info)
    {
        if (info.KeyExchangeAlgorithm == null || info.KeyExchangeAlgorithm == "None" || info.KeyExchangeAlgorithm == "0")
        {
            return "N/A (TLS 1.3 — key exchange is implicit)";
        }

        string name = MapKeyExchangeAlgorithm(info.KeyExchangeAlgorithm);
        return info.KeyExchangeStrength > 0
            ? $"{name} ({info.KeyExchangeStrength} bits)"
            : name;
    }

    private static string FormatHash(ConnectionSecurityInfo info)
    {
        if (info.HashAlgorithm == null || info.HashAlgorithm == "None" || info.HashAlgorithm == "0")
        {
            return "N/A (TLS 1.3 — hash is part of cipher suite)";
        }

        string name = MapHashAlgorithm(info.HashAlgorithm);
        return info.HashStrength > 0
            ? $"{name} ({info.HashStrength} bits)"
            : name;
    }

    /// <summary>
    /// Maps raw ExchangeAlgorithmType values to human-readable names.
    /// .NET returns numeric values for algorithms not in the enum.
    /// </summary>
    private static string MapKeyExchangeAlgorithm(string raw) => raw switch
    {
        "44550" => "ECDHE",
        "41984" => "RSA",
        "43522" => "DH",
        "9216"  => "RSA (signature)",
        _       => raw
    };

    private static string MapHashAlgorithm(string raw) => raw switch
    {
        "Sha1"   => "SHA-1",
        "Sha256" => "SHA-256",
        "Sha384" => "SHA-384",
        "Sha512" => "SHA-512",
        "Md5"    => "MD5",
        _        => raw
    };

    private static void ReportSanConnectivity(List<SanConnectivityResult> results)
    {
        WriteHeader("SAN Connectivity Tests");

        foreach (var result in results)
        {
            if (!result.Connected)
            {
                WriteFieldColored("SAN", result.SanHostname,
                    $"FAILED — {result.Error}", ConsoleColor.Red);
            }
            else if (result.SameCertificate)
            {
                WriteFieldColored("SAN", result.SanHostname,
                    "OK — same certificate", ConsoleColor.Green);
            }
            else
            {
                string certSubject = result.SecurityInfo?.Certificate?.Subject ?? "(no cert)";
                WriteFieldColored("SAN", result.SanHostname,
                    $"DIFFERENT CERT — {certSubject}", ConsoleColor.Yellow);
            }

            /* Show key differences for connected SANs */
            if (result.Connected && result.SecurityInfo != null)
            {
                var si = result.SecurityInfo;
                if (!result.SameCertificate && si.Certificate != null)
                {
                    WriteField("    Subject", si.Certificate.Subject);
                    WriteField("    Thumbprint", si.Certificate.ThumbprintSha256[..16] + "...");
                    WriteField("    Valid To", $"{si.Certificate.ValidTo:yyyy-MM-dd} ({si.Certificate.DaysUntilExpiry} days)");
                }
                if (si.TlsProtocolVersion != null)
                {
                    WriteField("    TLS Version", si.TlsProtocolVersion);
                }
                if (!si.IsEncrypted)
                {
                    WriteColored("    [WARN] Connection via this SAN is NOT encrypted.", ConsoleColor.Yellow);
                    Console.WriteLine();
                }
            }
        }
    }

    private static void WriteHeader(string title)
    {
        WriteColored($"═══ {title} ═══", ConsoleColor.Cyan);
        Console.WriteLine();
    }

    private static void WriteField(string label, string value)
    {
        string paddedLabel = $"  {label,-25}";
        if (_colorsEnabled)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(paddedLabel);
            Console.ResetColor();
            Console.WriteLine($" {value}");
        }
        else
        {
            Console.WriteLine($"{paddedLabel} {value}");
        }
    }

    private static void WriteColored(string text, ConsoleColor color)
    {
        if (_colorsEnabled)
        {
            Console.ForegroundColor = color;
            Console.Write(text);
            Console.ResetColor();
        }
        else
        {
            Console.Write(text);
        }
    }

    private static void WriteRc4AdvisoryLinks()
    {
        Console.WriteLine();
        WriteField("Advisory", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20833");
        WriteField("", "https://nvd.nist.gov/vuln/detail/CVE-2026-20833");
        WriteField("Mitigation", "https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d");
    }

    private static void ReportKerberosAuthTest(KerberosAuthResult authResult)
    {
        WriteHeader("Kerberos Authentication Test");
        WriteField("Target SPN", authResult.Spn);

        if (!authResult.Success)
        {
            WriteFieldColored("Result", "FAILED", authResult.Error ?? "Unknown error", ConsoleColor.Red);
            return;
        }

        WriteField("Protocol", authResult.Protocol ?? "Unknown");

        if (authResult.FellBackToNtlm)
        {
            WriteFieldColored("Result", "NTLM FALLBACK",
                "Kerberos was not used — check SPN registration and client TGT",
                ConsoleColor.Yellow);
        }
        else
        {
            if (authResult.KerberosEtype != null)
            {
                string etypeName = authResult.KerberosEtypeName ?? $"Unknown ({authResult.KerberosEtype})";
                WriteField("Ticket Etype", $"{authResult.KerberosEtype} ({etypeName})");

                if (authResult.UsesRc4)
                {
                    WriteFieldColored("RC4 Status", "IN USE",
                        "RC4-HMAC (etype 23) - deprecated per CVE-2026-20833",
                        ConsoleColor.Red);
                }
                else
                {
                    WriteFieldColored("RC4 Status", "Not in use", "OK", ConsoleColor.Green);
                }
            }

            /* Etype cross-reference: client vs service account */
            if (authResult.ClientEtypeNames is { Count: > 0 })
            {
                string clientLabel = authResult.ClientSupportedEtypes != null
                    ? $"0x{authResult.ClientSupportedEtypes:X2}"
                    : "default (0x1C)";
                WriteField("Client Etypes",
                    $"{string.Join(", ", authResult.ClientEtypeNames)} [{clientLabel}]");
            }

            if (authResult.ServiceAccountEtypes != null)
            {
                var svcNames = KerberosAuthResult.BitmaskToNames(authResult.ServiceAccountEtypes.Value);
                WriteField("Service Acct Etypes",
                    $"{string.Join(", ", svcNames)} [0x{authResult.ServiceAccountEtypes:X2}]");
            }
            else
            {
                WriteField("Service Acct Etypes", "(not configured in AD)");
            }

            if (authResult.NegotiableEtypeNames is { Count: > 0 })
            {
                bool intersectionHasRc4 = authResult.NegotiableEtypeNames.Contains("RC4-HMAC");
                if (intersectionHasRc4)
                {
                    WriteFieldColored("Negotiable Etypes",
                        string.Join(", ", authResult.NegotiableEtypeNames),
                        "RC4-HMAC is negotiable - remove from client or service account",
                        ConsoleColor.Yellow);
                }
                else
                {
                    WriteFieldColored("Negotiable Etypes",
                        string.Join(", ", authResult.NegotiableEtypeNames), "OK",
                        ConsoleColor.Green);
                }
            }
            else if (authResult.NegotiableEtypeNames is { Count: 0 })
            {
                WriteFieldColored("Negotiable Etypes", "NONE",
                    "No common encryption types between client and service account",
                    ConsoleColor.Red);
            }

            WriteColored("[PASS] Kerberos authentication succeeded.", ConsoleColor.Green);
            Console.WriteLine();
        }
    }
}
