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
        WriteField("Resolved Port", info.ResolvedPort.ToString());
        if (info.InstanceName != null)
        {
            WriteField("Instance Name", info.InstanceName);
        }
        if (info.SqlServerVersion != null)
        {
            WriteField("SQL Server Version", info.SqlServerVersion);
        }
        WriteField("Encryption Mode", info.EncryptionMode ?? "Unknown");
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
            ReportCertificate(info.Certificate, "Server Certificate");

            if (info.Certificate.ChainCertificates is { Count: > 0 } chain)
            {
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
        WriteHeader("DNS Resolution");
        WriteField("Requested Hostname", kerberos.RequestedHostname);

        if (kerberos.DnsError != null)
        {
            WriteField("DNS Error", kerberos.DnsError);
        }
        else
        {
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
        WriteHeader("Kerberos SPN Registration");
        WriteField("Expected SPN (port)", kerberos.ExpectedSpnWithPort);
        WriteField("Expected SPN (base)", kerberos.ExpectedSpnWithoutPort);

        if (kerberos.SpnLookupError != null)
        {
            WriteField("SPN Lookup Error", kerberos.SpnLookupError);
        }
        else
        {
            if (kerberos.SpnWithPort != null)
            {
                ReportSpn(kerberos.SpnWithPort, "Port SPN");
            }
            if (kerberos.SpnWithoutPort != null)
            {
                ReportSpn(kerberos.SpnWithoutPort, "Base SPN");
            }
        }

        if (kerberos.Warnings.Count > 0)
        {
            Console.WriteLine();
            WriteHeader("Kerberos Health Checks");
            WriteWarningList(kerberos.Warnings);
        }
        else
        {
            Console.WriteLine();
            WriteColored("[PASS] No Kerberos issues detected.", ConsoleColor.Green);
            Console.WriteLine();
        }
    }

    private static void ReportSpn(SpnLookupResult spn, string label)
    {
        if (spn.Found)
        {
            WriteColored($"  {label,-25} ", ConsoleColor.DarkGray);
            WriteColored("REGISTERED", ConsoleColor.Green);
            string account = spn.AccountName != null
                ? $" → {spn.AccountName} ({spn.AccountType})"
                : "";
            Console.WriteLine(account);
        }
        else
        {
            WriteColored($"  {label,-25} ", ConsoleColor.DarkGray);
            WriteColored("NOT FOUND", ConsoleColor.Yellow);
            Console.WriteLine();
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
}
