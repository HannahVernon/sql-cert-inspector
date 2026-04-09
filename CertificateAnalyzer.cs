using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SqlCertInspector;

/// <summary>
/// Extracts detailed information from an X.509 certificate and performs health checks.
/// </summary>
public static class CertificateAnalyzer
{
    private const int MinRsaKeySize = 2048;
    private const int MinEccKeySize = 256;
    private const int ExpiryWarningDays = 30;

    public static CertificateInfo Analyze(X509Certificate2 cert, string serverHost, bool showFullChain)
    {
        var info = ExtractCertDetails(cert);

        RunHealthChecks(info, serverHost);

        if (showFullChain)
        {
            info.ChainCertificates = BuildChain(cert, info.ChainStatusMessages);
        }

        return info;
    }

    private static CertificateInfo ExtractCertDetails(X509Certificate2 cert)
    {
        var info = new CertificateInfo
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            SerialNumber = cert.SerialNumber,
            ThumbprintSha1 = cert.Thumbprint,
            ThumbprintSha256 = ComputeSha256Thumbprint(cert),
            ValidFrom = cert.NotBefore,
            ValidTo = cert.NotAfter,
            DaysUntilExpiry = (int)(cert.NotAfter - DateTime.UtcNow).TotalDays,
            SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "Unknown",
            Version = cert.Version,
            IsSelfSigned = cert.Subject == cert.Issuer
        };

        /* Key algorithm and size */
        var publicKey = cert.PublicKey;
        info.KeyAlgorithm = publicKey.Oid.FriendlyName ?? publicKey.Oid.Value ?? "Unknown";

        if (cert.GetRSAPublicKey() is RSA rsa)
        {
            info.KeySizeBits = rsa.KeySize;
        }
        else if (cert.GetECDsaPublicKey() is ECDsa ecdsa)
        {
            info.KeySizeBits = ecdsa.KeySize;
        }
        else if (cert.GetDSAPublicKey() is DSA dsa)
        {
            info.KeySizeBits = dsa.KeySize;
        }

        /* Subject Alternative Names */
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509SubjectAlternativeNameExtension sanExt)
            {
                foreach (var dns in sanExt.EnumerateDnsNames())
                {
                    info.SubjectAlternativeNames.Add($"DNS:{dns}");
                }
                foreach (var ip in sanExt.EnumerateIPAddresses())
                {
                    info.SubjectAlternativeNames.Add($"IP:{ip}");
                }
            }
            else if (ext is X509KeyUsageExtension kuExt)
            {
                info.KeyUsage = kuExt.KeyUsages.ToString();
            }
            else if (ext is X509EnhancedKeyUsageExtension ekuExt)
            {
                foreach (var oid in ekuExt.EnhancedKeyUsages)
                {
                    info.EnhancedKeyUsage.Add(oid.FriendlyName ?? oid.Value ?? "Unknown");
                }
            }
            else if (ext is X509BasicConstraintsExtension bcExt)
            {
                info.IsCA = bcExt.CertificateAuthority;
            }
        }

        return info;
    }

    internal static void RunHealthChecks(CertificateInfo info, string serverHost)
    {
        /* Expired */
        if (info.ValidTo < DateTime.UtcNow)
        {
            info.Warnings.Add(new CertificateWarning(WarningSeverity.Error,
                $"Certificate EXPIRED on {info.ValidTo:yyyy-MM-dd} ({Math.Abs(info.DaysUntilExpiry)} days ago)."));
        }
        else if (info.DaysUntilExpiry <= ExpiryWarningDays)
        {
            info.Warnings.Add(new CertificateWarning(WarningSeverity.Warning,
                $"Certificate expires in {info.DaysUntilExpiry} days (on {info.ValidTo:yyyy-MM-dd})."));
        }

        /* Not yet valid */
        if (info.ValidFrom > DateTime.UtcNow)
        {
            info.Warnings.Add(new CertificateWarning(WarningSeverity.Warning,
                $"Certificate is not yet valid. Valid from {info.ValidFrom:yyyy-MM-dd}."));
        }

        /* Self-signed */
        if (info.IsSelfSigned)
        {
            info.Warnings.Add(new CertificateWarning(WarningSeverity.Warning,
                "Certificate is self-signed (Issuer matches Subject)."));
        }

        /* Hostname mismatch */
        if (!HostnameMatchesCertificate(serverHost, info))
        {
            info.Warnings.Add(new CertificateWarning(WarningSeverity.Warning,
                $"Hostname '{serverHost}' does not match the certificate's CN or SANs."));
        }

        /* Weak key size */
        string keyAlgUpper = info.KeyAlgorithm.ToUpperInvariant();
        if (keyAlgUpper.Contains("RSA") && info.KeySizeBits < MinRsaKeySize)
        {
            info.Warnings.Add(new CertificateWarning(WarningSeverity.Warning,
                $"Weak RSA key size: {info.KeySizeBits} bits (minimum recommended: {MinRsaKeySize})."));
        }
        else if (keyAlgUpper.Contains("EC") && info.KeySizeBits < MinEccKeySize)
        {
            info.Warnings.Add(new CertificateWarning(WarningSeverity.Warning,
                $"Weak ECC key size: {info.KeySizeBits} bits (minimum recommended: {MinEccKeySize})."));
        }

        /* Deprecated signature algorithm */
        string sigAlgUpper = info.SignatureAlgorithm.ToUpperInvariant();
        if (sigAlgUpper.Contains("SHA1") || sigAlgUpper.Contains("SHA-1"))
        {
            info.Warnings.Add(new CertificateWarning(WarningSeverity.Warning,
                $"Deprecated signature algorithm: {info.SignatureAlgorithm}. SHA-1 is considered insecure."));
        }
        else if (sigAlgUpper.Contains("MD5"))
        {
            info.Warnings.Add(new CertificateWarning(WarningSeverity.Error,
                $"Insecure signature algorithm: {info.SignatureAlgorithm}. MD5 is broken."));
        }
    }

    internal static bool HostnameMatchesCertificate(string host, CertificateInfo info)
    {
        /* Check CN in Subject */
        string cn = ExtractCN(info.Subject);
        if (!string.IsNullOrEmpty(cn) && MatchesHostname(host, cn))
        {
            return true;
        }

        /* Check SANs */
        foreach (string san in info.SubjectAlternativeNames)
        {
            string sanValue = san;
            if (san.StartsWith("DNS:", StringComparison.OrdinalIgnoreCase))
            {
                sanValue = san[4..];
            }
            else if (san.StartsWith("IP:", StringComparison.OrdinalIgnoreCase))
            {
                sanValue = san[3..];
            }

            if (MatchesHostname(host, sanValue))
            {
                return true;
            }
        }

        return false;
    }

    internal static string ExtractCN(string subject)
    {
        /* Parse "CN=something, O=..." */
        foreach (string part in subject.Split(','))
        {
            string trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed[3..].Trim();
            }
        }
        return string.Empty;
    }

    internal static bool MatchesHostname(string host, string pattern)
    {
        if (string.Equals(host, pattern, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        /* Wildcard matching: *.example.com matches foo.example.com */
        if (pattern.StartsWith("*."))
        {
            string suffix = pattern[1..]; /* .example.com */
            int dotIndex = host.IndexOf('.');
            if (dotIndex >= 0)
            {
                string hostSuffix = host[dotIndex..];
                return string.Equals(hostSuffix, suffix, StringComparison.OrdinalIgnoreCase);
            }
        }

        return false;
    }

    private static string ComputeSha256Thumbprint(X509Certificate2 cert)
    {
        byte[] hash = SHA256.HashData(cert.RawData);
        return Convert.ToHexString(hash);
    }

    private static List<CertificateInfo> BuildChain(
        X509Certificate2 cert, List<string> statusMessages)
    {
        var chainCerts = new List<CertificateInfo>();

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;

        chain.Build(cert);

        foreach (var element in chain.ChainElements)
        {
            chainCerts.Add(ExtractCertDetails(element.Certificate));
            foreach (var cs in element.ChainElementStatus)
            {
                statusMessages.Add($"{element.Certificate.Subject}: {cs.StatusInformation}");
            }
        }

        return chainCerts;
    }
}
