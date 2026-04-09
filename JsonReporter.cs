using System.Text.Json;
using System.Text.Json.Serialization;

namespace SqlCertInspector;

/// <summary>
/// Renders <see cref="ConnectionSecurityInfo"/> as JSON for machine-readable output.
/// </summary>
public static class JsonReporter
{
    private static readonly JsonSerializerOptions s_options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static void Report(ConnectionSecurityInfo info)
    {
        var output = new JsonOutput
        {
            Connection = new ConnectionJson
            {
                ServerName = info.ServerName,
                ResolvedHost = info.ResolvedHost,
                ResolvedPort = info.ResolvedPort,
                InstanceName = info.InstanceName,
                SqlServerVersion = info.SqlServerVersion,
                EncryptionMode = info.EncryptionMode,
                IsEncrypted = info.IsEncrypted
            }
        };

        if (info.IsEncrypted)
        {
            output.Tls = new TlsJson
            {
                Protocol = info.TlsProtocolVersion,
                CipherSuite = info.CipherSuite,
                KeyExchangeAlgorithm = MapKeyExchangeAlgorithm(info.KeyExchangeAlgorithm),
                KeyExchangeStrength = info.KeyExchangeStrength,
                HashAlgorithm = MapHashAlgorithm(info.HashAlgorithm),
                HashStrength = info.HashStrength
            };
        }

        if (info.Certificate != null)
        {
            output.Certificate = MapCertificate(info.Certificate);

            if (info.Certificate.Warnings.Count > 0)
            {
                output.Warnings = info.Certificate.Warnings
                    .Select(w => new WarningJson { Severity = w.Severity.ToString(), Message = w.Message })
                    .ToList();
            }

            if (info.Certificate.ChainCertificates is { Count: > 0 } chain)
            {
                output.CertificateChain = chain.Select(MapCertificate).ToList();
            }

            if (info.Certificate.ChainStatusMessages.Count > 0)
            {
                output.ChainValidation = info.Certificate.ChainStatusMessages;
            }
        }

        string json = JsonSerializer.Serialize(output, s_options);
        Console.WriteLine(json);
    }

    private static CertificateJson MapCertificate(CertificateInfo cert) => new()
    {
        Subject = cert.Subject,
        Issuer = cert.Issuer,
        SerialNumber = cert.SerialNumber,
        ThumbprintSha1 = cert.ThumbprintSha1,
        ThumbprintSha256 = cert.ThumbprintSha256,
        ValidFrom = cert.ValidFrom,
        ValidTo = cert.ValidTo,
        DaysUntilExpiry = cert.DaysUntilExpiry,
        KeyAlgorithm = cert.KeyAlgorithm,
        KeySizeBits = cert.KeySizeBits,
        SignatureAlgorithm = cert.SignatureAlgorithm,
        Version = cert.Version,
        IsSelfSigned = cert.IsSelfSigned,
        IsCA = cert.IsCA,
        KeyUsage = cert.KeyUsage,
        EnhancedKeyUsage = cert.EnhancedKeyUsage.Count > 0 ? cert.EnhancedKeyUsage : null,
        SubjectAlternativeNames = cert.SubjectAlternativeNames.Count > 0 ? cert.SubjectAlternativeNames : null
    };

    private static string? MapKeyExchangeAlgorithm(string? raw) => raw switch
    {
        "44550" => "ECDHE",
        "41984" => "RSA",
        "43522" => "DH",
        "9216"  => "RSA (signature)",
        _       => raw
    };

    private static string? MapHashAlgorithm(string? raw) => raw switch
    {
        "Sha1"   => "SHA-1",
        "Sha256" => "SHA-256",
        "Sha384" => "SHA-384",
        "Sha512" => "SHA-512",
        "Md5"    => "MD5",
        _        => raw
    };

    /* JSON shape classes */

    private sealed class JsonOutput
    {
        public ConnectionJson Connection { get; set; } = new();
        public TlsJson? Tls { get; set; }
        public CertificateJson? Certificate { get; set; }
        public List<WarningJson>? Warnings { get; set; }
        public List<CertificateJson>? CertificateChain { get; set; }
        public List<string>? ChainValidation { get; set; }
    }

    private sealed class ConnectionJson
    {
        public string ServerName { get; set; } = string.Empty;
        public string ResolvedHost { get; set; } = string.Empty;
        public int ResolvedPort { get; set; }
        public string? InstanceName { get; set; }
        public string? SqlServerVersion { get; set; }
        public string? EncryptionMode { get; set; }
        public bool IsEncrypted { get; set; }
    }

    private sealed class TlsJson
    {
        public string? Protocol { get; set; }
        public string? CipherSuite { get; set; }
        public string? KeyExchangeAlgorithm { get; set; }
        public int? KeyExchangeStrength { get; set; }
        public string? HashAlgorithm { get; set; }
        public int? HashStrength { get; set; }
    }

    private sealed class CertificateJson
    {
        public string Subject { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public string ThumbprintSha1 { get; set; } = string.Empty;
        public string ThumbprintSha256 { get; set; } = string.Empty;
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public int DaysUntilExpiry { get; set; }
        public string KeyAlgorithm { get; set; } = string.Empty;
        public int KeySizeBits { get; set; }
        public string SignatureAlgorithm { get; set; } = string.Empty;
        public int Version { get; set; }
        public bool IsSelfSigned { get; set; }
        public bool IsCA { get; set; }
        public string? KeyUsage { get; set; }
        public List<string>? EnhancedKeyUsage { get; set; }
        public List<string>? SubjectAlternativeNames { get; set; }
    }

    private sealed class WarningJson
    {
        public string Severity { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }
}
