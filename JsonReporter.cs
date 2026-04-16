using System.Reflection;
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

    private static readonly string s_toolVersion =
        typeof(JsonReporter).Assembly
            .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ?? "unknown";

    /// <summary>
    /// Generates the JSON report string without writing it anywhere.
    /// </summary>
    public static string GenerateJson(ConnectionSecurityInfo info)
    {
        var output = BuildOutput(info);
        return JsonSerializer.Serialize(output, s_options);
    }

    public static void Report(ConnectionSecurityInfo info)
    {
        Console.WriteLine(GenerateJson(info));
    }

    private static JsonOutput BuildOutput(ConnectionSecurityInfo info)
    {
        var output = new JsonOutput
        {
            Meta = new MetaJson
            {
                ToolVersion = s_toolVersion,
                Timestamp = DateTime.UtcNow,
                Target = info.ServerName
            },
            Connection = new ConnectionJson
            {
                ServerName = info.ServerName,
                ResolvedHost = info.ResolvedHost,
                ResolvedPort = info.ResolvedPort,
                ResolvedIPs = info.ResolvedIPs,
                ConnectedIP = info.ConnectedIP,
                ResolvedHostname = info.ResolvedHostname,
                InstanceName = info.InstanceName,
                SqlServerVersion = info.SqlServerVersion,
                EncryptionMode = info.EncryptionMode,
                IsEncrypted = info.IsEncrypted,
                TdsProtocol = info.TdsProtocol.ToDisplayString(),
                UsedFallback = info.UsedFallback ? true : null
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

        /* Kerberos diagnostics */
        if (info.Kerberos != null)
        {
            output.Kerberos = new KerberosJson
            {
                Dns = new DnsJson
                {
                    RequestedHostname = info.Kerberos.RequestedHostname,
                    ResolvedFqdn = info.Kerberos.ResolvedFqdn,
                    DnsRecordTypes = info.Kerberos.DnsRecordTypes.Count > 0 ? info.Kerberos.DnsRecordTypes : null,
                    ResolvedIpAddresses = info.Kerberos.ResolvedIpAddresses.Count > 0 ? info.Kerberos.ResolvedIpAddresses : null,
                    ReverseHostname = info.Kerberos.ReverseHostname,
                    ForwardReverseMismatch = info.Kerberos.ForwardReverseMismatch,
                    CnameTarget = info.Kerberos.CnameTarget,
                    DnsError = info.Kerberos.DnsError
                },
                Spns = info.Kerberos.ExpectedSpns.Select(e => new SpnJson
                {
                    Label = e.Label,
                    Spn = e.Spn,
                    Found = e.Result?.Found ?? false,
                    AccountName = e.Result?.AccountName,
                    AccountType = e.Result?.AccountType
                }).ToList(),
                SpnLookupError = info.Kerberos.SpnLookupError,
                Warnings = info.Kerberos.Warnings.Count > 0
                    ? info.Kerberos.Warnings.Select(w => new WarningJson { Severity = w.Severity.ToString(), Message = w.Message }).ToList()
                    : null
            };
        }

        return output;
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
        public MetaJson Meta { get; set; } = new();
        public ConnectionJson Connection { get; set; } = new();
        public TlsJson? Tls { get; set; }
        public CertificateJson? Certificate { get; set; }
        public List<WarningJson>? Warnings { get; set; }
        public List<CertificateJson>? CertificateChain { get; set; }
        public List<string>? ChainValidation { get; set; }
        public KerberosJson? Kerberos { get; set; }
    }

    private sealed class MetaJson
    {
        public string ToolVersion { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string Target { get; set; } = string.Empty;
    }

    private sealed class ConnectionJson
    {
        public string ServerName { get; set; } = string.Empty;
        public string ResolvedHost { get; set; } = string.Empty;
        public int ResolvedPort { get; set; }
        public string[]? ResolvedIPs { get; set; }
        public string? ConnectedIP { get; set; }
        public string? ResolvedHostname { get; set; }
        public string? InstanceName { get; set; }
        public string? SqlServerVersion { get; set; }
        public string? EncryptionMode { get; set; }
        public bool IsEncrypted { get; set; }
        public string? TdsProtocol { get; set; }
        public bool? UsedFallback { get; set; }
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

    private sealed class KerberosJson
    {
        public DnsJson? Dns { get; set; }
        public List<SpnJson> Spns { get; set; } = new();
        public string? SpnLookupError { get; set; }
        public List<WarningJson>? Warnings { get; set; }
    }

    private sealed class DnsJson
    {
        public string RequestedHostname { get; set; } = string.Empty;
        public string? ResolvedFqdn { get; set; }
        public List<string>? DnsRecordTypes { get; set; }
        public List<string>? ResolvedIpAddresses { get; set; }
        public string? ReverseHostname { get; set; }
        public bool ForwardReverseMismatch { get; set; }
        public string? CnameTarget { get; set; }
        public string? DnsError { get; set; }
    }

    private sealed class SpnJson
    {
        public string Label { get; set; } = string.Empty;
        public string Spn { get; set; } = string.Empty;
        public bool Found { get; set; }
        public string? AccountName { get; set; }
        public string? AccountType { get; set; }
    }
}
