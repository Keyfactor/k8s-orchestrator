using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.Orchestrator.K8S.Utilities;

/// <summary>
/// Certificate format enumeration
/// </summary>
public enum CertificateFormat
{
    Unknown,
    Pem,
    Der,
    Pkcs12
}

/// <summary>
/// Utility class providing BouncyCastle-based implementations for certificate operations.
/// This class replaces X509Certificate2 usage to avoid deprecated APIs and ensure cross-platform compatibility.
/// </summary>
public static class CertificateUtilities
{
    #region Certificate Parsing

    /// <summary>
    /// Parse a certificate from byte array data, automatically detecting the format
    /// </summary>
    /// <param name="certData">Certificate data bytes</param>
    /// <param name="format">Optional format hint. If Unknown, format will be auto-detected</param>
    /// <returns>Parsed X509Certificate</returns>
    public static X509Certificate ParseCertificate(byte[] certData, CertificateFormat format = CertificateFormat.Unknown)
    {
        if (certData == null || certData.Length == 0)
            throw new ArgumentException("Certificate data cannot be null or empty", nameof(certData));

        if (format == CertificateFormat.Unknown)
            format = DetectFormat(certData);

        return format switch
        {
            CertificateFormat.Pem => ParseCertificateFromPem(Encoding.UTF8.GetString(certData)),
            CertificateFormat.Der => ParseCertificateFromDer(certData),
            CertificateFormat.Pkcs12 => throw new ArgumentException(
                "Use ParseCertificateFromPkcs12 for PKCS12 format certificates"),
            _ => throw new ArgumentException($"Unknown certificate format: {format}")
        };
    }

    /// <summary>
    /// Parse a certificate from PEM string
    /// </summary>
    /// <param name="pemString">PEM-encoded certificate string</param>
    /// <returns>Parsed X509Certificate</returns>
    public static X509Certificate ParseCertificateFromPem(string pemString)
    {
        if (string.IsNullOrWhiteSpace(pemString))
            throw new ArgumentException("PEM string cannot be null or empty", nameof(pemString));

        using var reader = new StringReader(pemString);
        var pemReader = new PemReader(reader);
        var pemObject = pemReader.ReadPemObject();

        if (pemObject == null || pemObject.Type != "CERTIFICATE")
            throw new ArgumentException("Invalid PEM certificate format");

        var certificateParser = new X509CertificateParser();
        return certificateParser.ReadCertificate(pemObject.Content);
    }

    /// <summary>
    /// Parse a certificate from DER-encoded bytes
    /// </summary>
    /// <param name="derBytes">DER-encoded certificate bytes</param>
    /// <returns>Parsed X509Certificate</returns>
    public static X509Certificate ParseCertificateFromDer(byte[] derBytes)
    {
        if (derBytes == null || derBytes.Length == 0)
            throw new ArgumentException("DER bytes cannot be null or empty", nameof(derBytes));

        var certificateParser = new X509CertificateParser();
        return certificateParser.ReadCertificate(derBytes);
    }

    /// <summary>
    /// Parse a certificate from a PKCS12/PFX store
    /// </summary>
    /// <param name="pkcs12Bytes">PKCS12 store bytes</param>
    /// <param name="password">Store password</param>
    /// <param name="alias">Optional alias. If null, first key entry will be used</param>
    /// <returns>Parsed X509Certificate</returns>
    public static X509Certificate ParseCertificateFromPkcs12(byte[] pkcs12Bytes, string password, string alias = null)
    {
        if (pkcs12Bytes == null || pkcs12Bytes.Length == 0)
            throw new ArgumentException("PKCS12 bytes cannot be null or empty", nameof(pkcs12Bytes));

        var store = LoadPkcs12Store(pkcs12Bytes, password);

        if (string.IsNullOrEmpty(alias))
            alias = store.Aliases.FirstOrDefault(a => store.IsKeyEntry(a));

        if (alias == null)
            throw new ArgumentException("No key entry found in PKCS12 store");

        var certEntry = store.GetCertificate(alias);
        return certEntry?.Certificate;
    }

    #endregion

    #region Certificate Properties

    /// <summary>
    /// Get the certificate thumbprint (SHA-1 hash of DER-encoded certificate)
    /// </summary>
    /// <param name="cert">Certificate</param>
    /// <returns>Uppercase hexadecimal string representation of SHA-1 hash</returns>
    public static string GetThumbprint(X509Certificate cert)
    {
        if (cert == null)
            throw new ArgumentNullException(nameof(cert));

        using var sha1 = SHA1.Create();
        var hash = sha1.ComputeHash(cert.GetEncoded());
        return BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
    }

    /// <summary>
    /// Get the Common Name (CN) from the certificate subject
    /// </summary>
    /// <param name="cert">Certificate</param>
    /// <returns>Subject Common Name or empty string if not found</returns>
    public static string GetSubjectCN(X509Certificate cert)
    {
        if (cert == null)
            throw new ArgumentNullException(nameof(cert));

        var subject = cert.SubjectDN;
        var oids = subject.GetOidList();
        var values = subject.GetValueList();

        for (var i = 0; i < oids.Count; i++)
        {
            if (oids[i].ToString() == X509Name.CN.Id)
                return values[i].ToString();
        }

        return string.Empty;
    }

    /// <summary>
    /// Get the full subject Distinguished Name
    /// </summary>
    /// <param name="cert">Certificate</param>
    /// <returns>Subject DN string</returns>
    public static string GetSubjectDN(X509Certificate cert)
    {
        if (cert == null)
            throw new ArgumentNullException(nameof(cert));

        return cert.SubjectDN.ToString();
    }

    /// <summary>
    /// Get the Common Name (CN) from the certificate issuer
    /// </summary>
    /// <param name="cert">Certificate</param>
    /// <returns>Issuer Common Name or empty string if not found</returns>
    public static string GetIssuerCN(X509Certificate cert)
    {
        if (cert == null)
            throw new ArgumentNullException(nameof(cert));

        var issuer = cert.IssuerDN;
        var oids = issuer.GetOidList();
        var values = issuer.GetValueList();

        for (var i = 0; i < oids.Count; i++)
        {
            if (oids[i].ToString() == X509Name.CN.Id)
                return values[i].ToString();
        }

        return string.Empty;
    }

    /// <summary>
    /// Get the full issuer Distinguished Name
    /// </summary>
    /// <param name="cert">Certificate</param>
    /// <returns>Issuer DN string</returns>
    public static string GetIssuerDN(X509Certificate cert)
    {
        if (cert == null)
            throw new ArgumentNullException(nameof(cert));

        return cert.IssuerDN.ToString();
    }

    /// <summary>
    /// Get the certificate validity start date
    /// </summary>
    /// <param name="cert">Certificate</param>
    /// <returns>NotBefore date</returns>
    public static DateTime GetNotBefore(X509Certificate cert)
    {
        if (cert == null)
            throw new ArgumentNullException(nameof(cert));

        return cert.NotBefore;
    }

    /// <summary>
    /// Get the certificate validity end date
    /// </summary>
    /// <param name="cert">Certificate</param>
    /// <returns>NotAfter date</returns>
    public static DateTime GetNotAfter(X509Certificate cert)
    {
        if (cert == null)
            throw new ArgumentNullException(nameof(cert));

        return cert.NotAfter;
    }

    /// <summary>
    /// Get the certificate serial number
    /// </summary>
    /// <param name="cert">Certificate</param>
    /// <returns>Serial number as hexadecimal string</returns>
    public static string GetSerialNumber(X509Certificate cert)
    {
        if (cert == null)
            throw new ArgumentNullException(nameof(cert));

        return cert.SerialNumber.ToString(16).ToUpperInvariant();
    }

    /// <summary>
    /// Get the public key algorithm name
    /// </summary>
    /// <param name="cert">Certificate</param>
    /// <returns>Algorithm name: "RSA", "ECDSA", "DSA", or "Unknown"</returns>
    public static string GetKeyAlgorithm(X509Certificate cert)
    {
        if (cert == null)
            throw new ArgumentNullException(nameof(cert));

        var publicKey = cert.GetPublicKey();

        return publicKey switch
        {
            RsaKeyParameters => "RSA",
            ECPublicKeyParameters => "ECDSA",
            DsaPublicKeyParameters => "DSA",
            _ => "Unknown"
        };
    }

    /// <summary>
    /// Get the public key bytes
    /// </summary>
    /// <param name="cert">Certificate</param>
    /// <returns>Public key bytes</returns>
    public static byte[] GetPublicKey(X509Certificate cert)
    {
        if (cert == null)
            throw new ArgumentNullException(nameof(cert));

        var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(cert.GetPublicKey());
        return publicKeyInfo.GetEncoded();
    }

    #endregion

    #region Private Key Operations

    /// <summary>
    /// Extract private key from PKCS12 store
    /// </summary>
    /// <param name="store">PKCS12 store</param>
    /// <param name="alias">Key alias. If null, first key entry will be used</param>
    /// <param name="password">Key password (may differ from store password)</param>
    /// <returns>Private key parameter</returns>
    public static AsymmetricKeyParameter ExtractPrivateKey(Pkcs12Store store, string alias = null, string password = null)
    {
        if (store == null)
            throw new ArgumentNullException(nameof(store));

        if (string.IsNullOrEmpty(alias))
            alias = store.Aliases.FirstOrDefault(a => store.IsKeyEntry(a));

        if (alias == null)
            throw new ArgumentException("No key entry found in PKCS12 store");

        if (!store.IsKeyEntry(alias))
            throw new ArgumentException($"Alias '{alias}' does not have a private key entry");

        var keyEntry = store.GetKey(alias);
        return keyEntry?.Key;
    }

    /// <summary>
    /// Extract private key as PEM string
    /// </summary>
    /// <param name="privateKey">Private key parameter</param>
    /// <param name="keyType">Key type for PEM header (e.g., "RSA PRIVATE KEY", "EC PRIVATE KEY"). If null, will be auto-detected.</param>
    /// <returns>PEM-encoded private key</returns>
    public static string ExtractPrivateKeyAsPem(AsymmetricKeyParameter privateKey, string keyType = null)
    {
        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));

        if (string.IsNullOrEmpty(keyType))
        {
            keyType = privateKey switch
            {
                RsaPrivateCrtKeyParameters => "RSA PRIVATE KEY",
                ECPrivateKeyParameters => "EC PRIVATE KEY",
                DsaPrivateKeyParameters => "DSA PRIVATE KEY",
                _ => throw new ArgumentException("Unsupported private key type")
            };
        }

        using var stringWriter = new StringWriter();
        var pemWriter = new PemWriter(stringWriter);
        var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
        var privateKeyBytes = privateKeyInfo.ToAsn1Object().GetEncoded();
        var pemObject = new PemObject(keyType, privateKeyBytes);
        pemWriter.WriteObject(pemObject);
        pemWriter.Writer.Flush();

        return stringWriter.ToString();
    }

    /// <summary>
    /// Export private key in PKCS#8 format
    /// </summary>
    /// <param name="privateKey">Private key parameter</param>
    /// <returns>PKCS#8 encoded private key bytes</returns>
    public static byte[] ExportPrivateKeyPkcs8(AsymmetricKeyParameter privateKey)
    {
        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));

        var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
        return privateKeyInfo.ToAsn1Object().GetEncoded();
    }

    /// <summary>
    /// Get the private key algorithm type
    /// </summary>
    /// <param name="privateKey">Private key parameter</param>
    /// <returns>Key type: "RSA", "EC", "DSA", or "Unknown"</returns>
    public static string GetPrivateKeyType(AsymmetricKeyParameter privateKey)
    {
        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));

        return privateKey switch
        {
            RsaPrivateCrtKeyParameters => "RSA",
            ECPrivateKeyParameters => "EC",
            DsaPrivateKeyParameters => "DSA",
            _ => "Unknown"
        };
    }

    #endregion

    #region Chain Operations

    /// <summary>
    /// Load certificate chain from PEM data
    /// </summary>
    /// <param name="pemData">PEM data containing multiple certificates</param>
    /// <returns>List of certificates in order</returns>
    public static List<X509Certificate> LoadCertificateChain(string pemData)
    {
        if (string.IsNullOrWhiteSpace(pemData))
            return new List<X509Certificate>();

        var pemReader = new PemReader(new StringReader(pemData));
        var certificates = new List<X509Certificate>();

        PemObject pemObject;
        while ((pemObject = pemReader.ReadPemObject()) != null)
        {
            if (pemObject.Type == "CERTIFICATE")
            {
                var certificateParser = new X509CertificateParser();
                var certificate = certificateParser.ReadCertificate(pemObject.Content);
                certificates.Add(certificate);
            }
        }

        return certificates;
    }

    /// <summary>
    /// Extract certificate chain from PKCS12 store
    /// </summary>
    /// <param name="pkcs12Bytes">PKCS12 store bytes</param>
    /// <param name="password">Store password</param>
    /// <param name="alias">Optional alias. If null, first key entry will be used</param>
    /// <returns>List of certificates in chain order</returns>
    public static List<X509Certificate> ExtractChainFromPkcs12(byte[] pkcs12Bytes, string password, string alias = null)
    {
        if (pkcs12Bytes == null || pkcs12Bytes.Length == 0)
            throw new ArgumentException("PKCS12 bytes cannot be null or empty", nameof(pkcs12Bytes));

        var store = LoadPkcs12Store(pkcs12Bytes, password);

        if (string.IsNullOrEmpty(alias))
            alias = store.Aliases.FirstOrDefault(a => store.IsKeyEntry(a));

        if (alias == null)
            return new List<X509Certificate>();

        var chain = store.GetCertificateChain(alias);
        return chain?.Select(entry => entry.Certificate).ToList() ?? new List<X509Certificate>();
    }

    #endregion

    #region Format Detection and Conversion

    /// <summary>
    /// Detect the certificate format from byte array data
    /// </summary>
    /// <param name="data">Certificate data bytes</param>
    /// <returns>Detected format</returns>
    public static CertificateFormat DetectFormat(byte[] data)
    {
        if (data == null || data.Length == 0)
            return CertificateFormat.Unknown;

        // Check for PEM format (starts with "-----BEGIN")
        var header = Encoding.UTF8.GetString(data.Take(Math.Min(30, data.Length)).ToArray());
        if (header.Contains("-----BEGIN"))
            return CertificateFormat.Pem;

        // Check for PKCS12 format (starts with 0x30 0x82 or 0x30 0x80)
        if (data.Length >= 2 && data[0] == 0x30 && (data[1] == 0x82 || data[1] == 0x80 || data[1] == 0x84))
        {
            // Try to parse as DER certificate first
            try
            {
                var parser = new X509CertificateParser();
                parser.ReadCertificate(data);
                return CertificateFormat.Der;
            }
            catch
            {
                // If DER parsing fails, it might be PKCS12
                try
                {
                    var storeBuilder = new Pkcs12StoreBuilder();
                    var store = storeBuilder.Build();
                    using var ms = new MemoryStream(data);
                    store.Load(ms, Array.Empty<char>());
                    return CertificateFormat.Pkcs12;
                }
                catch
                {
                    return CertificateFormat.Unknown;
                }
            }
        }

        return CertificateFormat.Unknown;
    }

    /// <summary>
    /// Convert certificate to PEM format
    /// </summary>
    /// <param name="cert">Certificate</param>
    /// <returns>PEM-encoded certificate string</returns>
    public static string ConvertToPem(X509Certificate cert)
    {
        if (cert == null)
            throw new ArgumentNullException(nameof(cert));

        var pemObject = new PemObject("CERTIFICATE", cert.GetEncoded());
        using var stringWriter = new StringWriter();
        var pemWriter = new PemWriter(stringWriter);
        pemWriter.WriteObject(pemObject);
        pemWriter.Writer.Flush();
        return stringWriter.ToString();
    }

    /// <summary>
    /// Convert certificate to DER format
    /// </summary>
    /// <param name="cert">Certificate</param>
    /// <returns>DER-encoded certificate bytes</returns>
    public static byte[] ConvertToDer(X509Certificate cert)
    {
        if (cert == null)
            throw new ArgumentNullException(nameof(cert));

        return cert.GetEncoded();
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Load a PKCS12 store from bytes
    /// </summary>
    /// <param name="pkcs12Data">PKCS12 store bytes</param>
    /// <param name="password">Store password</param>
    /// <returns>Loaded PKCS12 store</returns>
    public static Pkcs12Store LoadPkcs12Store(byte[] pkcs12Data, string password)
    {
        if (pkcs12Data == null || pkcs12Data.Length == 0)
            throw new ArgumentException("PKCS12 data cannot be null or empty", nameof(pkcs12Data));

        var storeBuilder = new Pkcs12StoreBuilder();
        var store = storeBuilder.Build();

        using var ms = new MemoryStream(pkcs12Data);
        var passwordChars = string.IsNullOrEmpty(password) ? Array.Empty<char>() : password.ToCharArray();
        store.Load(ms, passwordChars);

        return store;
    }

    /// <summary>
    /// Check if data is in DER format
    /// </summary>
    /// <param name="data">Data bytes</param>
    /// <returns>True if DER format</returns>
    public static bool IsDerFormat(byte[] data)
    {
        try
        {
            var parser = new X509CertificateParser();
            parser.ReadCertificate(data);
            return true;
        }
        catch
        {
            return false;
        }
    }

    #endregion
}
