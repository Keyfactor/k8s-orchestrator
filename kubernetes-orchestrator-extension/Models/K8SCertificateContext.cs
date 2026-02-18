using System;
using System.Collections.Generic;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.Orchestrator.K8S.Models;

/// <summary>
/// Certificate context wrapper that provides BouncyCastle-based certificate operations.
/// This class replaces X509Certificate2-dependent functionality to avoid deprecated APIs.
/// </summary>
public class K8SCertificateContext
{
    /// <summary>
    /// The BouncyCastle X509Certificate
    /// </summary>
    public X509Certificate Certificate { get; set; }

    /// <summary>
    /// The private key (if available)
    /// </summary>
    public AsymmetricKeyParameter PrivateKey { get; set; }

    /// <summary>
    /// Certificate chain (excluding the leaf certificate)
    /// </summary>
    public List<X509Certificate> Chain { get; set; } = new List<X509Certificate>();

    /// <summary>
    /// Certificate thumbprint (SHA-1 hash, uppercase hex)
    /// </summary>
    public string Thumbprint => Certificate != null
        ? CertificateUtilities.GetThumbprint(Certificate)
        : string.Empty;

    /// <summary>
    /// Certificate subject Common Name
    /// </summary>
    public string SubjectCN => Certificate != null
        ? CertificateUtilities.GetSubjectCN(Certificate)
        : string.Empty;

    /// <summary>
    /// Certificate subject Distinguished Name
    /// </summary>
    public string SubjectDN => Certificate != null
        ? CertificateUtilities.GetSubjectDN(Certificate)
        : string.Empty;

    /// <summary>
    /// Certificate issuer Common Name
    /// </summary>
    public string IssuerCN => Certificate != null
        ? CertificateUtilities.GetIssuerCN(Certificate)
        : string.Empty;

    /// <summary>
    /// Certificate issuer Distinguished Name
    /// </summary>
    public string IssuerDN => Certificate != null
        ? CertificateUtilities.GetIssuerDN(Certificate)
        : string.Empty;

    /// <summary>
    /// Certificate validity start date
    /// </summary>
    public DateTime NotBefore => Certificate?.NotBefore ?? DateTime.MinValue;

    /// <summary>
    /// Certificate validity end date
    /// </summary>
    public DateTime NotAfter => Certificate?.NotAfter ?? DateTime.MaxValue;

    /// <summary>
    /// Certificate serial number
    /// </summary>
    public string SerialNumber => Certificate != null
        ? CertificateUtilities.GetSerialNumber(Certificate)
        : string.Empty;

    /// <summary>
    /// Public key algorithm (RSA, ECDSA, DSA)
    /// </summary>
    public string KeyAlgorithm => Certificate != null
        ? CertificateUtilities.GetKeyAlgorithm(Certificate)
        : string.Empty;

    /// <summary>
    /// Indicates whether a private key is present
    /// </summary>
    public bool HasPrivateKey => PrivateKey != null;

    /// <summary>
    /// PEM representation of the certificate
    /// </summary>
    public string CertPem
    {
        get => _certPem ?? (Certificate != null ? CertificateUtilities.ConvertToPem(Certificate) : string.Empty);
        set => _certPem = value;
    }
    private string _certPem;

    /// <summary>
    /// PEM representation of the private key
    /// </summary>
    public string PrivateKeyPem
    {
        get => _privateKeyPem ?? (PrivateKey != null ? CertificateUtilities.ExtractPrivateKeyAsPem(PrivateKey) : string.Empty);
        set => _privateKeyPem = value;
    }
    private string _privateKeyPem;

    /// <summary>
    /// PEM representations of certificates in the chain
    /// </summary>
    public List<string> ChainPem
    {
        get => _chainPem ?? (Chain?.Select(CertificateUtilities.ConvertToPem).ToList() ?? new List<string>());
        set => _chainPem = value;
    }
    private List<string> _chainPem;

    #region Factory Methods

    /// <summary>
    /// Create context from PKCS12/PFX data
    /// </summary>
    /// <param name="pkcs12Bytes">PKCS12 store bytes</param>
    /// <param name="password">Store password</param>
    /// <param name="alias">Optional alias. If null, first key entry will be used</param>
    /// <returns>Certificate context</returns>
    public static K8SCertificateContext FromPkcs12(byte[] pkcs12Bytes, string password, string alias = null)
    {
        if (pkcs12Bytes == null || pkcs12Bytes.Length == 0)
            throw new ArgumentException("PKCS12 bytes cannot be null or empty", nameof(pkcs12Bytes));

        var store = CertificateUtilities.LoadPkcs12Store(pkcs12Bytes, password);

        if (string.IsNullOrEmpty(alias))
            alias = store.Aliases.FirstOrDefault(a => store.IsKeyEntry(a));

        if (alias == null)
            throw new ArgumentException("No key entry found in PKCS12 store");

        var context = new K8SCertificateContext
        {
            Certificate = CertificateUtilities.ParseCertificateFromPkcs12(pkcs12Bytes, password, alias),
            PrivateKey = CertificateUtilities.ExtractPrivateKey(store, alias, password)
        };

        // Extract chain (excluding the leaf certificate)
        var fullChain = CertificateUtilities.ExtractChainFromPkcs12(pkcs12Bytes, password, alias);
        if (fullChain != null && fullChain.Count > 1)
        {
            context.Chain = fullChain.Skip(1).ToList(); // Skip the first one (leaf cert)
        }

        return context;
    }

    /// <summary>
    /// Create context from PKCS12 store
    /// </summary>
    /// <param name="store">PKCS12 store</param>
    /// <param name="alias">Optional alias. If null, first key entry will be used</param>
    /// <param name="password">Optional password for key extraction</param>
    /// <returns>Certificate context</returns>
    public static K8SCertificateContext FromPkcs12Store(Pkcs12Store store, string alias = null, string password = null)
    {
        if (store == null)
            throw new ArgumentNullException(nameof(store));

        if (string.IsNullOrEmpty(alias))
            alias = store.Aliases.FirstOrDefault(a => store.IsKeyEntry(a));

        if (alias == null)
            throw new ArgumentException("No key entry found in PKCS12 store");

        var context = new K8SCertificateContext
        {
            Certificate = store.GetCertificate(alias)?.Certificate,
            PrivateKey = store.GetKey(alias)?.Key
        };

        // Extract chain (excluding the leaf certificate)
        var fullChain = store.GetCertificateChain(alias);
        if (fullChain != null && fullChain.Length > 1)
        {
            context.Chain = fullChain.Skip(1).Select(entry => entry.Certificate).ToList();
        }

        return context;
    }

    /// <summary>
    /// Create context from PEM string (certificate only, no private key)
    /// </summary>
    /// <param name="pemString">PEM-encoded certificate string</param>
    /// <returns>Certificate context</returns>
    public static K8SCertificateContext FromPem(string pemString)
    {
        if (string.IsNullOrWhiteSpace(pemString))
            throw new ArgumentException("PEM string cannot be null or empty", nameof(pemString));

        // Try to load multiple certificates (chain)
        var certificates = CertificateUtilities.LoadCertificateChain(pemString);

        if (certificates == null || certificates.Count == 0)
            throw new ArgumentException("No valid certificates found in PEM data");

        var context = new K8SCertificateContext
        {
            Certificate = certificates[0],
            PrivateKey = null // PEM certificate data typically doesn't include private key
        };

        // If multiple certificates, treat the rest as chain
        if (certificates.Count > 1)
        {
            context.Chain = certificates.Skip(1).ToList();
        }

        return context;
    }

    /// <summary>
    /// Create context from PEM certificate and private key strings
    /// </summary>
    /// <param name="certPem">PEM-encoded certificate</param>
    /// <param name="privateKeyPem">PEM-encoded private key</param>
    /// <param name="chainPem">Optional PEM-encoded certificate chain</param>
    /// <returns>Certificate context</returns>
    public static K8SCertificateContext FromPemWithKey(string certPem, string privateKeyPem, string chainPem = null)
    {
        if (string.IsNullOrWhiteSpace(certPem))
            throw new ArgumentException("Certificate PEM cannot be null or empty", nameof(certPem));

        var context = new K8SCertificateContext
        {
            Certificate = CertificateUtilities.ParseCertificateFromPem(certPem),
            _certPem = certPem,
            _privateKeyPem = privateKeyPem
        };

        // Parse private key if provided
        if (!string.IsNullOrWhiteSpace(privateKeyPem))
        {
            // Note: Parsing private key from PEM requires additional logic
            // This is a placeholder for now - will be implemented when needed
            // For now, we'll store the PEM string
        }

        // Parse chain if provided
        if (!string.IsNullOrWhiteSpace(chainPem))
        {
            context.Chain = CertificateUtilities.LoadCertificateChain(chainPem);
            context._chainPem = context.Chain.Select(CertificateUtilities.ConvertToPem).ToList();
        }

        return context;
    }

    /// <summary>
    /// Create context from DER-encoded bytes
    /// </summary>
    /// <param name="derBytes">DER-encoded certificate bytes</param>
    /// <returns>Certificate context</returns>
    public static K8SCertificateContext FromDer(byte[] derBytes)
    {
        if (derBytes == null || derBytes.Length == 0)
            throw new ArgumentException("DER bytes cannot be null or empty", nameof(derBytes));

        return new K8SCertificateContext
        {
            Certificate = CertificateUtilities.ParseCertificateFromDer(derBytes),
            PrivateKey = null // DER format typically doesn't include private key
        };
    }

    /// <summary>
    /// Create context from X509Certificate and optional private key
    /// </summary>
    /// <param name="certificate">BouncyCastle X509Certificate</param>
    /// <param name="privateKey">Optional private key</param>
    /// <param name="chain">Optional certificate chain</param>
    /// <returns>Certificate context</returns>
    public static K8SCertificateContext FromCertificate(
        X509Certificate certificate,
        AsymmetricKeyParameter privateKey = null,
        List<X509Certificate> chain = null)
    {
        if (certificate == null)
            throw new ArgumentNullException(nameof(certificate));

        return new K8SCertificateContext
        {
            Certificate = certificate,
            PrivateKey = privateKey,
            Chain = chain ?? new List<X509Certificate>()
        };
    }

    #endregion

    #region Export Methods

    /// <summary>
    /// Export certificate as PEM string
    /// </summary>
    /// <returns>PEM-encoded certificate</returns>
    public string ExportCertificatePem()
    {
        if (Certificate == null)
            throw new InvalidOperationException("No certificate available to export");

        return CertificateUtilities.ConvertToPem(Certificate);
    }

    /// <summary>
    /// Export certificate as DER bytes
    /// </summary>
    /// <returns>DER-encoded certificate</returns>
    public byte[] ExportCertificateDer()
    {
        if (Certificate == null)
            throw new InvalidOperationException("No certificate available to export");

        return CertificateUtilities.ConvertToDer(Certificate);
    }

    /// <summary>
    /// Export private key as PKCS#8 bytes
    /// </summary>
    /// <returns>PKCS#8 encoded private key</returns>
    public byte[] ExportPrivateKeyPkcs8()
    {
        if (PrivateKey == null)
            throw new InvalidOperationException("No private key available to export");

        return CertificateUtilities.ExportPrivateKeyPkcs8(PrivateKey);
    }

    /// <summary>
    /// Export private key as PEM string
    /// </summary>
    /// <returns>PEM-encoded private key</returns>
    public string ExportPrivateKeyPem()
    {
        if (PrivateKey == null)
            throw new InvalidOperationException("No private key available to export");

        return CertificateUtilities.ExtractPrivateKeyAsPem(PrivateKey);
    }

    #endregion
}
