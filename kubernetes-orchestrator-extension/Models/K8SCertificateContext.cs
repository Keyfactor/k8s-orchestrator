using System;
using System.Collections.Generic;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
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
    private static readonly ILogger Logger = LogHandler.GetClassLogger(typeof(K8SCertificateContext));

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
        Logger.LogTrace("FromPkcs12 called with {ByteCount} bytes, alias: {Alias}",
            pkcs12Bytes?.Length ?? 0, alias ?? "null");
        Logger.LogTrace("Password: {Password}", LoggingUtilities.RedactPassword(password));

        if (pkcs12Bytes == null || pkcs12Bytes.Length == 0)
        {
            Logger.LogError("PKCS12 bytes are null or empty");
            throw new ArgumentException("PKCS12 bytes cannot be null or empty", nameof(pkcs12Bytes));
        }

        try
        {
            var store = CertificateUtilities.LoadPkcs12Store(pkcs12Bytes, password);

            if (string.IsNullOrEmpty(alias))
            {
                alias = store.Aliases.FirstOrDefault(a => store.IsKeyEntry(a));
                Logger.LogDebug("No alias specified, using first key entry: {Alias}", alias ?? "null");
            }

            if (alias == null)
            {
                Logger.LogError("No key entry found in PKCS12 store");
                throw new ArgumentException("No key entry found in PKCS12 store");
            }

            var context = new K8SCertificateContext
            {
                Certificate = CertificateUtilities.ParseCertificateFromPkcs12(pkcs12Bytes, password, alias),
                PrivateKey = CertificateUtilities.ExtractPrivateKey(store, alias, password)
            };

            Logger.LogDebug("Certificate loaded: {Summary}", LoggingUtilities.GetCertificateSummary(context.Certificate));
            Logger.LogDebug("Private key present: {HasKey}", context.HasPrivateKey);

            // Extract chain (excluding the leaf certificate)
            var fullChain = CertificateUtilities.ExtractChainFromPkcs12(pkcs12Bytes, password, alias);
            if (fullChain != null && fullChain.Count > 1)
            {
                context.Chain = fullChain.Skip(1).ToList(); // Skip the first one (leaf cert)
                Logger.LogDebug("Certificate chain loaded: {Count} certificates", context.Chain.Count);
            }
            else
            {
                Logger.LogDebug("No certificate chain found or chain has only leaf certificate");
            }

            return context;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error creating context from PKCS12: {Message}", ex.Message);
            throw;
        }
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
        Logger.LogTrace("FromPem called with PEM length: {Length}", pemString?.Length ?? 0);

        if (string.IsNullOrWhiteSpace(pemString))
        {
            Logger.LogError("PEM string is null or empty");
            throw new ArgumentException("PEM string cannot be null or empty", nameof(pemString));
        }

        try
        {
            // Try to load multiple certificates (chain)
            var certificates = CertificateUtilities.LoadCertificateChain(pemString);

            if (certificates == null || certificates.Count == 0)
            {
                Logger.LogError("No valid certificates found in PEM data");
                throw new ArgumentException("No valid certificates found in PEM data");
            }

            Logger.LogDebug("Loaded {Count} certificates from PEM data", certificates.Count);

            var context = new K8SCertificateContext
            {
                Certificate = certificates[0],
                PrivateKey = null // PEM certificate data typically doesn't include private key
            };

            Logger.LogDebug("Certificate loaded: {Summary}", LoggingUtilities.GetCertificateSummary(context.Certificate));
            Logger.LogDebug("Private key present: {HasKey}", context.HasPrivateKey);

            // If multiple certificates, treat the rest as chain
            if (certificates.Count > 1)
            {
                context.Chain = certificates.Skip(1).ToList();
                Logger.LogDebug("Certificate chain loaded: {Count} certificates", context.Chain.Count);
            }

            return context;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error creating context from PEM: {Message}", ex.Message);
            throw;
        }
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
        Logger.LogTrace("FromPemWithKey called with cert PEM length: {CertLength}, key PEM length: {KeyLength}, chain PEM length: {ChainLength}",
            certPem?.Length ?? 0, privateKeyPem?.Length ?? 0, chainPem?.Length ?? 0);

        if (string.IsNullOrWhiteSpace(certPem))
        {
            Logger.LogError("Certificate PEM is null or empty");
            throw new ArgumentException("Certificate PEM cannot be null or empty", nameof(certPem));
        }

        try
        {
            var context = new K8SCertificateContext
            {
                Certificate = CertificateUtilities.ParseCertificateFromPem(certPem),
                _certPem = certPem,
                _privateKeyPem = privateKeyPem
            };

            Logger.LogDebug("Certificate loaded: {Summary}", LoggingUtilities.GetCertificateSummary(context.Certificate));

            // Parse private key if provided
            if (!string.IsNullOrWhiteSpace(privateKeyPem))
            {
                Logger.LogTrace("Private key PEM provided: {PrivateKeyPem}", LoggingUtilities.RedactPrivateKeyPem(privateKeyPem));
                // Note: Parsing private key from PEM requires additional logic
                // This is a placeholder for now - will be implemented when needed
                // For now, we'll store the PEM string
            }
            else
            {
                Logger.LogDebug("No private key PEM provided");
            }

            // Parse chain if provided
            if (!string.IsNullOrWhiteSpace(chainPem))
            {
                context.Chain = CertificateUtilities.LoadCertificateChain(chainPem);
                context._chainPem = context.Chain.Select(CertificateUtilities.ConvertToPem).ToList();
                Logger.LogDebug("Certificate chain loaded: {Count} certificates", context.Chain.Count);
            }
            else
            {
                Logger.LogDebug("No chain PEM provided");
            }

            return context;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error creating context from PEM with key: {Message}", ex.Message);
            throw;
        }
    }

    /// <summary>
    /// Create context from DER-encoded bytes
    /// </summary>
    /// <param name="derBytes">DER-encoded certificate bytes</param>
    /// <returns>Certificate context</returns>
    public static K8SCertificateContext FromDer(byte[] derBytes)
    {
        Logger.LogTrace("FromDer called with {ByteCount} bytes", derBytes?.Length ?? 0);

        if (derBytes == null || derBytes.Length == 0)
        {
            Logger.LogError("DER bytes are null or empty");
            throw new ArgumentException("DER bytes cannot be null or empty", nameof(derBytes));
        }

        try
        {
            var context = new K8SCertificateContext
            {
                Certificate = CertificateUtilities.ParseCertificateFromDer(derBytes),
                PrivateKey = null // DER format typically doesn't include private key
            };

            Logger.LogDebug("Certificate loaded: {Summary}", LoggingUtilities.GetCertificateSummary(context.Certificate));
            Logger.LogDebug("Private key present: {HasKey}", context.HasPrivateKey);

            return context;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error creating context from DER: {Message}", ex.Message);
            throw;
        }
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
        Logger.LogTrace("FromCertificate called");

        if (certificate == null)
        {
            Logger.LogError("Certificate is null");
            throw new ArgumentNullException(nameof(certificate));
        }

        var context = new K8SCertificateContext
        {
            Certificate = certificate,
            PrivateKey = privateKey,
            Chain = chain ?? new List<X509Certificate>()
        };

        Logger.LogDebug("Certificate loaded: {Summary}", LoggingUtilities.GetCertificateSummary(context.Certificate));
        Logger.LogDebug("Private key present: {HasKey}", context.HasPrivateKey);
        Logger.LogDebug("Certificate chain: {Count} certificates", context.Chain.Count);

        return context;
    }

    #endregion

    #region Export Methods

    /// <summary>
    /// Export certificate as PEM string
    /// </summary>
    /// <returns>PEM-encoded certificate</returns>
    public string ExportCertificatePem()
    {
        Logger.LogTrace("ExportCertificatePem called");

        if (Certificate == null)
        {
            Logger.LogError("No certificate available to export");
            throw new InvalidOperationException("No certificate available to export");
        }

        try
        {
            var pem = CertificateUtilities.ConvertToPem(Certificate);
            Logger.LogTrace("Certificate exported to PEM: {Pem}", LoggingUtilities.RedactCertificatePem(pem));
            return pem;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error exporting certificate to PEM: {Message}", ex.Message);
            throw;
        }
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
        Logger.LogTrace("ExportPrivateKeyPkcs8 called");

        if (PrivateKey == null)
        {
            Logger.LogError("No private key available to export");
            throw new InvalidOperationException("No private key available to export");
        }

        try
        {
            var pkcs8 = CertificateUtilities.ExportPrivateKeyPkcs8(PrivateKey);
            Logger.LogTrace("Private key exported to PKCS#8: {KeyBytes}", LoggingUtilities.RedactPrivateKeyBytes(pkcs8));
            return pkcs8;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error exporting private key to PKCS#8: {Message}", ex.Message);
            throw;
        }
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
