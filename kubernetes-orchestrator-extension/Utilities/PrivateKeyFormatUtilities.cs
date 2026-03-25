using System;
using System.IO;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Utilities.IO.Pem;
using OpenSslPemWriter = Org.BouncyCastle.OpenSsl.PemWriter;

namespace Keyfactor.Extensions.Orchestrator.K8S.Utilities;

/// <summary>
/// Utility class for private key format detection and conversion between PKCS#1 and PKCS#8 formats.
/// </summary>
public static class PrivateKeyFormatUtilities
{
    private static readonly ILogger Logger = LogHandler.GetClassLogger(typeof(PrivateKeyFormatUtilities));

    // PEM delimiters for format detection
    private const string Pkcs8Header = "-----BEGIN PRIVATE KEY-----";
    private const string Pkcs8EncryptedHeader = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    private const string RsaPkcs1Header = "-----BEGIN RSA PRIVATE KEY-----";
    private const string EcPkcs1Header = "-----BEGIN EC PRIVATE KEY-----";
    private const string DsaPkcs1Header = "-----BEGIN DSA PRIVATE KEY-----";

    /// <summary>
    /// Detects the private key format from PEM data by examining the header.
    /// </summary>
    /// <param name="pemData">PEM-encoded private key data</param>
    /// <returns>Detected format (defaults to Pkcs8 if unable to detect)</returns>
    public static PrivateKeyFormat DetectFormat(string pemData)
    {
        Logger.LogTrace("DetectFormat called");

        if (string.IsNullOrWhiteSpace(pemData))
        {
            Logger.LogDebug("PEM data is null or empty, defaulting to PKCS8");
            return PrivateKeyFormat.Pkcs8;
        }

        // Check for PKCS#1 formats first (more specific)
        if (pemData.Contains(RsaPkcs1Header) ||
            pemData.Contains(EcPkcs1Header) ||
            pemData.Contains(DsaPkcs1Header))
        {
            Logger.LogDebug("Detected PKCS#1 format");
            return PrivateKeyFormat.Pkcs1;
        }

        // Check for PKCS#8 formats
        if (pemData.Contains(Pkcs8Header) || pemData.Contains(Pkcs8EncryptedHeader))
        {
            Logger.LogDebug("Detected PKCS#8 format");
            return PrivateKeyFormat.Pkcs8;
        }

        // Default to PKCS#8
        Logger.LogDebug("Unable to detect format, defaulting to PKCS8");
        return PrivateKeyFormat.Pkcs8;
    }

    /// <summary>
    /// Determines if the given private key algorithm supports PKCS#1 format.
    /// </summary>
    /// <param name="privateKey">The private key to check</param>
    /// <returns>True if PKCS#1 is supported (RSA, EC, DSA), false otherwise (Ed25519, Ed448)</returns>
    public static bool SupportsPkcs1(AsymmetricKeyParameter privateKey)
    {
        if (privateKey == null)
        {
            Logger.LogWarning("Private key is null, returning false for PKCS1 support");
            return false;
        }

        var supported = privateKey switch
        {
            RsaPrivateCrtKeyParameters => true,
            ECPrivateKeyParameters => true,
            DsaPrivateKeyParameters => true,
            Ed25519PrivateKeyParameters => false,
            Ed448PrivateKeyParameters => false,
            _ => false
        };

        Logger.LogTrace("SupportsPkcs1 for {KeyType}: {Supported}",
            privateKey.GetType().Name, supported);

        return supported;
    }

    /// <summary>
    /// Gets the algorithm name for a private key.
    /// </summary>
    /// <param name="privateKey">The private key</param>
    /// <returns>Algorithm name (RSA, EC, DSA, Ed25519, Ed448, or Unknown)</returns>
    public static string GetAlgorithmName(AsymmetricKeyParameter privateKey)
    {
        return privateKey switch
        {
            RsaPrivateCrtKeyParameters => "RSA",
            ECPrivateKeyParameters => "EC",
            DsaPrivateKeyParameters => "DSA",
            Ed25519PrivateKeyParameters => "Ed25519",
            Ed448PrivateKeyParameters => "Ed448",
            _ => "Unknown"
        };
    }

    /// <summary>
    /// Exports a private key as PKCS#1 PEM format.
    /// Uses BouncyCastle's PemWriter.WriteObject which outputs native PKCS#1/SEC1 format.
    /// </summary>
    /// <param name="privateKey">The private key to export</param>
    /// <returns>PEM-encoded private key in PKCS#1 format</returns>
    /// <exception cref="ArgumentNullException">If privateKey is null</exception>
    /// <exception cref="NotSupportedException">If key type doesn't support PKCS#1</exception>
    public static string ExportAsPkcs1Pem(AsymmetricKeyParameter privateKey)
    {
        Logger.LogTrace("ExportAsPkcs1Pem called");

        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));

        if (!SupportsPkcs1(privateKey))
        {
            var algorithm = GetAlgorithmName(privateKey);
            throw new NotSupportedException(
                $"PKCS#1 format is not supported for {algorithm} keys. Use PKCS#8 format instead.");
        }

        // BouncyCastle's OpenSsl.PemWriter.WriteObject() outputs native PKCS#1/SEC1 format
        // when given the raw key parameter object (RSA PRIVATE KEY, EC PRIVATE KEY, etc.)
        using var stringWriter = new StringWriter();
        var pemWriter = new OpenSslPemWriter(stringWriter);
        pemWriter.WriteObject(privateKey);
        pemWriter.Writer.Flush();

        var pem = stringWriter.ToString();
        Logger.LogTrace("Exported private key as PKCS#1 PEM");
        return pem;
    }

    /// <summary>
    /// Exports a private key as PKCS#8 PEM format.
    /// </summary>
    /// <param name="privateKey">The private key to export</param>
    /// <returns>PEM-encoded private key in PKCS#8 format</returns>
    /// <exception cref="ArgumentNullException">If privateKey is null</exception>
    public static string ExportAsPkcs8Pem(AsymmetricKeyParameter privateKey)
    {
        Logger.LogTrace("ExportAsPkcs8Pem called");

        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));

        // Wrap key in PKCS#8 PrivateKeyInfo structure
        var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
        var privateKeyBytes = privateKeyInfo.ToAsn1Object().GetEncoded();

        using var stringWriter = new StringWriter();
        var pemWriter = new PemWriter(stringWriter);
        var pemObject = new PemObject("PRIVATE KEY", privateKeyBytes);
        pemWriter.WriteObject(pemObject);
        pemWriter.Writer.Flush();

        var pem = stringWriter.ToString();
        Logger.LogTrace("Exported private key as PKCS#8 PEM");
        return pem;
    }

    /// <summary>
    /// Exports a private key as PEM in the specified format.
    /// If PKCS#1 is requested but not supported by the algorithm, falls back to PKCS#8.
    /// </summary>
    /// <param name="privateKey">The private key to export</param>
    /// <param name="format">Desired format</param>
    /// <returns>PEM-encoded private key</returns>
    /// <exception cref="ArgumentNullException">If privateKey is null</exception>
    public static string ExportPrivateKeyAsPem(AsymmetricKeyParameter privateKey, PrivateKeyFormat format)
    {
        Logger.LogTrace("ExportPrivateKeyAsPem called with format: {Format}", format);

        if (privateKey == null)
            throw new ArgumentNullException(nameof(privateKey));

        // If PKCS#1 requested but not supported, fall back to PKCS#8
        if (format == PrivateKeyFormat.Pkcs1 && !SupportsPkcs1(privateKey))
        {
            var algorithm = GetAlgorithmName(privateKey);
            Logger.LogWarning(
                "PKCS#1 format not supported for {Algorithm} keys, falling back to PKCS#8",
                algorithm);
            format = PrivateKeyFormat.Pkcs8;
        }

        return format switch
        {
            PrivateKeyFormat.Pkcs1 => ExportAsPkcs1Pem(privateKey),
            PrivateKeyFormat.Pkcs8 => ExportAsPkcs8Pem(privateKey),
            _ => ExportAsPkcs8Pem(privateKey)
        };
    }

    /// <summary>
    /// Parses a format string to PrivateKeyFormat enum.
    /// </summary>
    /// <param name="formatString">Format string ("PKCS1", "PKCS8", or null/empty for default)</param>
    /// <returns>Parsed format (defaults to Pkcs8)</returns>
    public static PrivateKeyFormat ParseFormat(string formatString)
    {
        if (string.IsNullOrWhiteSpace(formatString))
            return PrivateKeyFormat.Pkcs8;

        return formatString.Trim().ToUpperInvariant() switch
        {
            "PKCS1" => PrivateKeyFormat.Pkcs1,
            "PKCS8" => PrivateKeyFormat.Pkcs8,
            _ => PrivateKeyFormat.Pkcs8
        };
    }
}
