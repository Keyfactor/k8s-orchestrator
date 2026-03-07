// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.Orchestrator.K8S.Clients;

/// <summary>
/// Provides certificate parsing, conversion, and chain operations.
/// Delegates to <see cref="CertificateUtilities"/> for core logic.
/// </summary>
public class CertificateOperations
{
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of CertificateOperations.
    /// </summary>
    /// <param name="logger">Logger instance for diagnostic output. If null, creates a default logger.</param>
    public CertificateOperations(ILogger logger = null)
    {
        _logger = logger ?? LogHandler.GetClassLogger<CertificateOperations>();
    }

    /// <summary>
    /// Reads a DER-encoded certificate from a base64 string.
    /// </summary>
    /// <param name="derString">Base64-encoded DER certificate data.</param>
    /// <returns>Parsed X509Certificate object.</returns>
    public X509Certificate ReadDerCertificate(string derString)
    {
        _logger.MethodEntry(LogLevel.Debug);
        var derData = Convert.FromBase64String(derString);
        var cert = CertificateUtilities.ParseCertificateFromDer(derData);
        _logger.LogDebug("Parsed DER certificate: {Summary}", LoggingUtilities.GetCertificateSummary(cert));
        _logger.MethodExit(LogLevel.Debug);
        return cert;
    }

    /// <summary>
    /// Reads a PEM-encoded certificate from a string.
    /// Returns null if the input is not a valid certificate (unlike <see cref="CertificateUtilities.ParseCertificateFromPem"/> which throws).
    /// </summary>
    /// <param name="pemString">PEM-encoded certificate string.</param>
    /// <returns>Parsed X509Certificate object, or null if not a valid certificate.</returns>
    public X509Certificate ReadPemCertificate(string pemString)
    {
        _logger.MethodEntry(LogLevel.Debug);
        try
        {
            var cert = CertificateUtilities.ParseCertificateFromPem(pemString);
            _logger.LogDebug("Parsed PEM certificate: {Summary}", LoggingUtilities.GetCertificateSummary(cert));
            _logger.MethodExit(LogLevel.Debug);
            return cert;
        }
        catch
        {
            _logger.LogDebug("PEM object is not a valid certificate, returning null");
            _logger.MethodExit(LogLevel.Debug);
            return null;
        }
    }

    /// <summary>
    /// Loads a certificate chain from PEM data containing multiple certificates.
    /// </summary>
    /// <param name="pemData">PEM string potentially containing multiple certificates.</param>
    /// <returns>List of parsed X509Certificate objects.</returns>
    public List<X509Certificate> LoadCertificateChain(string pemData)
    {
        _logger.MethodEntry(LogLevel.Debug);
        var certificates = CertificateUtilities.LoadCertificateChain(pemData);
        _logger.LogDebug("Loaded {Count} certificates from chain", certificates.Count);
        _logger.MethodExit(LogLevel.Debug);
        return certificates;
    }

    /// <summary>
    /// Converts a BouncyCastle X509Certificate to PEM format.
    /// </summary>
    /// <param name="certificate">The certificate to convert.</param>
    /// <returns>PEM-formatted certificate string.</returns>
    public string ConvertToPem(X509Certificate certificate)
    {
        _logger.MethodEntry(LogLevel.Debug);
        var pem = CertificateUtilities.ConvertToPem(certificate);
        _logger.MethodExit(LogLevel.Debug);
        return pem;
    }

    /// <summary>
    /// Extracts a private key from a PKCS12 store and converts it to PEM format.
    /// Supports RSA, EC, Ed25519, and Ed448 private keys.
    /// </summary>
    /// <param name="store">The PKCS12 store containing the private key.</param>
    /// <param name="password">Password for the store (currently unused, key is already decrypted).</param>
    /// <param name="format">The desired PEM format (PKCS1 or PKCS8). Defaults to PKCS8.</param>
    /// <returns>PEM-formatted private key string.</returns>
    /// <exception cref="Exception">Thrown when no private key is found or key type is unsupported.</exception>
    public string ExtractPrivateKeyAsPem(Pkcs12Store store, string password, PrivateKeyFormat format = PrivateKeyFormat.Pkcs8)
    {
        _logger.MethodEntry(LogLevel.Debug);

        var privateKey = CertificateUtilities.ExtractPrivateKey(store);
        var keyTypeName = PrivateKeyFormatUtilities.GetAlgorithmName(privateKey);
        _logger.LogDebug("Private key type: {KeyType}, requested format: {Format}", keyTypeName, format);

        var pem = PrivateKeyFormatUtilities.ExportPrivateKeyAsPem(privateKey, format);

        _logger.LogTrace("Private key: {Key}", LoggingUtilities.RedactPrivateKeyPem(pem));
        _logger.MethodExit(LogLevel.Debug);
        return pem;
    }

    /// <summary>
    /// Parses a certificate from PEM string using BouncyCastle.
    /// </summary>
    /// <param name="pemCertificate">PEM-encoded certificate string.</param>
    /// <returns>Parsed X509Certificate object.</returns>
    public X509Certificate ParseCertificateFromPem(string pemCertificate)
    {
        _logger.MethodEntry(LogLevel.Debug);
        var cert = CertificateUtilities.ParseCertificateFromPem(pemCertificate);
        _logger.LogDebug("Parsed certificate: {Summary}", LoggingUtilities.GetCertificateSummary(cert));
        _logger.MethodExit(LogLevel.Debug);
        return cert;
    }

    /// <summary>
    /// Parses a certificate from DER bytes using BouncyCastle.
    /// </summary>
    /// <param name="derBytes">DER-encoded certificate bytes.</param>
    /// <returns>Parsed X509Certificate object.</returns>
    public X509Certificate ParseCertificateFromDer(byte[] derBytes)
    {
        _logger.MethodEntry(LogLevel.Debug);
        var cert = CertificateUtilities.ParseCertificateFromDer(derBytes);
        _logger.LogDebug("Parsed certificate: {Summary}", LoggingUtilities.GetCertificateSummary(cert));
        _logger.MethodExit(LogLevel.Debug);
        return cert;
    }
}
