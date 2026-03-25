// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Logging;
using Keyfactor.PKI.Extensions;
using Keyfactor.PKI.PEM;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.Orchestrator.K8S.Services;

/// <summary>
/// Parses certificate data from job configuration into a K8SJobCertificate.
/// Handles PKCS12, DER, and PEM format detection and extraction.
/// </summary>
public class JobCertificateParser
{
    private readonly ILogger _logger;

    public JobCertificateParser(ILogger logger)
    {
        _logger = logger ?? LogHandler.GetClassLogger<JobCertificateParser>();
    }

    /// <summary>
    /// Parses certificate data from a management job configuration.
    /// </summary>
    /// <param name="config">The management job configuration.</param>
    /// <param name="includeCertChain">Whether to include the certificate chain.</param>
    /// <returns>A populated K8SJobCertificate.</returns>
    public K8SJobCertificate Parse(ManagementJobConfiguration config, bool includeCertChain)
    {
        _logger.LogDebug("Parsing job certificate data");

        var jobCert = new K8SJobCertificate();

        if (config.JobCertificate == null ||
            string.IsNullOrEmpty(config.JobCertificate.Contents))
        {
            _logger.LogWarning("Job certificate contents are null or empty");
            return jobCert;
        }

        string password = config.JobCertificate.PrivateKeyPassword ?? "";
        jobCert.Password = password;

        byte[] certBytes = Convert.FromBase64String(config.JobCertificate.Contents);
        _logger.LogDebug("Certificate data length: {Length} bytes", certBytes.Length);

        if (certBytes.Length == 0)
        {
            _logger.LogError("Certificate data is empty");
            return jobCert;
        }

        return DetectAndRoute(certBytes, password, jobCert, includeCertChain, config);
    }

    /// <summary>
    /// Detects certificate format and routes to the appropriate parser.
    /// Order: PKCS12 → PEM → DER → error.
    /// PEM is checked before DER because X509CertificateParser (used by IsDerFormat)
    /// can also parse PEM data, which would cause multi-cert PEM chains to be truncated.
    /// </summary>
    private K8SJobCertificate DetectAndRoute(byte[] certBytes, string password,
        K8SJobCertificate jobCert, bool includeCertChain, ManagementJobConfiguration config)
    {
        // Try PKCS12 first (most common format for certs with keys)
        var pkcs12Result = TryParsePkcs12(certBytes, password);
        if (pkcs12Result.HasValue)
        {
            return ParseFromPkcs12(pkcs12Result.Value.Store, pkcs12Result.Value.Alias,
                certBytes, password, jobCert, config);
        }

        // Check PEM format before DER — X509CertificateParser (used by IsDerFormat) can also
        // parse PEM data, so PEM must be detected first to handle multi-cert chains correctly.
        var dataStr = Encoding.UTF8.GetString(certBytes);
        if (dataStr.Contains("-----BEGIN CERTIFICATE-----"))
        {
            _logger.LogDebug("Certificate data is in PEM format");
            return ParsePemCertificate(dataStr, jobCert);
        }

        // Check DER format
        if (CertificateUtilities.IsDerFormat(certBytes))
        {
            _logger.LogDebug("Certificate data is in DER format (no private key)");
            return ParseDerCertificate(certBytes, jobCert, includeCertChain);
        }

        _logger.LogError("Failed to parse certificate data as PKCS12, DER, or PEM format");
        throw new InvalidOperationException(
            "Failed to parse certificate data. The data does not appear to be a valid PKCS12, DER, or PEM certificate.");
    }

    /// <summary>
    /// Attempts to parse data as PKCS12. Returns the store and alias if successful.
    /// </summary>
    private (Pkcs12Store Store, string Alias)? TryParsePkcs12(byte[] certBytes, string password)
    {
        try
        {
            var store = CertificateUtilities.LoadPkcs12Store(certBytes, password);
            var alias = store.Aliases.FirstOrDefault(store.IsKeyEntry);
            if (alias != null)
            {
                _logger.LogDebug("Successfully parsed as PKCS12 format, alias: {Alias}", alias);
                return (store, alias);
            }

            _logger.LogDebug("PKCS12 parsed but no key entry found");
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Not PKCS12 format: {Error}", ex.Message);
        }

        return null;
    }

    /// <summary>
    /// Extracts certificate, key, and chain from a PKCS12 store.
    /// </summary>
    private K8SJobCertificate ParseFromPkcs12(Pkcs12Store store, string alias,
        byte[] rawBytes, string password, K8SJobCertificate jobCert, ManagementJobConfiguration config)
    {
        _logger.LogDebug("Extracting certificate data from PKCS12 store");

        var x509Obj = store.GetCertificate(alias);
        if (x509Obj?.Certificate == null)
        {
            _logger.LogError("Unable to retrieve certificate from PKCS12 store");
            return jobCert;
        }

        var bcCert = x509Obj.Certificate;
        _logger.LogDebug("Certificate loaded: {Summary}", LoggingUtilities.GetCertificateSummary(bcCert));

        jobCert.CertPem = PemUtilities.DERToPEM(bcCert.GetEncoded(), PemUtilities.PemObjectType.Certificate);
        jobCert.CertBytes = bcCert.GetEncoded();
        jobCert.CertThumbprint = bcCert.Thumbprint();
        jobCert.Pkcs12 = rawBytes;
        jobCert.CertificateEntry = x509Obj;

        // Extract chain
        var chain = store.GetCertificateChain(alias);
        if (chain != null && chain.Length > 0)
        {
            _logger.LogDebug("Certificate chain: {Count} certificates", chain.Length);
            jobCert.CertificateEntryChain = chain;
            jobCert.ChainPem = chain.Select(c => PemUtilities.DERToPEM(c.Certificate.GetEncoded(), PemUtilities.PemObjectType.Certificate)).ToList();
        }

        // Extract private key
        ExtractPrivateKeyFromStore(store, alias, password, jobCert);

        jobCert.StorePassword = config.CertificateStoreDetails?.StorePassword;
        return jobCert;
    }

    /// <summary>
    /// Extracts the private key from a PKCS12 store and sets it on the job certificate.
    /// </summary>
    private void ExtractPrivateKeyFromStore(Pkcs12Store store, string alias,
        string password, K8SJobCertificate jobCert)
    {
        try
        {
            var keyEntry = store.GetKey(alias);
            if (keyEntry?.Key == null)
            {
                _logger.LogDebug("No private key found for alias '{Alias}'", alias);
                return;
            }

            var privateKey = keyEntry.Key;
            jobCert.PrivateKeyParameter = privateKey;
            jobCert.PrivateKeyPem = PrivateKeyFormatUtilities.ExportPrivateKeyAsPem(privateKey, PrivateKeyFormat.Pkcs8);
            jobCert.PrivateKeyBytes = CertificateUtilities.ExportPrivateKeyPkcs8(privateKey);
            jobCert.HasPrivateKey = true;

            _logger.LogDebug("Private key extracted for certificate: {Thumbprint}", jobCert.CertThumbprint);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Private key extraction failed for certificate: {Thumbprint}", jobCert.CertThumbprint);
        }
    }

    /// <summary>
    /// Parses a DER-encoded certificate (no private key).
    /// </summary>
    private K8SJobCertificate ParseDerCertificate(byte[] derBytes, K8SJobCertificate jobCert, bool includeCertChain)
    {
        if (includeCertChain)
        {
            _logger.LogWarning(
                "IncludeCertChain is enabled but certificate is DER format (no private key). " +
                "Chain cannot be included.");
        }

        var parser = new X509CertificateParser();
        var bcCert = parser.ReadCertificate(derBytes);
        if (bcCert == null)
        {
            _logger.LogError("Failed to parse DER certificate - parser returned null");
            return jobCert;
        }

        _logger.LogDebug("DER certificate loaded: {Summary}", LoggingUtilities.GetCertificateSummary(bcCert));

        jobCert.CertPem = PemUtilities.DERToPEM(bcCert.GetEncoded(), PemUtilities.PemObjectType.Certificate);
        jobCert.CertBytes = bcCert.GetEncoded();
        jobCert.CertThumbprint = bcCert.Thumbprint();
        jobCert.CertificateEntry = new X509CertificateEntry(bcCert);
        jobCert.HasPrivateKey = false;
        jobCert.CertificateEntryChain = new[] { jobCert.CertificateEntry };
        jobCert.ChainPem = new List<string> { jobCert.CertPem };

        return jobCert;
    }

    /// <summary>
    /// Parses PEM-encoded certificate(s) (no private key).
    /// </summary>
    private K8SJobCertificate ParsePemCertificate(string pemData, K8SJobCertificate jobCert)
    {
        var certificates = new List<X509Certificate>();
        using var stringReader = new StringReader(pemData);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(stringReader);

        object pemObject;
        while ((pemObject = pemReader.ReadObject()) != null)
        {
            if (pemObject is X509Certificate cert)
            {
                certificates.Add(cert);
            }
        }

        if (certificates.Count == 0)
        {
            // Fallback: try parsing as raw certificate data
            var parser = new X509CertificateParser();
            var bcCert = parser.ReadCertificate(Encoding.UTF8.GetBytes(pemData));
            if (bcCert != null)
                certificates.Add(bcCert);
        }

        if (certificates.Count == 0)
        {
            _logger.LogError("Failed to parse PEM certificate - no certificates found");
            return jobCert;
        }

        var leafCert = certificates[0];
        _logger.LogDebug("Leaf certificate: {Summary}", LoggingUtilities.GetCertificateSummary(leafCert));

        jobCert.CertPem = PemUtilities.DERToPEM(leafCert.GetEncoded(), PemUtilities.PemObjectType.Certificate);
        jobCert.CertBytes = leafCert.GetEncoded();
        jobCert.CertThumbprint = leafCert.Thumbprint();
        jobCert.CertificateEntry = new X509CertificateEntry(leafCert);
        jobCert.HasPrivateKey = false;

        jobCert.CertificateEntryChain = certificates
            .Select(c => new X509CertificateEntry(c))
            .ToArray();

        jobCert.ChainPem = certificates
            .Select(c => PemUtilities.DERToPEM(c.GetEncoded(), PemUtilities.PemObjectType.Certificate))
            .ToList();

        _logger.LogInformation("PEM certificate(s) parsed: {Count} certificate(s), no private key", certificates.Count);
        return jobCert;
    }
}
