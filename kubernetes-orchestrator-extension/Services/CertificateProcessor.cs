// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Pkcs;

namespace Keyfactor.Extensions.Orchestrator.K8S.Services;

/// <summary>
/// Service for processing certificates from job configurations.
/// Centralizes certificate parsing, chain extraction, and private key handling.
/// </summary>
public class CertificateProcessor
{
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new CertificateProcessor.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    public CertificateProcessor(ILogger logger = null)
    {
        _logger = logger ?? LogHandler.GetClassLogger(typeof(CertificateProcessor));
    }

    /// <summary>
    /// Parses a job certificate from PKCS12 data.
    /// </summary>
    /// <param name="pkcs12Base64">Base64-encoded PKCS12 data.</param>
    /// <param name="password">Password for the PKCS12 store.</param>
    /// <returns>Populated K8SJobCertificate, or null if parsing fails.</returns>
    public K8SJobCertificate ParseJobCertificate(string pkcs12Base64, string password)
    {
        _logger.LogDebug("Parsing job certificate from PKCS12 data");

        if (string.IsNullOrEmpty(pkcs12Base64))
        {
            _logger.LogError("PKCS12 data is null or empty");
            return null;
        }

        try
        {
            var certBytes = Convert.FromBase64String(pkcs12Base64);
            return ParseJobCertificate(certBytes, password);
        }
        catch (FormatException ex)
        {
            _logger.LogError(ex, "Invalid base64 PKCS12 data");
            return null;
        }
    }

    /// <summary>
    /// Parses a job certificate from PKCS12 bytes.
    /// </summary>
    /// <param name="pkcs12Bytes">PKCS12 store bytes.</param>
    /// <param name="password">Password for the PKCS12 store.</param>
    /// <returns>Populated K8SJobCertificate, or null if parsing fails.</returns>
    public K8SJobCertificate ParseJobCertificate(byte[] pkcs12Bytes, string password)
    {
        _logger.LogDebug("Parsing job certificate from {ByteCount} PKCS12 bytes", pkcs12Bytes?.Length ?? 0);

        if (pkcs12Bytes == null || pkcs12Bytes.Length == 0)
        {
            _logger.LogError("PKCS12 bytes are null or empty");
            return null;
        }

        var jobCert = new K8SJobCertificate
        {
            Password = password,
            Pkcs12 = pkcs12Bytes
        };

        try
        {
            var store = CertificateUtilities.LoadPkcs12Store(pkcs12Bytes, password ?? string.Empty);
            PopulateFromStore(jobCert, store, password);
            return jobCert;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error parsing PKCS12 store: {Message}", ex.Message);
            return jobCert; // Return partially populated object
        }
    }

    /// <summary>
    /// Populates a K8SJobCertificate from a PKCS12 store.
    /// </summary>
    private void PopulateFromStore(K8SJobCertificate jobCert, Pkcs12Store store, string password)
    {
        var alias = store.Aliases.FirstOrDefault(store.IsKeyEntry);

        if (alias == null)
        {
            _logger.LogWarning("No key entry found in PKCS12 store");
            return;
        }

        _logger.LogDebug("Processing certificate with alias: {Alias}", alias);

        // Get certificate
        var certEntry = store.GetCertificate(alias);
        if (certEntry?.Certificate == null)
        {
            _logger.LogError("Unable to retrieve certificate from PKCS12 store");
            return;
        }

        var certificate = certEntry.Certificate;
        jobCert.CertificateEntry = certEntry;
        jobCert.CertPem = CertificateUtilities.ConvertToPem(certificate);
        jobCert.CertBytes = certificate.GetEncoded();
        jobCert.CertThumbprint = CertificateUtilities.GetThumbprint(certificate);

        _logger.LogDebug("Certificate loaded: {Summary}", LoggingUtilities.GetCertificateSummary(certificate));

        // Get certificate chain
        var chain = store.GetCertificateChain(alias);
        if (chain != null && chain.Length > 0)
        {
            jobCert.CertificateEntryChain = chain;
            jobCert.ChainPem = chain.Select(c => CertificateUtilities.ConvertToPem(c.Certificate)).ToList();
            _logger.LogDebug("Certificate chain: {Count} certificates", chain.Length);
        }

        // Extract private key if available
        var keyEntry = store.GetKey(alias);
        if (keyEntry?.Key != null)
        {
            try
            {
                jobCert.PrivateKeyPem = CertificateUtilities.ExtractPrivateKeyAsPem(keyEntry.Key);
                _logger.LogDebug("Private key extracted successfully");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to extract private key: {Message}", ex.Message);
            }
        }
    }

    /// <summary>
    /// Extracts the private key from a PKCS12 store as PEM format.
    /// </summary>
    /// <param name="pkcs12Bytes">PKCS12 store bytes.</param>
    /// <param name="password">Password for the store.</param>
    /// <param name="alias">Optional alias. If null, first key entry is used.</param>
    /// <returns>PEM-encoded private key, or null if not available.</returns>
    public string ExtractPrivateKeyPem(byte[] pkcs12Bytes, string password, string alias = null)
    {
        _logger.LogDebug("Extracting private key from PKCS12 store");

        try
        {
            var store = CertificateUtilities.LoadPkcs12Store(pkcs12Bytes, password ?? string.Empty);

            if (string.IsNullOrEmpty(alias))
            {
                alias = store.Aliases.FirstOrDefault(store.IsKeyEntry);
            }

            if (alias == null)
            {
                _logger.LogWarning("No key entry found in PKCS12 store");
                return null;
            }

            var keyEntry = store.GetKey(alias);
            if (keyEntry?.Key == null)
            {
                _logger.LogWarning("No private key found for alias {Alias}", alias);
                return null;
            }

            return CertificateUtilities.ExtractPrivateKeyAsPem(keyEntry.Key);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error extracting private key: {Message}", ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Gets the certificate thumbprint from PKCS12 data.
    /// </summary>
    /// <param name="pkcs12Bytes">PKCS12 store bytes.</param>
    /// <param name="password">Password for the store.</param>
    /// <returns>Certificate thumbprint, or null if unavailable.</returns>
    public string GetThumbprint(byte[] pkcs12Bytes, string password)
    {
        try
        {
            var store = CertificateUtilities.LoadPkcs12Store(pkcs12Bytes, password ?? string.Empty);
            var alias = store.Aliases.FirstOrDefault(store.IsKeyEntry);

            if (alias == null)
                return null;

            var certEntry = store.GetCertificate(alias);
            return certEntry?.Certificate != null
                ? CertificateUtilities.GetThumbprint(certEntry.Certificate)
                : null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting thumbprint: {Message}", ex.Message);
            return null;
        }
    }
}
