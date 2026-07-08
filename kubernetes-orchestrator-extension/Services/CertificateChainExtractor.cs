// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Text;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Services;

/// <summary>
/// Extracts certificate chains from Kubernetes secret data.
/// Handles both PEM chains and single DER certificates, with fallback logic.
/// </summary>
public class CertificateChainExtractor
{
    private readonly KubeCertificateManagerClient _kubeClient;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of CertificateChainExtractor.
    /// </summary>
    /// <param name="kubeClient">Kubernetes client for certificate operations.</param>
    /// <param name="logger">Logger instance for diagnostic output.</param>
    public CertificateChainExtractor(KubeCertificateManagerClient kubeClient, ILogger logger = null)
    {
        _kubeClient = kubeClient;
        _logger = logger ?? LogHandler.GetClassLogger<CertificateChainExtractor>();
    }

    /// <summary>
    /// Extracts certificates from PEM or DER data.
    /// First tries to parse as a PEM chain, then falls back to single DER certificate.
    /// </summary>
    /// <param name="certData">Certificate data (PEM string or base64 DER).</param>
    /// <param name="sourceDescription">Description of the source for logging (e.g., "key 'tls.crt'").</param>
    /// <returns>List of PEM-formatted certificates, or empty list if parsing fails.</returns>
    public List<string> ExtractCertificates(string certData, string sourceDescription = "certificate data")
    {
        var result = new List<string>();

        if (string.IsNullOrWhiteSpace(certData))
        {
            _logger.LogDebug("Certificate data from {Source} is empty or whitespace", sourceDescription);
            return result;
        }

        // First, try to parse as a PEM chain (handles multiple certs in one field)
        var certChain = _kubeClient.LoadCertificateChain(certData);
        if (certChain != null && certChain.Count > 0)
        {
            _logger.LogDebug("Found {Count} certificate(s) in {Source}", certChain.Count, sourceDescription);
            foreach (var cert in certChain)
            {
                var certPem = _kubeClient.ConvertToPem(cert);
                _logger.LogTrace("Adding certificate from {Source}: {Subject}", sourceDescription, cert.SubjectDN);
                result.Add(certPem);
            }
            return result;
        }

        // Fallback: try to parse as a single DER certificate
        _logger.LogDebug("Failed to parse {Source} as PEM chain, trying DER format", sourceDescription);
        var certObj = _kubeClient.ReadDerCertificate(certData);
        if (certObj != null)
        {
            var certPem = _kubeClient.ConvertToPem(certObj);
            _logger.LogTrace("Adding DER certificate from {Source}: {Subject}", sourceDescription, certObj.SubjectDN);
            result.Add(certPem);
        }
        else
        {
            _logger.LogWarning("Failed to parse certificate from {Source} as PEM or DER format", sourceDescription);
        }

        return result;
    }

    /// <summary>
    /// Extracts certificates from byte array data (converts to UTF-8 string first).
    /// </summary>
    /// <param name="certBytes">Certificate data as bytes.</param>
    /// <param name="sourceDescription">Description of the source for logging.</param>
    /// <returns>List of PEM-formatted certificates, or empty list if parsing fails.</returns>
    public List<string> ExtractCertificates(byte[] certBytes, string sourceDescription = "certificate data")
    {
        if (certBytes == null || certBytes.Length == 0)
        {
            _logger.LogDebug("Certificate bytes from {Source} is null or empty", sourceDescription);
            return new List<string>();
        }

        var certData = Encoding.UTF8.GetString(certBytes);
        return ExtractCertificates(certData, sourceDescription);
    }

    /// <summary>
    /// Extracts certificates and adds them to an existing list, avoiding duplicates.
    /// Useful for adding CA chain certificates to an existing certificate list.
    /// </summary>
    /// <param name="certData">Certificate data (PEM string or base64 DER).</param>
    /// <param name="existingCerts">Existing list of PEM certificates to append to.</param>
    /// <param name="sourceDescription">Description of the source for logging.</param>
    /// <returns>Number of new certificates added.</returns>
    public int ExtractAndAppendUnique(string certData, List<string> existingCerts, string sourceDescription = "certificate data")
    {
        var newCerts = ExtractCertificates(certData, sourceDescription);
        var addedCount = 0;

        foreach (var cert in newCerts)
        {
            if (!existingCerts.Contains(cert))
            {
                existingCerts.Add(cert);
                addedCount++;
            }
            else
            {
                _logger.LogTrace("Skipping duplicate certificate from {Source}", sourceDescription);
            }
        }

        return addedCount;
    }

    /// <summary>
    /// Extracts certificates from byte array and adds them to an existing list, avoiding duplicates.
    /// </summary>
    /// <param name="certBytes">Certificate data as bytes.</param>
    /// <param name="existingCerts">Existing list of PEM certificates to append to.</param>
    /// <param name="sourceDescription">Description of the source for logging.</param>
    /// <returns>Number of new certificates added.</returns>
    public int ExtractAndAppendUnique(byte[] certBytes, List<string> existingCerts, string sourceDescription = "certificate data")
    {
        if (certBytes == null || certBytes.Length == 0)
        {
            return 0;
        }

        var certData = Encoding.UTF8.GetString(certBytes);
        return ExtractAndAppendUnique(certData, existingCerts, sourceDescription);
    }

    /// <summary>
    /// Extracts certificates from a secret's data dictionary using the specified allowed keys.
    /// Tries each key in order until certificates are found.
    /// </summary>
    /// <param name="secretData">Dictionary of secret data (key -> byte array).</param>
    /// <param name="allowedKeys">Keys to try, in priority order.</param>
    /// <param name="secretName">Name of the secret for logging.</param>
    /// <param name="namespaceName">Namespace of the secret for logging.</param>
    /// <returns>List of PEM-formatted certificates.</returns>
    public List<string> ExtractFromSecretData(
        IDictionary<string, byte[]> secretData,
        string[] allowedKeys,
        string secretName,
        string namespaceName)
    {
        var certsList = new List<string>();

        if (secretData == null)
        {
            _logger.LogWarning("Secret data is null for {SecretName} in {Namespace}", secretName, namespaceName);
            return certsList;
        }

        // Try primary keys first (excludes ca.crt which is handled separately)
        foreach (var key in allowedKeys)
        {
            if (key == "ca.crt") continue; // CA chain is processed separately

            if (!secretData.TryGetValue(key, out var certBytes) || certBytes == null || certBytes.Length == 0)
            {
                continue;
            }

            var sourceDesc = $"secret '{secretName}' key '{key}' in namespace '{namespaceName}'";
            var certs = ExtractCertificates(certBytes, sourceDesc);

            if (certs.Count > 0)
            {
                certsList.AddRange(certs);
                _logger.LogDebug("Found {Count} certificate(s) in {Source}", certs.Count, sourceDesc);
                break; // Found certificates, stop trying other primary keys
            }
        }

        // Process ca.crt separately to add chain certificates (avoiding duplicates)
        if (secretData.TryGetValue("ca.crt", out var caBytes) && caBytes != null && caBytes.Length > 0)
        {
            var sourceDesc = $"secret '{secretName}' key 'ca.crt' in namespace '{namespaceName}'";
            var addedCount = ExtractAndAppendUnique(caBytes, certsList, sourceDesc);
            if (addedCount > 0)
            {
                _logger.LogDebug("Added {Count} CA certificate(s) from ca.crt", addedCount);
            }
        }

        return certsList;
    }
}
