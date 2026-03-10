// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using k8s.Models;
using Keyfactor.PKI.Extensions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using X509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate2;

namespace Keyfactor.Extensions.Orchestrator.K8S.Utilities
{
    /// <summary>
    /// Provides utilities for safe logging of sensitive data by redacting or summarizing
    /// passwords, private keys, certificates, and other sensitive information.
    /// </summary>
    public static class LoggingUtilities
    {
        #region Password Redaction

        /// <summary>
        /// Redacts a password for safe logging.
        /// </summary>
        /// <param name="password">The password to redact</param>
        /// <returns>"***REDACTED***", "EMPTY", or "NULL"</returns>
        public static string RedactPassword(string password)
        {
            if (password == null)
            {
                return "NULL";
            }

            if (string.IsNullOrEmpty(password))
            {
                return "EMPTY";
            }

            return "***REDACTED***";
        }

        /// <summary>
        /// Generates a correlation ID for a password based on its SHA-256 hash.
        /// This allows tracking the same password across multiple operations without
        /// logging the actual password value.
        /// </summary>
        /// <param name="password">The password to generate a correlation ID for</param>
        /// <returns>A correlation ID like "hash:abc123..." or "NULL" or "EMPTY"</returns>
        public static string GetPasswordCorrelationId(string password)
        {
            if (password == null)
            {
                return "NULL";
            }

            if (string.IsNullOrEmpty(password))
            {
                return "EMPTY";
            }

            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                var hashPrefix = BitConverter.ToString(hashBytes).Replace("-", "").Substring(0, 16).ToLower();
                return $"hash:{hashPrefix}";
            }
        }

        #endregion

        #region Private Key Redaction

        /// <summary>
        /// Redacts a private key in PEM format for safe logging. Shows the key type and
        /// length only, never the actual key material.
        /// </summary>
        /// <param name="privateKeyPem">The PEM-encoded private key</param>
        /// <returns>A redacted string showing key type and length, or "EMPTY" or "NULL"</returns>
        public static string RedactPrivateKeyPem(string privateKeyPem)
        {
            if (privateKeyPem == null)
            {
                return "NULL";
            }

            if (string.IsNullOrEmpty(privateKeyPem))
            {
                return "EMPTY";
            }

            // Detect key type from PEM header
            string keyType = "UNKNOWN";
            if (privateKeyPem.Contains("BEGIN RSA PRIVATE KEY"))
            {
                keyType = "RSA";
            }
            else if (privateKeyPem.Contains("BEGIN EC PRIVATE KEY"))
            {
                keyType = "EC";
            }
            else if (privateKeyPem.Contains("BEGIN PRIVATE KEY"))
            {
                keyType = "PKCS8";
            }
            else if (privateKeyPem.Contains("BEGIN ENCRYPTED PRIVATE KEY"))
            {
                keyType = "ENCRYPTED_PKCS8";
            }

            return $"***REDACTED_PRIVATE_KEY*** (type: {keyType}, length: {privateKeyPem.Length})";
        }

        /// <summary>
        /// Redacts a private key in byte array format for safe logging.
        /// </summary>
        /// <param name="privateKeyBytes">The private key bytes</param>
        /// <returns>A redacted string showing byte count, or "EMPTY" or "NULL"</returns>
        public static string RedactPrivateKeyBytes(byte[] privateKeyBytes)
        {
            if (privateKeyBytes == null)
            {
                return "NULL";
            }

            if (privateKeyBytes.Length == 0)
            {
                return "EMPTY";
            }

            return $"***REDACTED_PRIVATE_KEY_BYTES*** (count: {privateKeyBytes.Length})";
        }

        /// <summary>
        /// Redacts a BouncyCastle AsymmetricKeyParameter for safe logging.
        /// </summary>
        /// <param name="privateKey">The private key parameter</param>
        /// <returns>A redacted string showing key type, or "NULL"</returns>
        public static string RedactPrivateKey(AsymmetricKeyParameter privateKey)
        {
            if (privateKey == null)
            {
                return "NULL";
            }

            var keyType = privateKey.GetType().Name;
            return $"***REDACTED_PRIVATE_KEY*** (type: {keyType}, isPrivate: {privateKey.IsPrivate})";
        }

        #endregion

        #region Certificate Data Redaction

        /// <summary>
        /// Gets a safe summary of a certificate for logging. Includes subject, thumbprint,
        /// and validity period, but not the certificate data itself.
        /// </summary>
        /// <param name="certificate">The certificate to summarize</param>
        /// <returns>A summary string with certificate metadata</returns>
        public static string GetCertificateSummary(X509Certificate certificate)
        {
            if (certificate == null)
            {
                return "NULL";
            }

            try
            {
                var subject = certificate.Subject;
                var thumbprint = certificate.Thumbprint;
                var notBefore = certificate.NotBefore.ToString("yyyy-MM-dd");
                var notAfter = certificate.NotAfter.ToString("yyyy-MM-dd");

                return $"Subject: {subject}, Thumbprint: {thumbprint}, Valid: {notBefore} to {notAfter}";
            }
            catch (Exception ex)
            {
                return $"ERROR_READING_CERTIFICATE: {ex.Message}";
            }
        }

        /// <summary>
        /// Gets a safe summary of a BouncyCastle certificate for logging.
        /// </summary>
        /// <param name="certificate">The BouncyCastle certificate to summarize</param>
        /// <returns>A summary string with certificate metadata</returns>
        public static string GetCertificateSummary(Org.BouncyCastle.X509.X509Certificate certificate)
        {
            if (certificate == null)
            {
                return "NULL";
            }

            try
            {
                var subject = certificate.SubjectDN.ToString();
                var thumbprint = certificate.Thumbprint();
                var notBefore = certificate.NotBefore.ToString("yyyy-MM-dd");
                var notAfter = certificate.NotAfter.ToString("yyyy-MM-dd");

                return $"Subject: {subject}, Thumbprint: {thumbprint}, Valid: {notBefore} to {notAfter}";
            }
            catch (Exception ex)
            {
                return $"ERROR_READING_CERTIFICATE: {ex.Message}";
            }
        }

        /// <summary>
        /// Gets a safe summary of a certificate from PEM string for logging.
        /// </summary>
        /// <param name="certificatePem">The PEM-encoded certificate</param>
        /// <returns>A summary string with certificate metadata or error message</returns>
        public static string GetCertificateSummaryFromPem(string certificatePem)
        {
            if (certificatePem == null)
            {
                return "NULL";
            }

            if (string.IsNullOrEmpty(certificatePem))
            {
                return "EMPTY";
            }

            try
            {
                var cert = CertificateUtilities.ParseCertificateFromPem(certificatePem);
                return GetCertificateSummary(cert);
            }
            catch (Exception ex)
            {
                return $"ERROR_PARSING_CERTIFICATE: {ex.Message}";
            }
        }

        /// <summary>
        /// Redacts a certificate in PEM format for safe logging. Shows length only.
        /// </summary>
        /// <param name="certificatePem">The PEM-encoded certificate</param>
        /// <returns>A redacted string showing length, or "EMPTY" or "NULL"</returns>
        public static string RedactCertificatePem(string certificatePem)
        {
            if (certificatePem == null)
            {
                return "NULL";
            }

            if (string.IsNullOrEmpty(certificatePem))
            {
                return "EMPTY";
            }

            return $"***REDACTED_CERTIFICATE_PEM*** (length: {certificatePem.Length})";
        }

        /// <summary>
        /// Redacts PKCS12/PFX bytes for safe logging. Shows size only.
        /// </summary>
        /// <param name="pkcs12Bytes">The PKCS12 data</param>
        /// <returns>A redacted string showing byte count, or "EMPTY" or "NULL"</returns>
        public static string RedactPkcs12Bytes(byte[] pkcs12Bytes)
        {
            if (pkcs12Bytes == null)
            {
                return "NULL";
            }

            if (pkcs12Bytes.Length == 0)
            {
                return "EMPTY";
            }

            return $"***REDACTED_PKCS12*** (bytes: {pkcs12Bytes.Length})";
        }

        #endregion

        #region Kubernetes Secret Redaction

        /// <summary>
        /// Gets a safe summary of a Kubernetes secret for logging. Includes metadata
        /// but never the secret data itself.
        /// </summary>
        /// <param name="secret">The Kubernetes secret</param>
        /// <returns>A summary string with secret metadata</returns>
        public static string GetSecretSummary(V1Secret secret)
        {
            if (secret == null)
            {
                return "NULL";
            }

            try
            {
                var name = secret.Metadata?.Name ?? "UNKNOWN";
                var ns = secret.Metadata?.NamespaceProperty ?? "UNKNOWN";
                var type = secret.Type ?? "UNKNOWN";
                var dataKeyCount = secret.Data?.Count ?? 0;
                var dataKeys = secret.Data != null ? string.Join(", ", secret.Data.Keys) : "NONE";

                return $"Name: {name}, Namespace: {ns}, Type: {type}, DataKeys: [{dataKeys}] (count: {dataKeyCount})";
            }
            catch (Exception ex)
            {
                return $"ERROR_READING_SECRET: {ex.Message}";
            }
        }

        /// <summary>
        /// Gets a safe summary of secret data keys for logging. Shows keys but never values.
        /// </summary>
        /// <param name="secretData">The secret data dictionary</param>
        /// <returns>A comma-separated list of keys or "EMPTY" or "NULL"</returns>
        public static string GetSecretDataKeysSummary(IDictionary<string, byte[]> secretData)
        {
            if (secretData == null)
            {
                return "NULL";
            }

            if (secretData.Count == 0)
            {
                return "EMPTY";
            }

            return string.Join(", ", secretData.Keys);
        }

        /// <summary>
        /// Redacts a kubeconfig JSON string for safe logging. Shows structure but not
        /// sensitive data like tokens or certificates.
        /// </summary>
        /// <param name="kubeconfigJson">The kubeconfig JSON string</param>
        /// <returns>A safe summary of the kubeconfig structure</returns>
        public static string RedactKubeconfig(string kubeconfigJson)
        {
            if (kubeconfigJson == null)
            {
                return "NULL";
            }

            if (string.IsNullOrEmpty(kubeconfigJson))
            {
                return "EMPTY";
            }

            // Count the number of clusters, users, and contexts
            int clusterCount = kubeconfigJson.Split(new[] { "\"cluster\"" }, StringSplitOptions.None).Length - 1;
            int userCount = kubeconfigJson.Split(new[] { "\"user\"" }, StringSplitOptions.None).Length - 1;
            int contextCount = kubeconfigJson.Split(new[] { "\"context\"" }, StringSplitOptions.None).Length - 1;

            return $"***REDACTED_KUBECONFIG*** (length: {kubeconfigJson.Length}, clusters: ~{clusterCount}, users: ~{userCount}, contexts: ~{contextCount})";
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Returns a string indicating whether a field is present, empty, or null.
        /// Useful for logging the presence of optional fields without revealing their values.
        /// </summary>
        /// <param name="fieldName">The name of the field</param>
        /// <param name="value">The field value</param>
        /// <returns>A string like "fieldName: PRESENT" or "fieldName: EMPTY" or "fieldName: NULL"</returns>
        public static string GetFieldPresence(string fieldName, string value)
        {
            if (value == null)
            {
                return $"{fieldName}: NULL";
            }

            if (string.IsNullOrEmpty(value))
            {
                return $"{fieldName}: EMPTY";
            }

            return $"{fieldName}: PRESENT";
        }

        /// <summary>
        /// Returns a string indicating whether a field is present, empty, or null.
        /// Useful for logging the presence of optional fields without revealing their values.
        /// </summary>
        /// <param name="fieldName">The name of the field</param>
        /// <param name="value">The field value</param>
        /// <returns>A string like "fieldName: PRESENT (count: N)" or "fieldName: EMPTY" or "fieldName: NULL"</returns>
        public static string GetFieldPresence(string fieldName, byte[] value)
        {
            if (value == null)
            {
                return $"{fieldName}: NULL";
            }

            if (value.Length == 0)
            {
                return $"{fieldName}: EMPTY";
            }

            return $"{fieldName}: PRESENT (count: {value.Length})";
        }

        /// <summary>
        /// Redacts a token string for safe logging.
        /// </summary>
        /// <param name="token">The token to redact</param>
        /// <returns>A redacted string showing length, or "EMPTY" or "NULL"</returns>
        public static string RedactToken(string token)
        {
            if (token == null)
            {
                return "NULL";
            }

            if (string.IsNullOrEmpty(token))
            {
                return "EMPTY";
            }

            // Show first and last 4 characters for correlation if token is long enough
            if (token.Length > 12)
            {
                var prefix = token.Substring(0, 4);
                var suffix = token.Substring(token.Length - 4);
                return $"***REDACTED_TOKEN*** ({prefix}...{suffix}, length: {token.Length})";
            }

            return $"***REDACTED_TOKEN*** (length: {token.Length})";
        }

        #endregion
    }
}
