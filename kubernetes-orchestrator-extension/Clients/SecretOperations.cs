// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using k8s;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Clients;

/// <summary>
/// Handles Kubernetes secret CRUD operations.
/// Provides methods for creating, reading, updating, and deleting secrets.
/// </summary>
public class SecretOperations
{
    private readonly ILogger _logger;
    private readonly IKubernetes _client;

    /// <summary>
    /// Initializes a new instance of SecretOperations.
    /// </summary>
    /// <param name="client">Kubernetes API client.</param>
    /// <param name="logger">Logger instance for diagnostic output.</param>
    public SecretOperations(IKubernetes client, ILogger logger = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _logger = logger ?? LogHandler.GetClassLogger<SecretOperations>();
    }

    /// <summary>
    /// Creates a new Kubernetes secret with the specified data.
    /// </summary>
    /// <param name="secretName">Name of the secret to create.</param>
    /// <param name="namespaceName">Namespace where the secret will be created.</param>
    /// <param name="secretType">Type of secret (tls, opaque, pkcs12, jks).</param>
    /// <param name="keyPem">Private key in PEM format (optional for opaque).</param>
    /// <param name="certPem">Certificate in PEM format.</param>
    /// <param name="chainPem">Certificate chain in PEM format.</param>
    /// <param name="separateChain">Whether to store chain in separate ca.crt field.</param>
    /// <param name="includeChain">Whether to include the certificate chain.</param>
    /// <returns>The created V1Secret object ready for API submission.</returns>
    public V1Secret BuildNewSecret(
        string secretName,
        string namespaceName,
        string secretType,
        string keyPem = null,
        string certPem = null,
        IList<string> chainPem = null,
        bool separateChain = true,
        bool includeChain = true)
    {
        _logger.LogTrace("Building new secret: {SecretName} in {Namespace}", secretName, namespaceName);

        // Normalize the secret type
        var normalizedType = SecretTypes.Normalize(secretType);
        _logger.LogDebug("Normalized secret type: {OriginalType} -> {NormalizedType}", secretType, normalizedType);

        V1Secret secret;

        if (SecretTypes.IsTlsType(normalizedType))
        {
            secret = BuildTlsSecret(secretName, namespaceName, keyPem, certPem);
        }
        else if (SecretTypes.IsOpaqueType(normalizedType))
        {
            secret = BuildOpaqueSecret(secretName, namespaceName, keyPem, certPem);
        }
        else if (SecretTypes.IsKeystoreType(normalizedType))
        {
            // Keystore secrets start as empty Opaque secrets
            secret = BuildEmptyOpaqueSecret(secretName, namespaceName);
            _logger.LogDebug("Created empty Opaque secret for {Type} store", normalizedType);
        }
        else
        {
            throw new NotSupportedException($"Secret type '{secretType}' is not supported for new secret creation.");
        }

        // Add chain if provided and requested
        if (chainPem != null && chainPem.Count > 0 && includeChain)
        {
            AddChainToSecret(secret, certPem, chainPem, separateChain);
        }

        _logger.LogTrace("Finished building secret");
        return secret;
    }

    /// <summary>
    /// Creates a TLS secret (kubernetes.io/tls type).
    /// </summary>
    private V1Secret BuildTlsSecret(string secretName, string namespaceName, string keyPem, string certPem)
    {
        if (string.IsNullOrEmpty(keyPem))
        {
            _logger.LogWarning("TLS secrets require a private key. Certificate was provided without private key - creating with empty tls.key field");
        }

        return new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = secretName,
                NamespaceProperty = namespaceName
            },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.key", Encoding.UTF8.GetBytes(keyPem ?? "") },
                { "tls.crt", Encoding.UTF8.GetBytes(certPem ?? "") }
            }
        };
    }

    /// <summary>
    /// Creates an Opaque secret with certificate data.
    /// </summary>
    private V1Secret BuildOpaqueSecret(string secretName, string namespaceName, string keyPem, string certPem)
    {
        var data = new Dictionary<string, byte[]>
        {
            { "tls.crt", Encoding.UTF8.GetBytes(certPem ?? "") }
        };

        if (!string.IsNullOrEmpty(keyPem))
        {
            data["tls.key"] = Encoding.UTF8.GetBytes(keyPem);
        }
        else
        {
            _logger.LogDebug("No private key provided for Opaque secret - storing certificate only");
        }

        return new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = secretName,
                NamespaceProperty = namespaceName
            },
            Type = "Opaque",
            Data = data
        };
    }

    /// <summary>
    /// Creates an empty Opaque secret (for keystore initialization).
    /// </summary>
    private V1Secret BuildEmptyOpaqueSecret(string secretName, string namespaceName)
    {
        return new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = secretName,
                NamespaceProperty = namespaceName
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>()
        };
    }

    /// <summary>
    /// Adds certificate chain to an existing secret.
    /// </summary>
    private void AddChainToSecret(V1Secret secret, string certPem, IList<string> chainPem, bool separateChain)
    {
        // Filter out the leaf certificate from the chain
        var chainCerts = chainPem.Where(c => c != certPem).ToList();
        if (chainCerts.Count == 0)
            return;

        var chainPemString = string.Join("", chainCerts);

        if (separateChain)
        {
            secret.Data["ca.crt"] = Encoding.UTF8.GetBytes(chainPemString);
            _logger.LogDebug("Added certificate chain to ca.crt field");
        }
        else
        {
            // Bundle chain with the certificate in tls.crt
            var existingCert = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
            secret.Data["tls.crt"] = Encoding.UTF8.GetBytes(existingCert + chainPemString);
            _logger.LogDebug("Bundled certificate chain into tls.crt field");
        }
    }

    /// <summary>
    /// Updates an existing Opaque secret with new certificate data.
    /// </summary>
    /// <param name="existingSecret">The existing secret to update.</param>
    /// <param name="newKeyPem">New private key (null to keep existing).</param>
    /// <param name="newCertPem">New certificate.</param>
    /// <param name="chainPem">Certificate chain.</param>
    /// <param name="separateChain">Whether to store chain separately.</param>
    /// <param name="includeChain">Whether to include the chain.</param>
    /// <returns>The updated V1Secret object.</returns>
    public V1Secret UpdateOpaqueSecretData(
        V1Secret existingSecret,
        string newKeyPem,
        string newCertPem,
        IList<string> chainPem = null,
        bool separateChain = true,
        bool includeChain = true)
    {
        _logger.LogTrace("Updating Opaque secret data");

        // Update private key only if provided
        if (!string.IsNullOrEmpty(newKeyPem))
        {
            existingSecret.Data["tls.key"] = Encoding.UTF8.GetBytes(newKeyPem);
        }
        else
        {
            _logger.LogDebug("No private key provided in update - keeping existing tls.key if present");
        }

        // Update certificate
        if (!string.IsNullOrEmpty(newCertPem))
        {
            existingSecret.Data["tls.crt"] = Encoding.UTF8.GetBytes(newCertPem);
        }

        // Handle chain
        if (chainPem != null && chainPem.Count > 0 && includeChain)
        {
            AddChainToSecret(existingSecret, newCertPem, chainPem, separateChain);
        }

        return existingSecret;
    }

    /// <summary>
    /// Reads a secret from the Kubernetes API.
    /// </summary>
    /// <param name="secretName">Name of the secret.</param>
    /// <param name="namespaceName">Namespace of the secret.</param>
    /// <returns>The V1Secret if found, null otherwise.</returns>
    public V1Secret GetSecret(string secretName, string namespaceName)
    {
        _logger.LogTrace("Reading secret {SecretName} from namespace {Namespace}", secretName, namespaceName);

        try
        {
            return _client.CoreV1.ReadNamespacedSecret(secretName, namespaceName);
        }
        catch (k8s.Autorest.HttpOperationException ex) when (ex.Response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            _logger.LogDebug("Secret {SecretName} not found in namespace {Namespace}", secretName, namespaceName);
            return null;
        }
    }

    /// <summary>
    /// Creates a new secret in Kubernetes.
    /// </summary>
    /// <param name="secret">The secret to create.</param>
    /// <param name="namespaceName">Namespace where to create the secret.</param>
    /// <returns>The created secret.</returns>
    public V1Secret CreateSecret(V1Secret secret, string namespaceName)
    {
        _logger.LogDebug("Creating secret {SecretName} in namespace {Namespace}",
            secret.Metadata?.Name, namespaceName);

        return _client.CoreV1.CreateNamespacedSecret(secret, namespaceName);
    }

    /// <summary>
    /// Updates an existing secret in Kubernetes.
    /// </summary>
    /// <param name="secret">The secret to update.</param>
    /// <param name="namespaceName">Namespace of the secret.</param>
    /// <returns>The updated secret.</returns>
    public V1Secret UpdateSecret(V1Secret secret, string namespaceName)
    {
        _logger.LogDebug("Updating secret {SecretName} in namespace {Namespace}",
            secret.Metadata?.Name, namespaceName);

        return _client.CoreV1.ReplaceNamespacedSecret(secret, secret.Metadata.Name, namespaceName);
    }

    /// <summary>
    /// Deletes a secret from Kubernetes.
    /// </summary>
    /// <param name="secretName">Name of the secret to delete.</param>
    /// <param name="namespaceName">Namespace of the secret.</param>
    /// <returns>Status of the delete operation.</returns>
    public V1Status DeleteSecret(string secretName, string namespaceName)
    {
        _logger.LogDebug("Deleting secret {SecretName} from namespace {Namespace}", secretName, namespaceName);

        return _client.CoreV1.DeleteNamespacedSecret(secretName, namespaceName);
    }

    /// <summary>
    /// Lists all secrets in a namespace.
    /// </summary>
    /// <param name="namespaceName">Namespace to list secrets from.</param>
    /// <returns>List of secrets in the namespace.</returns>
    public V1SecretList ListSecrets(string namespaceName)
    {
        _logger.LogTrace("Listing secrets in namespace {Namespace}", namespaceName);

        return _client.CoreV1.ListNamespacedSecret(namespaceName);
    }

    /// <summary>
    /// Creates or updates a secret (upsert operation).
    /// </summary>
    /// <param name="secret">The secret to create or update.</param>
    /// <param name="namespaceName">Namespace for the operation.</param>
    /// <returns>The created or updated secret.</returns>
    public V1Secret CreateOrUpdateSecret(V1Secret secret, string namespaceName)
    {
        var existing = GetSecret(secret.Metadata.Name, namespaceName);

        if (existing != null)
        {
            // Preserve resource version for update
            secret.Metadata.ResourceVersion = existing.Metadata.ResourceVersion;
            return UpdateSecret(secret, namespaceName);
        }

        return CreateSecret(secret, namespaceName);
    }
}
