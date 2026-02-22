// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using k8s;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Microsoft.Extensions.Logging;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace Keyfactor.Extensions.Orchestrator.K8S.Clients;

/// <summary>
/// Extension methods providing async versions of KubeCertificateManagerClient operations.
/// These wrap the underlying Kubernetes client's async methods for improved performance
/// in high-throughput scenarios.
/// </summary>
public static class KubeClientAsyncExtensions
{
    /// <summary>
    /// Asynchronously retrieves a Kubernetes secret.
    /// </summary>
    /// <param name="client">The KubeCertificateManagerClient instance.</param>
    /// <param name="secretName">Name of the secret.</param>
    /// <param name="namespaceName">Namespace containing the secret.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The V1Secret if found; otherwise, null.</returns>
    public static async Task<V1Secret> GetSecretAsync(
        this KubeCertificateManagerClient client,
        string secretName,
        string namespaceName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);

        try
        {
            // Access the underlying Kubernetes client
            var k8sClient = client.GetKubernetesClient();
            return await k8sClient.CoreV1.ReadNamespacedSecretAsync(
                secretName,
                namespaceName,
                cancellationToken: cancellationToken);
        }
        catch (k8s.Autorest.HttpOperationException ex) when (ex.Response?.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
    }

    /// <summary>
    /// Asynchronously creates a Kubernetes secret.
    /// </summary>
    /// <param name="client">The KubeCertificateManagerClient instance.</param>
    /// <param name="secret">The secret to create.</param>
    /// <param name="namespaceName">Namespace for the secret.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created V1Secret.</returns>
    public static async Task<V1Secret> CreateSecretAsync(
        this KubeCertificateManagerClient client,
        V1Secret secret,
        string namespaceName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(secret);

        var k8sClient = client.GetKubernetesClient();
        return await k8sClient.CoreV1.CreateNamespacedSecretAsync(
            secret,
            namespaceName,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Asynchronously updates (replaces) a Kubernetes secret.
    /// </summary>
    /// <param name="client">The KubeCertificateManagerClient instance.</param>
    /// <param name="secret">The secret to update.</param>
    /// <param name="namespaceName">Namespace containing the secret.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The updated V1Secret.</returns>
    public static async Task<V1Secret> UpdateSecretAsync(
        this KubeCertificateManagerClient client,
        V1Secret secret,
        string namespaceName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(secret);

        var k8sClient = client.GetKubernetesClient();
        return await k8sClient.CoreV1.ReplaceNamespacedSecretAsync(
            secret,
            secret.Metadata.Name,
            namespaceName,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Asynchronously deletes a Kubernetes secret.
    /// </summary>
    /// <param name="client">The KubeCertificateManagerClient instance.</param>
    /// <param name="secretName">Name of the secret to delete.</param>
    /// <param name="namespaceName">Namespace containing the secret.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The deletion status.</returns>
    public static async Task<V1Status> DeleteSecretAsync(
        this KubeCertificateManagerClient client,
        string secretName,
        string namespaceName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);

        var k8sClient = client.GetKubernetesClient();
        return await k8sClient.CoreV1.DeleteNamespacedSecretAsync(
            secretName,
            namespaceName,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Asynchronously lists all secrets in a namespace.
    /// </summary>
    /// <param name="client">The KubeCertificateManagerClient instance.</param>
    /// <param name="namespaceName">Namespace to list secrets from.</param>
    /// <param name="labelSelector">Optional label selector.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of V1Secret objects.</returns>
    public static async Task<V1SecretList> ListSecretsAsync(
        this KubeCertificateManagerClient client,
        string namespaceName,
        string labelSelector = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);

        var k8sClient = client.GetKubernetesClient();
        return await k8sClient.CoreV1.ListNamespacedSecretAsync(
            namespaceName,
            labelSelector: labelSelector,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Asynchronously lists all secrets across all namespaces.
    /// </summary>
    /// <param name="client">The KubeCertificateManagerClient instance.</param>
    /// <param name="labelSelector">Optional label selector.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of V1Secret objects from all namespaces.</returns>
    public static async Task<V1SecretList> ListSecretsAllNamespacesAsync(
        this KubeCertificateManagerClient client,
        string labelSelector = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);

        var k8sClient = client.GetKubernetesClient();
        return await k8sClient.CoreV1.ListSecretForAllNamespacesAsync(
            labelSelector: labelSelector,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Asynchronously creates or updates a secret.
    /// </summary>
    /// <param name="client">The KubeCertificateManagerClient instance.</param>
    /// <param name="secret">The secret to create or update.</param>
    /// <param name="namespaceName">Namespace for the secret.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created or updated V1Secret.</returns>
    public static async Task<V1Secret> CreateOrUpdateSecretAsync(
        this KubeCertificateManagerClient client,
        V1Secret secret,
        string namespaceName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(secret);

        var existing = await client.GetSecretAsync(secret.Metadata.Name, namespaceName, cancellationToken);

        if (existing != null)
        {
            // Preserve resource version for update
            secret.Metadata.ResourceVersion = existing.Metadata.ResourceVersion;
            return await client.UpdateSecretAsync(secret, namespaceName, cancellationToken);
        }
        else
        {
            return await client.CreateSecretAsync(secret, namespaceName, cancellationToken);
        }
    }

    /// <summary>
    /// Asynchronously lists all namespaces.
    /// </summary>
    /// <param name="client">The KubeCertificateManagerClient instance.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of V1Namespace objects.</returns>
    public static async Task<V1NamespaceList> ListNamespacesAsync(
        this KubeCertificateManagerClient client,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);

        var k8sClient = client.GetKubernetesClient();
        return await k8sClient.CoreV1.ListNamespaceAsync(cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Asynchronously gets a Certificate Signing Request.
    /// </summary>
    /// <param name="client">The KubeCertificateManagerClient instance.</param>
    /// <param name="name">Name of the CSR.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The V1CertificateSigningRequest if found; otherwise, null.</returns>
    public static async Task<V1CertificateSigningRequest> GetCsrAsync(
        this KubeCertificateManagerClient client,
        string name,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);

        try
        {
            var k8sClient = client.GetKubernetesClient();
            return await k8sClient.CertificatesV1.ReadCertificateSigningRequestAsync(
                name,
                cancellationToken: cancellationToken);
        }
        catch (k8s.Autorest.HttpOperationException ex) when (ex.Response?.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
    }

    /// <summary>
    /// Asynchronously lists all Certificate Signing Requests.
    /// </summary>
    /// <param name="client">The KubeCertificateManagerClient instance.</param>
    /// <param name="labelSelector">Optional label selector.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of V1CertificateSigningRequest objects.</returns>
    public static async Task<V1CertificateSigningRequestList> ListCsrsAsync(
        this KubeCertificateManagerClient client,
        string labelSelector = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);

        var k8sClient = client.GetKubernetesClient();
        return await k8sClient.CertificatesV1.ListCertificateSigningRequestAsync(
            labelSelector: labelSelector,
            cancellationToken: cancellationToken);
    }
}

/// <summary>
/// Partial class to add the GetKubernetesClient method to KubeCertificateManagerClient.
/// </summary>
public partial class KubeCertificateManagerClient
{
    private IKubernetes _cachedK8sClient;

    /// <summary>
    /// Gets the underlying IKubernetes client for async operations.
    /// </summary>
    /// <returns>The IKubernetes client instance.</returns>
    public IKubernetes GetKubernetesClient()
    {
        if (_cachedK8sClient != null)
            return _cachedK8sClient;

        // Use reflection to access the private _client field
        var field = typeof(KubeCertificateManagerClient)
            .GetField("_client", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

        if (field != null)
        {
            _cachedK8sClient = field.GetValue(this) as IKubernetes;
            return _cachedK8sClient;
        }

        throw new InvalidOperationException("Unable to access the underlying Kubernetes client.");
    }
}
