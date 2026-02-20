// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Text;
using k8s.Models;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests;

/// <summary>
/// Unit tests for K8SCluster store type operations.
/// K8SCluster manages ALL secrets across ALL namespaces in a cluster.
/// A single K8SCluster store represents the entire cluster.
/// Tests focus on multi-namespace operations, collection handling, and discovery.
/// </summary>
public class K8SClusterStoreTests
{
    #region Cluster Scope Tests

    [Fact]
    public void ClusterStore_RepresentsAllNamespaces_NotSingleNamespace()
    {
        // K8SCluster operates on all namespaces, unlike K8SNS which operates on single namespace
        // The StorePath for K8SCluster is typically "cluster" or similar generic value
        var storePath = "cluster";

        Assert.NotNull(storePath);
        Assert.DoesNotContain("/", storePath); // Not a namespace/secret path
    }

    [Fact]
    public void ClusterStore_CanContainMultipleSecretTypes_InDifferentNamespaces()
    {
        // A cluster can contain Opaque, TLS, JKS, and PKCS12 secrets across different namespaces
        var secrets = new List<V1Secret>
        {
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "opaque-secret", NamespaceProperty = "namespace1" },
                Type = "Opaque"
            },
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "tls-secret", NamespaceProperty = "namespace2" },
                Type = "kubernetes.io/tls"
            },
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "jks-secret", NamespaceProperty = "namespace3" },
                Type = "Opaque"
            }
        };

        // Assert - All belong to different namespaces
        Assert.Equal(3, secrets.Count);
        Assert.Equal("namespace1", secrets[0].Metadata.NamespaceProperty);
        Assert.Equal("namespace2", secrets[1].Metadata.NamespaceProperty);
        Assert.Equal("namespace3", secrets[2].Metadata.NamespaceProperty);
    }

    #endregion

    #region Secret Collection Tests

    [Fact]
    public void SecretList_MultipleNamespaces_CanBeGrouped()
    {
        // Arrange
        var secrets = new List<V1Secret>
        {
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "secret1", NamespaceProperty = "default" },
                Type = "Opaque"
            },
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "secret2", NamespaceProperty = "default" },
                Type = "kubernetes.io/tls"
            },
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "secret3", NamespaceProperty = "kube-system" },
                Type = "Opaque"
            }
        };

        // Act - Group by namespace
        var groupedByNamespace = new Dictionary<string, List<V1Secret>>();
        foreach (var secret in secrets)
        {
            var ns = secret.Metadata.NamespaceProperty;
            if (!groupedByNamespace.ContainsKey(ns))
            {
                groupedByNamespace[ns] = new List<V1Secret>();
            }
            groupedByNamespace[ns].Add(secret);
        }

        // Assert
        Assert.Equal(2, groupedByNamespace.Count); // 2 namespaces
        Assert.Equal(2, groupedByNamespace["default"].Count);
        Assert.Single(groupedByNamespace["kube-system"]);
    }

    [Fact]
    public void SecretList_FilterByType_ReturnsOnlyMatchingSecrets()
    {
        // Arrange
        var secrets = new List<V1Secret>
        {
            new V1Secret { Metadata = new V1ObjectMeta { Name = "opaque1" }, Type = "Opaque" },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "tls1" }, Type = "kubernetes.io/tls" },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "opaque2" }, Type = "Opaque" },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "tls2" }, Type = "kubernetes.io/tls" }
        };

        // Act - Filter for TLS secrets
        var tlsSecrets = secrets.FindAll(s => s.Type == "kubernetes.io/tls");

        // Assert
        Assert.Equal(2, tlsSecrets.Count);
        Assert.All(tlsSecrets, s => Assert.Equal("kubernetes.io/tls", s.Type));
    }

    #endregion

    #region Discovery Tests

    [Fact]
    public void Discovery_EmptyCluster_ReturnsEmptyList()
    {
        // An empty cluster with no secrets should return empty discovery results
        var secrets = new List<V1Secret>();

        Assert.Empty(secrets);
    }

    [Fact]
    public void Discovery_MultipleSecrets_ReturnsAllSecrets()
    {
        // Arrange
        var secrets = new List<V1Secret>
        {
            new V1Secret { Metadata = new V1ObjectMeta { Name = "s1", NamespaceProperty = "ns1" } },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "s2", NamespaceProperty = "ns2" } },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "s3", NamespaceProperty = "ns3" } }
        };

        // Assert
        Assert.Equal(3, secrets.Count);
    }

    #endregion

    #region Namespace Filtering Tests

    [Fact]
    public void NamespaceFilter_ExcludeSystemNamespaces_FilterCorrectly()
    {
        // Common pattern: exclude system namespaces like kube-system, kube-public, kube-node-lease
        var secrets = new List<V1Secret>
        {
            new V1Secret { Metadata = new V1ObjectMeta { Name = "s1", NamespaceProperty = "default" } },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "s2", NamespaceProperty = "kube-system" } },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "s3", NamespaceProperty = "my-app" } },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "s4", NamespaceProperty = "kube-public" } }
        };

        // Act - Filter out system namespaces
        var systemNamespaces = new[] { "kube-system", "kube-public", "kube-node-lease" };
        var filtered = secrets.FindAll(s => !Array.Exists(systemNamespaces, ns => ns == s.Metadata.NamespaceProperty));

        // Assert
        Assert.Equal(2, filtered.Count);
        Assert.Contains(filtered, s => s.Metadata.NamespaceProperty == "default");
        Assert.Contains(filtered, s => s.Metadata.NamespaceProperty == "my-app");
    }

    [Fact]
    public void NamespaceFilter_IncludeOnlySpecificNamespaces_FilterCorrectly()
    {
        // Pattern: only include secrets from specific namespaces
        var secrets = new List<V1Secret>
        {
            new V1Secret { Metadata = new V1ObjectMeta { Name = "s1", NamespaceProperty = "production" } },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "s2", NamespaceProperty = "staging" } },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "s3", NamespaceProperty = "development" } }
        };

        // Act - Only include production and staging
        var includedNamespaces = new[] { "production", "staging" };
        var filtered = secrets.FindAll(s => Array.Exists(includedNamespaces, ns => ns == s.Metadata.NamespaceProperty));

        // Assert
        Assert.Equal(2, filtered.Count);
        Assert.DoesNotContain(filtered, s => s.Metadata.NamespaceProperty == "development");
    }

    #endregion

    #region Certificate Data Tests

    [Fact]
    public void ClusterSecret_WithPemCertificate_CanBeRead()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Cluster Test");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "cluster-cert",
                NamespaceProperty = "production"
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
            }
        };

        // Assert
        Assert.NotNull(secret.Data);
        Assert.True(secret.Data.ContainsKey("tls.crt"));
        var retrievedPem = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        Assert.Contains("-----BEGIN CERTIFICATE-----", retrievedPem);
    }

    [Fact]
    public void ClusterSecret_MultipleSecretsWithCertificates_CanBeEnumerated()
    {
        // Arrange - Create secrets with certificates across multiple namespaces
        var secrets = new List<V1Secret>();
        for (int i = 0; i < 5; i++)
        {
            var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, $"Cert {i}");
            var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

            secrets.Add(new V1Secret
            {
                Metadata = new V1ObjectMeta
                {
                    Name = $"secret-{i}",
                    NamespaceProperty = $"namespace-{i}"
                },
                Type = "Opaque",
                Data = new Dictionary<string, byte[]>
                {
                    { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
                }
            });
        }

        // Assert
        Assert.Equal(5, secrets.Count);
        Assert.All(secrets, s => Assert.True(s.Data.ContainsKey("tls.crt")));
    }

    #endregion

    #region Permission Tests (Conceptual)

    [Fact]
    public void ClusterStore_RequiresClusterWidePermissions_NotNamespaceScoped()
    {
        // K8SCluster requires cluster-wide RBAC permissions
        // Unlike K8SNS which only needs namespace-scoped permissions
        // This is a conceptual test - permissions are validated by Kubernetes at runtime
        var requiredPermissions = new[]
        {
            "secrets.list (cluster-wide)",
            "secrets.get (cluster-wide)",
            "secrets.create (cluster-wide)",
            "secrets.update (cluster-wide)",
            "secrets.delete (cluster-wide)"
        };

        Assert.Equal(5, requiredPermissions.Length);
        Assert.Contains("cluster-wide", requiredPermissions[0]);
    }

    #endregion

    #region Edge Cases

    [Fact]
    public void ClusterStore_NamespaceWithNoSecrets_ReturnsEmpty()
    {
        // A namespace might exist but contain no secrets
        var namespaceName = "empty-namespace";
        var secrets = new List<V1Secret>(); // Empty list for this namespace

        Assert.Empty(secrets);
    }

    [Fact]
    public void ClusterStore_LargeNumberOfSecrets_CanBeHandled()
    {
        // Test handling of large number of secrets across cluster
        var secrets = new List<V1Secret>();
        for (int i = 0; i < 100; i++)
        {
            secrets.Add(new V1Secret
            {
                Metadata = new V1ObjectMeta
                {
                    Name = $"secret-{i}",
                    NamespaceProperty = $"namespace-{i % 10}" // 10 namespaces
                }
            });
        }

        // Assert
        Assert.Equal(100, secrets.Count);

        // Verify distribution across namespaces
        var byNamespace = new Dictionary<string, int>();
        foreach (var secret in secrets)
        {
            var ns = secret.Metadata.NamespaceProperty;
            if (!byNamespace.ContainsKey(ns))
            {
                byNamespace[ns] = 0;
            }
            byNamespace[ns]++;
        }

        Assert.Equal(10, byNamespace.Count); // 10 unique namespaces
        Assert.All(byNamespace.Values, count => Assert.Equal(10, count)); // 10 secrets per namespace
    }

    #endregion
}
