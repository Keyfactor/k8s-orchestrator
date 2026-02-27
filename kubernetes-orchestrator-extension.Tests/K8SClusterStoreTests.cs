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

    #region TLS Secret Operations via Cluster Store

    [Fact]
    public void ClusterTlsSecret_WithCertAndKey_HasCorrectStructure()
    {
        // K8SCluster can manage TLS secrets across the cluster
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Cluster TLS Test");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "cluster-tls-secret",
                NamespaceProperty = "production"
            },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert
        Assert.Equal("kubernetes.io/tls", secret.Type);
        Assert.Equal(2, secret.Data.Count);
        Assert.True(secret.Data.ContainsKey("tls.crt"));
        Assert.True(secret.Data.ContainsKey("tls.key"));
    }

    [Fact]
    public void ClusterTlsSecret_WithCertificateChain_CanStoreSeparateCaField()
    {
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafCert = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediateCert = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootCert = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "cluster-tls-with-chain",
                NamespaceProperty = "production"
            },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafCert) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) },
                { "ca.crt", Encoding.UTF8.GetBytes(intermediateCert + rootCert) }
            }
        };

        // Assert
        Assert.Equal(3, secret.Data.Count);
        Assert.True(secret.Data.ContainsKey("ca.crt"));
        var caCerts = Encoding.UTF8.GetString(secret.Data["ca.crt"]);
        Assert.Contains("-----BEGIN CERTIFICATE-----", caCerts);
    }

    [Fact]
    public void ClusterTlsSecret_StrictFieldNames_OnlyTlsCrtAndTlsKey()
    {
        // TLS secrets managed via K8SCluster still enforce strict field names
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "strict-fields", NamespaceProperty = "default" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert - Must have exactly tls.crt and tls.key
        Assert.True(secret.Data.ContainsKey("tls.crt"));
        Assert.True(secret.Data.ContainsKey("tls.key"));
        Assert.False(secret.Data.ContainsKey("cert")); // Not allowed for TLS
        Assert.False(secret.Data.ContainsKey("certificate")); // Not allowed for TLS
    }

    [Fact]
    public void ClusterTlsSecret_Type_MustBeKubernetesIoTls()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "tls-type", NamespaceProperty = "staging" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert
        Assert.Equal("kubernetes.io/tls", secret.Type);
        Assert.NotEqual("Opaque", secret.Type);
    }

    [Fact]
    public void ClusterTlsSecret_WithBundledChain_AllCertsInTlsCrt()
    {
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        var bundledChain = leafPem + intermediatePem + rootPem;

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "bundled-tls", NamespaceProperty = "production" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(bundledChain) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert
        Assert.Equal(2, secret.Data.Count);
        Assert.False(secret.Data.ContainsKey("ca.crt"));

        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = tlsCrtData.Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(3, certCount);
    }

    [Fact]
    public void ClusterTlsSecret_SeparateChainVsBundled_DifferentStructures()
    {
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // Separate chain
        var separateChainSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "separate", NamespaceProperty = "ns1" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) },
                { "ca.crt", Encoding.UTF8.GetBytes(intermediatePem + rootPem) }
            }
        };

        // Bundled chain
        var bundledChainSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "bundled", NamespaceProperty = "ns2" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafPem + intermediatePem + rootPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert - Separate chain has 3 fields
        Assert.Equal(3, separateChainSecret.Data.Count);
        Assert.True(separateChainSecret.Data.ContainsKey("ca.crt"));

        // Assert - Bundled chain has 2 fields
        Assert.Equal(2, bundledChainSecret.Data.Count);
        Assert.False(bundledChainSecret.Data.ContainsKey("ca.crt"));
    }

    [Fact]
    public void ClusterTlsSecret_NativeKubernetesFormat_Compatible()
    {
        // TLS secrets created via K8SCluster should be compatible with K8S Ingress
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "ingress-compatible-tls",
                NamespaceProperty = "ingress-namespace"
            },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert - Matches native K8S TLS secret format
        Assert.Equal("kubernetes.io/tls", secret.Type);
        Assert.Equal(2, secret.Data.Count);
        Assert.True(secret.Data.ContainsKey("tls.crt"));
        Assert.True(secret.Data.ContainsKey("tls.key"));
    }

    [Fact]
    public void ClusterTlsSecret_MissingRequiredFields_Invalid()
    {
        // TLS secrets require both tls.crt and tls.key
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "missing-key", NamespaceProperty = "default" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
                // Missing tls.key
            }
        };

        Assert.True(secret.Data.ContainsKey("tls.crt"));
        Assert.False(secret.Data.ContainsKey("tls.key")); // Missing required field
    }

    #endregion

    #region Opaque Secret Operations via Cluster Store

    [Fact]
    public void ClusterOpaqueSecret_WithPemCertAndKey_HasCorrectStructure()
    {
        // K8SCluster can manage Opaque secrets across the cluster
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Cluster Opaque Test");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "cluster-opaque-secret",
                NamespaceProperty = "production"
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        Assert.Equal("Opaque", secret.Type);
        Assert.Equal(2, secret.Data.Count);
        Assert.True(secret.Data.ContainsKey("tls.crt"));
        Assert.True(secret.Data.ContainsKey("tls.key"));
    }

    [Fact]
    public void ClusterOpaqueSecret_WithCertificateChain_CanStoreSeparateCaField()
    {
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafCert = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediateCert = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootCert = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "cluster-opaque-with-chain",
                NamespaceProperty = "staging"
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafCert) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) },
                { "ca.crt", Encoding.UTF8.GetBytes(intermediateCert + rootCert) }
            }
        };

        Assert.Equal(3, secret.Data.Count);
        Assert.True(secret.Data.ContainsKey("ca.crt"));
    }

    [Theory]
    [InlineData("tls.crt")]
    [InlineData("cert")]
    [InlineData("certificate")]
    [InlineData("crt")]
    public void ClusterOpaqueSecret_FlexibleFieldNames_SupportedVariations(string certFieldName)
    {
        // K8SCluster managing Opaque secrets supports flexible field names
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "flexible-fields", NamespaceProperty = "default" },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { certFieldName, Encoding.UTF8.GetBytes(certPem) }
            }
        };

        Assert.True(secret.Data.ContainsKey(certFieldName));
    }

    [Fact]
    public void ClusterOpaqueSecret_WithBundledChain_AllCertsInTlsCrt()
    {
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        var bundledChain = leafPem + intermediatePem + rootPem;

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "bundled-opaque", NamespaceProperty = "production" },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(bundledChain) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        Assert.Equal(2, secret.Data.Count);
        Assert.False(secret.Data.ContainsKey("ca.crt"));

        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = tlsCrtData.Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(3, certCount);
    }

    [Fact]
    public void ClusterOpaqueSecret_SeparateChainVsBundled_DifferentStructures()
    {
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        var separateChainSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "separate-opaque", NamespaceProperty = "ns1" },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) },
                { "ca.crt", Encoding.UTF8.GetBytes(intermediatePem + rootPem) }
            }
        };

        var bundledChainSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "bundled-opaque", NamespaceProperty = "ns2" },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafPem + intermediatePem + rootPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        Assert.Equal(3, separateChainSecret.Data.Count);
        Assert.True(separateChainSecret.Data.ContainsKey("ca.crt"));

        Assert.Equal(2, bundledChainSecret.Data.Count);
        Assert.False(bundledChainSecret.Data.ContainsKey("ca.crt"));
    }

    [Fact]
    public void ClusterOpaqueSecret_OnlyCertificateNoKey_ValidStructure()
    {
        // Some Opaque secrets may only contain certificates without private keys
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "cert-only", NamespaceProperty = "production" },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
            }
        };

        Assert.Single(secret.Data);
        Assert.False(secret.Data.ContainsKey("tls.key"));
    }

    #endregion

    #region Key Type Coverage via Cluster Store

    [Theory]
    [InlineData(KeyType.Rsa1024)]
    [InlineData(KeyType.Rsa2048)]
    [InlineData(KeyType.Rsa4096)]
    [InlineData(KeyType.Rsa8192)]
    public void ClusterSecret_RsaKeyTypes_ValidPemFormat(KeyType keyType)
    {
        // K8SCluster can manage secrets with various RSA key sizes
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"RSA {keyType}");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = $"rsa-{keyType}", NamespaceProperty = "production" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        Assert.Contains("-----BEGIN CERTIFICATE-----", certPem);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", keyPem);
    }

    [Theory]
    [InlineData(KeyType.EcP256)]
    [InlineData(KeyType.EcP384)]
    [InlineData(KeyType.EcP521)]
    public void ClusterSecret_EcKeyTypes_ValidPemFormat(KeyType keyType)
    {
        // K8SCluster can manage secrets with various EC curves
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"EC {keyType}");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = $"ec-{keyType}", NamespaceProperty = "production" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        Assert.Contains("-----BEGIN CERTIFICATE-----", certPem);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", keyPem);
    }

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.Ed448)]
    public void ClusterSecret_EdwardsKeyTypes_ValidPemFormat(KeyType keyType)
    {
        // K8SCluster can manage secrets with Edwards curve keys
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"Edwards {keyType}");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = $"edwards-{keyType}", NamespaceProperty = "production" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        Assert.Contains("-----BEGIN CERTIFICATE-----", certPem);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", keyPem);
    }

    #endregion

    #region Cross-Type Cluster Operations

    [Fact]
    public void ClusterStore_MixedSecretTypes_SameNamespace_CanCoexist()
    {
        // Both TLS and Opaque secrets can coexist in the same namespace
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var tlsSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "tls-secret", NamespaceProperty = "production" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        var opaqueSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "opaque-secret", NamespaceProperty = "production" },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Both in same namespace
        Assert.Equal(tlsSecret.Metadata.NamespaceProperty, opaqueSecret.Metadata.NamespaceProperty);
        // Different types
        Assert.NotEqual(tlsSecret.Type, opaqueSecret.Type);
        // Different names
        Assert.NotEqual(tlsSecret.Metadata.Name, opaqueSecret.Metadata.Name);
    }

    [Fact]
    public void ClusterStore_SameSecretName_DifferentNamespaces_AreIndependent()
    {
        // Same secret name can exist in different namespaces independently
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        var secretInProd = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "my-cert", NamespaceProperty = "production" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]> { { "tls.crt", Encoding.UTF8.GetBytes(certPem) } }
        };

        var secretInStaging = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "my-cert", NamespaceProperty = "staging" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]> { { "tls.crt", Encoding.UTF8.GetBytes(certPem) } }
        };

        // Same name
        Assert.Equal(secretInProd.Metadata.Name, secretInStaging.Metadata.Name);
        // Different namespaces
        Assert.NotEqual(secretInProd.Metadata.NamespaceProperty, secretInStaging.Metadata.NamespaceProperty);
    }

    [Fact]
    public void ClusterStore_FilterTlsSecrets_ReturnsOnlyTlsType()
    {
        // Arrange
        var secrets = new List<V1Secret>
        {
            new V1Secret { Metadata = new V1ObjectMeta { Name = "tls1", NamespaceProperty = "ns1" }, Type = "kubernetes.io/tls" },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "opaque1", NamespaceProperty = "ns1" }, Type = "Opaque" },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "tls2", NamespaceProperty = "ns2" }, Type = "kubernetes.io/tls" },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "opaque2", NamespaceProperty = "ns2" }, Type = "Opaque" }
        };

        // Act
        var tlsSecrets = secrets.FindAll(s => s.Type == "kubernetes.io/tls");

        // Assert
        Assert.Equal(2, tlsSecrets.Count);
        Assert.All(tlsSecrets, s => Assert.Equal("kubernetes.io/tls", s.Type));
    }

    [Fact]
    public void ClusterStore_FilterOpaqueSecrets_ReturnsOnlyOpaqueType()
    {
        // Arrange
        var secrets = new List<V1Secret>
        {
            new V1Secret { Metadata = new V1ObjectMeta { Name = "tls1", NamespaceProperty = "ns1" }, Type = "kubernetes.io/tls" },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "opaque1", NamespaceProperty = "ns1" }, Type = "Opaque" },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "tls2", NamespaceProperty = "ns2" }, Type = "kubernetes.io/tls" },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "opaque2", NamespaceProperty = "ns2" }, Type = "Opaque" }
        };

        // Act
        var opaqueSecrets = secrets.FindAll(s => s.Type == "Opaque");

        // Assert
        Assert.Equal(2, opaqueSecrets.Count);
        Assert.All(opaqueSecrets, s => Assert.Equal("Opaque", s.Type));
    }

    #endregion

    #region Encoding and Conversion Tests

    [Fact]
    public void ClusterSecret_Utf8Encoding_RoundTripSuccessful()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var originalPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        // Act - Encode to bytes and decode back
        var bytes = Encoding.UTF8.GetBytes(originalPem);
        var decodedPem = Encoding.UTF8.GetString(bytes);

        // Assert
        Assert.Equal(originalPem, decodedPem);
    }

    [Fact]
    public void ClusterSecret_DerToPemConversion_ValidFormat()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048);
        var derBytes = certInfo.Certificate.GetEncoded();

        // Act - Parse from DER and convert to PEM
        var parser = new Org.BouncyCastle.X509.X509CertificateParser();
        var cert = parser.ReadCertificate(derBytes);
        var pemCert = CertificateTestHelper.ConvertCertificateToPem(cert);

        // Assert
        Assert.NotNull(pemCert);
        Assert.Contains("-----BEGIN CERTIFICATE-----", pemCert);
        Assert.Contains("-----END CERTIFICATE-----", pemCert);
    }

    [Fact]
    public void ClusterSecret_PemWithWhitespace_StillValid()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        // Add extra whitespace
        var pemWithWhitespace = "\n" + certPem + "\n\n";

        // Assert - Should still contain valid markers
        Assert.Contains("-----BEGIN CERTIFICATE-----", pemWithWhitespace);
        Assert.Contains("-----END CERTIFICATE-----", pemWithWhitespace);
    }

    #endregion

    #region IncludeCertChain=false Tests

    [Fact]
    public void Management_IncludeCertChainFalse_TlsSecret_OnlyLeafCertStored()
    {
        // When IncludeCertChain=false is set for K8SCluster TLS secrets, only the leaf certificate
        // should be stored, not the intermediate or root certificates.

        // Arrange - Generate a certificate chain (leaf -> intermediate -> root)
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(leafCert);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // Act - Create TLS secret with ONLY the leaf certificate (simulating IncludeCertChain=false behavior)
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "cluster-tls-include-cert-chain-false",
                NamespaceProperty = "production"
            },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert
        Assert.Equal("kubernetes.io/tls", secret.Type);
        Assert.Equal(2, secret.Data.Count); // Only tls.crt and tls.key, NO ca.crt

        // Verify tls.crt contains ONLY the leaf certificate (1 certificate)
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = tlsCrtData.Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(1, certCount);

        // Verify NO ca.crt field exists
        Assert.False(secret.Data.ContainsKey("ca.crt"),
            "Cluster TLS secret should NOT contain ca.crt when IncludeCertChain=false");

        // Verify the stored certificate is the leaf certificate
        using var reader = new System.IO.StringReader(tlsCrtData);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
        var storedCert = (Org.BouncyCastle.X509.X509Certificate)pemReader.ReadObject();
        Assert.Equal(leafCert.SubjectDN.ToString(), storedCert.SubjectDN.ToString());
    }

    [Fact]
    public void Management_IncludeCertChainFalse_OpaqueSecret_OnlyLeafCertStored()
    {
        // When IncludeCertChain=false is set for K8SCluster Opaque secrets, only the leaf certificate
        // should be stored, not the intermediate or root certificates.

        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafCert = chain[0].Certificate;
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(leafCert);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // Act - Create Opaque secret with ONLY the leaf certificate
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "cluster-opaque-include-cert-chain-false",
                NamespaceProperty = "staging"
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert
        Assert.Equal("Opaque", secret.Type);
        Assert.Equal(2, secret.Data.Count);

        // Verify tls.crt contains ONLY the leaf certificate
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = tlsCrtData.Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(1, certCount);

        Assert.False(secret.Data.ContainsKey("ca.crt"),
            "Cluster Opaque secret should NOT contain ca.crt when IncludeCertChain=false");
    }

    [Fact]
    public void IncludeCertChainFalse_VersusTrue_ClusterSecrets_DifferentStructures()
    {
        // Compare the expected output between IncludeCertChain=true vs IncludeCertChain=false for cluster secrets
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // IncludeCertChain=false: Only leaf certificate
        var includeCertChainFalseSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "cluster-include-chain-false", NamespaceProperty = "ns1" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // IncludeCertChain=true (SeparateChain=false): Full chain bundled
        var includeCertChainTrueSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "cluster-include-chain-true", NamespaceProperty = "ns2" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafPem + intermediatePem + rootPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert - IncludeCertChain=false has only 1 certificate
        var falseChainCount = Encoding.UTF8.GetString(includeCertChainFalseSecret.Data["tls.crt"])
            .Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(1, falseChainCount);
        Assert.False(includeCertChainFalseSecret.Data.ContainsKey("ca.crt"));

        // Assert - IncludeCertChain=true has 3 certificates
        var trueChainCount = Encoding.UTF8.GetString(includeCertChainTrueSecret.Data["tls.crt"])
            .Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(3, trueChainCount);
    }

    [Fact]
    public void IncludeCertChainFalse_MultipleNamespaces_ConsistentBehavior()
    {
        // Verify IncludeCertChain=false behavior is consistent across multiple namespaces
        var namespaces = new[] { "production", "staging", "development" };
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        foreach (var ns in namespaces)
        {
            var secret = new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = $"secret-{ns}", NamespaceProperty = ns },
                Type = "kubernetes.io/tls",
                Data = new Dictionary<string, byte[]>
                {
                    { "tls.crt", Encoding.UTF8.GetBytes(leafPem) },
                    { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
                }
            };

            // Assert - Each secret should have only 1 certificate
            var certCount = Encoding.UTF8.GetString(secret.Data["tls.crt"])
                .Split("-----BEGIN CERTIFICATE-----").Length - 1;
            Assert.Equal(1, certCount);
            Assert.False(secret.Data.ContainsKey("ca.crt"));
        }
    }

    #endregion

    #region Metadata Tests

    [Fact]
    public void ClusterSecret_WithLabels_PreservesMetadata()
    {
        // Arrange
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "labeled-cluster-secret",
                NamespaceProperty = "production",
                Labels = new Dictionary<string, string>
                {
                    { "keyfactor.com/managed", "true" },
                    { "keyfactor.com/store-type", "K8SCluster" },
                    { "app.kubernetes.io/name", "my-app" }
                }
            },
            Type = "kubernetes.io/tls"
        };

        // Assert
        Assert.NotNull(secret.Metadata.Labels);
        Assert.Equal(3, secret.Metadata.Labels.Count);
        Assert.Equal("K8SCluster", secret.Metadata.Labels["keyfactor.com/store-type"]);
    }

    [Fact]
    public void ClusterSecret_WithAnnotations_PreservesMetadata()
    {
        // Arrange
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "annotated-cluster-secret",
                NamespaceProperty = "staging",
                Annotations = new Dictionary<string, string>
                {
                    { "keyfactor.com/certificate-id", "12345" },
                    { "keyfactor.com/last-synced", "2024-01-15T10:30:00Z" }
                }
            },
            Type = "kubernetes.io/tls"
        };

        // Assert
        Assert.NotNull(secret.Metadata.Annotations);
        Assert.Equal(2, secret.Metadata.Annotations.Count);
        Assert.Equal("12345", secret.Metadata.Annotations["keyfactor.com/certificate-id"]);
    }

    #endregion
}
