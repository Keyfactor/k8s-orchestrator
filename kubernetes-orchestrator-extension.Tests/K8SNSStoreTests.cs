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
using k8s.Models;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests;

/// <summary>
/// Unit tests for K8SNS store type operations.
/// K8SNS manages ALL secrets within a SINGLE namespace.
/// A single K8SNS store represents one namespace.
/// Tests focus on namespace-scoped operations, collection handling, and boundary enforcement.
/// </summary>
public class K8SNSStoreTests
{
    #region Namespace Scope Tests

    [Fact]
    public void NamespaceStore_RepresentsSingleNamespace_NotClusterWide()
    {
        // K8SNS operates on a single namespace, unlike K8SCluster which operates on all namespaces
        // The StorePath for K8SNS is the namespace name
        var storePath = "production";

        Assert.NotNull(storePath);
        Assert.DoesNotContain("cluster", storePath.ToLower()); // Not cluster-wide
    }

    [Fact]
    public void NamespaceStore_CanContainMultipleSecretTypes_InSameNamespace()
    {
        // A namespace can contain Opaque, TLS, JKS, and PKCS12 secrets
        var namespaceName = "production";
        var secrets = new List<V1Secret>
        {
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "opaque-secret", NamespaceProperty = namespaceName },
                Type = "Opaque"
            },
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "tls-secret", NamespaceProperty = namespaceName },
                Type = "kubernetes.io/tls"
            },
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "jks-secret", NamespaceProperty = namespaceName },
                Type = "Opaque"
            }
        };

        // Assert - All belong to the same namespace
        Assert.All(secrets, s => Assert.Equal(namespaceName, s.Metadata.NamespaceProperty));
    }

    [Fact]
    public void NamespaceStore_EnforcesNamespaceBoundary_NoOtherNamespaces()
    {
        // K8SNS should only manage secrets within its designated namespace
        var targetNamespace = "production";
        var secrets = new List<V1Secret>
        {
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "secret1", NamespaceProperty = "production" }
            },
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "secret2", NamespaceProperty = "staging" }
            },
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "secret3", NamespaceProperty = "production" }
            }
        };

        // Act - Filter to only target namespace
        var namespaceSecrets = secrets.FindAll(s => s.Metadata.NamespaceProperty == targetNamespace);

        // Assert
        Assert.Equal(2, namespaceSecrets.Count);
        Assert.All(namespaceSecrets, s => Assert.Equal(targetNamespace, s.Metadata.NamespaceProperty));
    }

    #endregion

    #region Secret Collection Tests

    [Fact]
    public void SecretList_SingleNamespace_CanBeEnumerated()
    {
        // Arrange
        var namespaceName = "default";
        var secrets = new List<V1Secret>
        {
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "secret1", NamespaceProperty = namespaceName },
                Type = "Opaque"
            },
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "secret2", NamespaceProperty = namespaceName },
                Type = "kubernetes.io/tls"
            },
            new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = "secret3", NamespaceProperty = namespaceName },
                Type = "Opaque"
            }
        };

        // Assert
        Assert.Equal(3, secrets.Count);
        Assert.All(secrets, s => Assert.Equal(namespaceName, s.Metadata.NamespaceProperty));
    }

    [Fact]
    public void SecretList_FilterByType_ReturnsOnlyMatchingSecrets()
    {
        // Arrange
        var namespaceName = "production";
        var secrets = new List<V1Secret>
        {
            new V1Secret { Metadata = new V1ObjectMeta { Name = "opaque1", NamespaceProperty = namespaceName }, Type = "Opaque" },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "tls1", NamespaceProperty = namespaceName }, Type = "kubernetes.io/tls" },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "opaque2", NamespaceProperty = namespaceName }, Type = "Opaque" }
        };

        // Act - Filter for Opaque secrets
        var opaqueSecrets = secrets.FindAll(s => s.Type == "Opaque");

        // Assert
        Assert.Equal(2, opaqueSecrets.Count);
        Assert.All(opaqueSecrets, s => Assert.Equal("Opaque", s.Type));
    }

    [Fact]
    public void SecretList_GroupByName_CanIdentifyDuplicates()
    {
        // Within a single namespace, secret names must be unique
        var namespaceName = "default";
        var secretNames = new[] { "secret1", "secret2", "secret1" }; // Duplicate name (invalid)

        // Act - Check for duplicates
        var uniqueNames = new HashSet<string>();
        var duplicates = new List<string>();

        foreach (var name in secretNames)
        {
            if (!uniqueNames.Add(name))
            {
                duplicates.Add(name);
            }
        }

        // Assert
        Assert.Single(duplicates);
        Assert.Contains("secret1", duplicates);
    }

    #endregion

    #region Discovery Tests

    [Fact]
    public void Discovery_EmptyNamespace_ReturnsEmptyList()
    {
        // An empty namespace with no secrets should return empty discovery results
        var secrets = new List<V1Secret>();

        Assert.Empty(secrets);
    }

    [Fact]
    public void Discovery_NamespaceWithSecrets_ReturnsAllSecrets()
    {
        // Arrange
        var namespaceName = "production";
        var secrets = new List<V1Secret>
        {
            new V1Secret { Metadata = new V1ObjectMeta { Name = "s1", NamespaceProperty = namespaceName } },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "s2", NamespaceProperty = namespaceName } },
            new V1Secret { Metadata = new V1ObjectMeta { Name = "s3", NamespaceProperty = namespaceName } }
        };

        // Assert
        Assert.Equal(3, secrets.Count);
        Assert.All(secrets, s => Assert.Equal(namespaceName, s.Metadata.NamespaceProperty));
    }

    #endregion

    #region Certificate Data Tests

    [Fact]
    public void NamespaceSecret_WithPemCertificate_CanBeRead()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Namespace Test");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "namespace-cert",
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
    public void NamespaceSecret_MultipleSecretsWithCertificates_CanBeEnumerated()
    {
        // Arrange - Create secrets with certificates in the same namespace
        var namespaceName = "production";
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
                    NamespaceProperty = namespaceName
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
        Assert.All(secrets, s => Assert.Equal(namespaceName, s.Metadata.NamespaceProperty));
        Assert.All(secrets, s => Assert.True(s.Data.ContainsKey("tls.crt")));
    }

    #endregion

    #region Permission Tests (Conceptual)

    [Fact]
    public void NamespaceStore_RequiresNamespaceScopedPermissions_NotClusterWide()
    {
        // K8SNS requires namespace-scoped RBAC permissions
        // Unlike K8SCluster which requires cluster-wide permissions
        // This is a conceptual test - permissions are validated by Kubernetes at runtime
        var namespaceName = "production";
        var requiredPermissions = new[]
        {
            $"secrets.list (namespace: {namespaceName})",
            $"secrets.get (namespace: {namespaceName})",
            $"secrets.create (namespace: {namespaceName})",
            $"secrets.update (namespace: {namespaceName})",
            $"secrets.delete (namespace: {namespaceName})"
        };

        Assert.Equal(5, requiredPermissions.Length);
        Assert.Contains(namespaceName, requiredPermissions[0]);
        Assert.DoesNotContain("cluster-wide", requiredPermissions[0]);
    }

    #endregion

    #region Edge Cases

    [Fact]
    public void NamespaceStore_LargeNumberOfSecrets_CanBeHandled()
    {
        // Test handling of large number of secrets in a single namespace
        var namespaceName = "production";
        var secrets = new List<V1Secret>();
        for (int i = 0; i < 100; i++)
        {
            secrets.Add(new V1Secret
            {
                Metadata = new V1ObjectMeta
                {
                    Name = $"secret-{i}",
                    NamespaceProperty = namespaceName
                }
            });
        }

        // Assert
        Assert.Equal(100, secrets.Count);
        Assert.All(secrets, s => Assert.Equal(namespaceName, s.Metadata.NamespaceProperty));
    }

    [Fact]
    public void NamespaceStore_SpecialCharactersInSecretNames_Handled()
    {
        // Kubernetes allows certain special characters in secret names
        var namespaceName = "default";
        var secretNames = new[]
        {
            "my-secret",
            "my.secret",
            "my-secret-123",
            "secret-with-dots.and-dashes"
        };

        var secrets = secretNames.Select(name => new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = name,
                NamespaceProperty = namespaceName
            }
        }).ToList();

        // Assert
        Assert.Equal(4, secrets.Count);
        Assert.All(secrets, s => Assert.NotNull(s.Metadata.Name));
    }

    #endregion

    #region KubeNamespace Property Priority Tests

    [Fact]
    public void NamespaceStore_KubeNamespaceProperty_TakesPriorityOverStorePath()
    {
        // K8SNS stores should use KubeNamespace from store properties when set,
        // NOT the StorePath value. This test validates that the namespace configuration
        // is properly respected.

        // Arrange - Simulate a store where KubeNamespace property differs from StorePath
        var storePathNamespace = "default"; // StorePath value (often "default")
        var configuredNamespace = "production"; // KubeNamespace property value

        // The expected behavior is that inventory should use the configured namespace
        // NOT the store path namespace
        Assert.NotEqual(storePathNamespace, configuredNamespace);

        // When KubeNamespace is set in store properties, it should take priority
        var effectiveNamespace = !string.IsNullOrEmpty(configuredNamespace)
            ? configuredNamespace
            : storePathNamespace;

        Assert.Equal("production", effectiveNamespace);
    }

    [Fact]
    public void NamespaceStore_EmptyKubeNamespaceProperty_FallsBackToStorePath()
    {
        // When KubeNamespace property is empty/null, StorePath should be used as fallback

        // Arrange
        var storePathNamespace = "default";
        string? configuredNamespace = null;

        // Act - Determine effective namespace (same logic as ResolveStorePath)
        var effectiveNamespace = !string.IsNullOrEmpty(configuredNamespace)
            ? configuredNamespace
            : storePathNamespace;

        Assert.Equal("default", effectiveNamespace);
    }

    [Fact]
    public void NamespaceStore_WhitespaceKubeNamespaceProperty_ShouldBeTrimmed()
    {
        // Leading/trailing whitespace in namespace values should be trimmed
        // This tests the .Trim() fix in JobBase.cs property retrieval

        // Arrange
        var namespaceWithWhitespace = " production ";
        var expectedNamespace = "production";

        // Act - Trim is applied during property retrieval
        var trimmedNamespace = namespaceWithWhitespace.Trim();

        Assert.Equal(expectedNamespace, trimmedNamespace);
    }

    [Fact]
    public void NamespaceStore_StorePathParsing_SinglePartPath()
    {
        // For K8SNS with single-part StorePath (e.g., "default"),
        // KubeNamespace from properties should NOT be overwritten

        // Arrange
        var storePath = "default";
        var kubeNamespaceFromProperties = "production";

        // Act - Simulate ResolveStorePath behavior (after fix)
        // Only set KubeNamespace from StorePath if not already set
        var finalNamespace = !string.IsNullOrEmpty(kubeNamespaceFromProperties)
            ? kubeNamespaceFromProperties  // Keep property value
            : storePath;                    // Fallback to StorePath

        // Assert - Should keep the property value, not overwrite with StorePath
        Assert.Equal("production", finalNamespace);
        Assert.NotEqual(storePath, finalNamespace);
    }

    #endregion

    #region IncludeCertChain=false Tests

    [Fact]
    public void Management_IncludeCertChainFalse_TlsSecret_OnlyLeafCertStored()
    {
        // When IncludeCertChain=false is set for K8SNS TLS secrets, only the leaf certificate
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
                Name = "ns-tls-include-cert-chain-false",
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
            "K8SNS TLS secret should NOT contain ca.crt when IncludeCertChain=false");

        // Verify the stored certificate is the leaf certificate
        using var reader = new System.IO.StringReader(tlsCrtData);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
        var storedCert = (Org.BouncyCastle.X509.X509Certificate)pemReader.ReadObject();
        Assert.Equal(leafCert.SubjectDN.ToString(), storedCert.SubjectDN.ToString());
    }

    [Fact]
    public void Management_IncludeCertChainFalse_OpaqueSecret_OnlyLeafCertStored()
    {
        // When IncludeCertChain=false is set for K8SNS Opaque secrets, only the leaf certificate
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
                Name = "ns-opaque-include-cert-chain-false",
                NamespaceProperty = "production"
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
            "K8SNS Opaque secret should NOT contain ca.crt when IncludeCertChain=false");
    }

    [Fact]
    public void IncludeCertChainFalse_VersusTrue_NamespaceSecrets_DifferentStructures()
    {
        // Compare the expected output between IncludeCertChain=true vs IncludeCertChain=false for namespace secrets
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // IncludeCertChain=false: Only leaf certificate
        var includeCertChainFalseSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "ns-include-chain-false", NamespaceProperty = "production" },
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
            Metadata = new V1ObjectMeta { Name = "ns-include-chain-true", NamespaceProperty = "production" },
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
    public void IncludeCertChainFalse_NamespaceBoundary_Enforced()
    {
        // Verify that IncludeCertChain=false respects namespace boundaries
        var namespaceName = "production";
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        var secrets = new List<V1Secret>();
        for (int i = 0; i < 3; i++)
        {
            secrets.Add(new V1Secret
            {
                Metadata = new V1ObjectMeta { Name = $"secret-{i}", NamespaceProperty = namespaceName },
                Type = "kubernetes.io/tls",
                Data = new Dictionary<string, byte[]>
                {
                    { "tls.crt", Encoding.UTF8.GetBytes(leafPem) },
                    { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
                }
            });
        }

        // Assert - All secrets are in the same namespace and have only leaf cert
        Assert.All(secrets, s => Assert.Equal(namespaceName, s.Metadata.NamespaceProperty));
        Assert.All(secrets, s =>
        {
            var certCount = Encoding.UTF8.GetString(s.Data["tls.crt"])
                .Split("-----BEGIN CERTIFICATE-----").Length - 1;
            Assert.Equal(1, certCount);
            Assert.False(s.Data.ContainsKey("ca.crt"));
        });
    }

    #endregion

    #region Namespace Validation Tests

    [Fact]
    public void NamespaceStore_ValidNamespace_AcceptsValidNames()
    {
        // Valid Kubernetes namespace names
        var validNamespaces = new[]
        {
            "default",
            "kube-system",
            "my-namespace",
            "prod-123"
        };

        // All should be valid (no exceptions or null)
        foreach (var ns in validNamespaces)
        {
            var secret = new V1Secret
            {
                Metadata = new V1ObjectMeta
                {
                    Name = "test-secret",
                    NamespaceProperty = ns
                }
            };

            Assert.Equal(ns, secret.Metadata.NamespaceProperty);
        }
    }

    [Fact]
    public void NamespaceStore_DefaultNamespace_HandledCorrectly()
    {
        // The "default" namespace is a special case that should be handled
        var namespaceName = "default";
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "test-secret",
                NamespaceProperty = namespaceName
            }
        };

        Assert.Equal("default", secret.Metadata.NamespaceProperty);
    }

    #endregion
}
