// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Text;
using k8s;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Moq;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Clients;

/// <summary>
/// Unit tests for the SecretOperations class.
/// Tests secret building for various secret types (TLS, Opaque, Keystore).
/// </summary>
public class SecretOperationsTests
{
    #region BuildNewSecret - TLS Secrets

    [Fact]
    public void BuildNewSecret_TlsType_CreatesTlsSecret()
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);

        // Act
        var secret = ops.BuildNewSecret(
            "my-tls-secret",
            "default",
            "tls",
            keyPem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
            certPem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----");

        // Assert
        Assert.NotNull(secret);
        Assert.Equal("my-tls-secret", secret.Metadata.Name);
        Assert.Equal("default", secret.Metadata.NamespaceProperty);
        Assert.Equal("kubernetes.io/tls", secret.Type);
        Assert.True(secret.Data.ContainsKey("tls.key"));
        Assert.True(secret.Data.ContainsKey("tls.crt"));
    }

    [Theory]
    [InlineData("tls")]
    [InlineData("tls_secret")]
    [InlineData("tlssecret")]
    [InlineData("TLS")]
    [InlineData("TLS_SECRET")]
    public void BuildNewSecret_TlsTypeVariants_CreatesTlsSecret(string secretType)
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);

        // Act
        var secret = ops.BuildNewSecret(
            "my-secret",
            "default",
            secretType,
            keyPem: "key",
            certPem: "cert");

        // Assert
        Assert.Equal("kubernetes.io/tls", secret.Type);
    }

    [Fact]
    public void BuildNewSecret_TlsType_WithoutKey_CreatesSecretWithEmptyKey()
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);

        // Act
        var secret = ops.BuildNewSecret(
            "my-tls-secret",
            "default",
            "tls",
            keyPem: null,
            certPem: "cert");

        // Assert
        Assert.True(secret.Data.ContainsKey("tls.key"));
        Assert.Empty(secret.Data["tls.key"]); // Empty but present
        Assert.NotEmpty(secret.Data["tls.crt"]);
    }

    #endregion

    #region BuildNewSecret - Opaque Secrets

    [Fact]
    public void BuildNewSecret_OpaqueType_CreatesOpaqueSecret()
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);

        // Act
        var secret = ops.BuildNewSecret(
            "my-opaque-secret",
            "default",
            "opaque",
            keyPem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
            certPem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----");

        // Assert
        Assert.NotNull(secret);
        Assert.Equal("my-opaque-secret", secret.Metadata.Name);
        Assert.Equal("Opaque", secret.Type);
        Assert.True(secret.Data.ContainsKey("tls.key"));
        Assert.True(secret.Data.ContainsKey("tls.crt"));
    }

    [Theory]
    [InlineData("opaque")]
    [InlineData("secret")]
    [InlineData("secrets")]
    [InlineData("OPAQUE")]
    [InlineData("Secret")]
    public void BuildNewSecret_OpaqueTypeVariants_CreatesOpaqueSecret(string secretType)
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);

        // Act
        var secret = ops.BuildNewSecret(
            "my-secret",
            "default",
            secretType,
            keyPem: "key",
            certPem: "cert");

        // Assert
        Assert.Equal("Opaque", secret.Type);
    }

    [Fact]
    public void BuildNewSecret_OpaqueType_WithoutKey_OmitsTlsKey()
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);

        // Act
        var secret = ops.BuildNewSecret(
            "my-opaque-secret",
            "default",
            "opaque",
            keyPem: null,
            certPem: "cert");

        // Assert
        Assert.False(secret.Data.ContainsKey("tls.key")); // Key not included for opaque without key
        Assert.True(secret.Data.ContainsKey("tls.crt"));
    }

    #endregion

    #region BuildNewSecret - Keystore Secrets

    [Theory]
    [InlineData("pkcs12")]
    [InlineData("p12")]
    [InlineData("pfx")]
    [InlineData("jks")]
    public void BuildNewSecret_KeystoreTypes_CreatesEmptyOpaqueSecret(string secretType)
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);

        // Act
        var secret = ops.BuildNewSecret(
            "my-keystore-secret",
            "default",
            secretType,
            keyPem: null,
            certPem: null);

        // Assert
        Assert.NotNull(secret);
        Assert.Equal("Opaque", secret.Type);
        Assert.Empty(secret.Data); // Keystore secrets start empty
    }

    #endregion

    #region BuildNewSecret - Chain Handling

    [Fact]
    public void BuildNewSecret_WithChain_SeparateChainTrue_AddsCaCrt()
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);
        var chain = new List<string>
        {
            "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"
        };

        // Act
        var secret = ops.BuildNewSecret(
            "my-secret",
            "default",
            "tls",
            keyPem: "key",
            certPem: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
            chainPem: chain,
            separateChain: true,
            includeChain: true);

        // Assert
        Assert.True(secret.Data.ContainsKey("ca.crt"));
        var caCrt = Encoding.UTF8.GetString(secret.Data["ca.crt"]);
        Assert.Contains("intermediate", caCrt);
        Assert.Contains("root", caCrt);
        Assert.DoesNotContain("leaf", caCrt); // Leaf should not be in ca.crt
    }

    [Fact]
    public void BuildNewSecret_WithChain_SeparateChainFalse_BundlesInTlsCrt()
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);
        var chain = new List<string>
        {
            "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"
        };

        // Act
        var secret = ops.BuildNewSecret(
            "my-secret",
            "default",
            "tls",
            keyPem: "key",
            certPem: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
            chainPem: chain,
            separateChain: false,
            includeChain: true);

        // Assert
        Assert.False(secret.Data.ContainsKey("ca.crt"));
        var tlsCrt = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        Assert.Contains("leaf", tlsCrt);
        Assert.Contains("intermediate", tlsCrt);
        Assert.Contains("root", tlsCrt);
    }

    [Fact]
    public void BuildNewSecret_WithChain_IncludeChainFalse_NoChainAdded()
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);
        var chain = new List<string>
        {
            "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----"
        };

        // Act
        var secret = ops.BuildNewSecret(
            "my-secret",
            "default",
            "tls",
            keyPem: "key",
            certPem: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
            chainPem: chain,
            separateChain: true,
            includeChain: false);

        // Assert
        Assert.False(secret.Data.ContainsKey("ca.crt"));
        var tlsCrt = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        Assert.DoesNotContain("intermediate", tlsCrt);
    }

    [Fact]
    public void BuildNewSecret_WithEmptyChain_NoCaCrtAdded()
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);
        var emptyChain = new List<string>();

        // Act
        var secret = ops.BuildNewSecret(
            "my-secret",
            "default",
            "tls",
            keyPem: "key",
            certPem: "cert",
            chainPem: emptyChain,
            separateChain: true,
            includeChain: true);

        // Assert
        Assert.False(secret.Data.ContainsKey("ca.crt"));
    }

    #endregion

    #region BuildNewSecret - Unsupported Type

    [Fact]
    public void BuildNewSecret_UnsupportedType_ThrowsNotSupportedException()
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);

        // Act & Assert
        var ex = Assert.Throws<NotSupportedException>(() =>
            ops.BuildNewSecret(
                "my-secret",
                "default",
                "unsupported_type",
                keyPem: "key",
                certPem: "cert"));

        Assert.Contains("unsupported_type", ex.Message);
    }

    #endregion

    #region UpdateOpaqueSecretData Tests

    [Fact]
    public void UpdateOpaqueSecretData_UpdatesCertAndKey()
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);
        var existing = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "test" },
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes("oldcert") },
                { "tls.key", Encoding.UTF8.GetBytes("oldkey") }
            }
        };

        // Act
        var updated = ops.UpdateOpaqueSecretData(
            existing,
            newKeyPem: "newkey",
            newCertPem: "newcert");

        // Assert
        Assert.Equal("newkey", Encoding.UTF8.GetString(updated.Data["tls.key"]));
        Assert.Equal("newcert", Encoding.UTF8.GetString(updated.Data["tls.crt"]));
    }

    [Fact]
    public void UpdateOpaqueSecretData_NullKey_PreservesExistingKey()
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);
        var existing = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "test" },
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes("oldcert") },
                { "tls.key", Encoding.UTF8.GetBytes("existingkey") }
            }
        };

        // Act
        var updated = ops.UpdateOpaqueSecretData(
            existing,
            newKeyPem: null, // Don't update key
            newCertPem: "newcert");

        // Assert
        Assert.Equal("existingkey", Encoding.UTF8.GetString(updated.Data["tls.key"]));
        Assert.Equal("newcert", Encoding.UTF8.GetString(updated.Data["tls.crt"]));
    }

    [Fact]
    public void UpdateOpaqueSecretData_WithChain_AddsChain()
    {
        // Arrange
        var ops = new SecretOperations(new Mock<IKubernetes>().Object, null);
        var existing = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "test" },
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes("oldcert") }
            }
        };

        var chain = new List<string> { "chainCert" };

        // Act
        var updated = ops.UpdateOpaqueSecretData(
            existing,
            newKeyPem: "key",
            newCertPem: "newcert",
            chainPem: chain,
            separateChain: true,
            includeChain: true);

        // Assert
        Assert.True(updated.Data.ContainsKey("ca.crt"));
    }

    #endregion

    #region Constructor Tests

    [Fact]
    public void Constructor_NullClient_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new SecretOperations(null, null));
    }

    #endregion
}
