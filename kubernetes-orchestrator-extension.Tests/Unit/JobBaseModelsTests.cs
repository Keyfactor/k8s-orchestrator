// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit;

/// <summary>
/// Tests for model classes defined in JobBase.cs: KubernetesCertStore, KubeCreds, Cert, and exception classes.
/// </summary>
public class JobBaseModelsTests
{
    #region KubernetesCertStore Tests

    [Fact]
    public void KubernetesCertStore_DefaultValues_AreEmptyStrings()
    {
        // Arrange & Act
        var store = new KubernetesCertStore();

        // Assert
        Assert.Equal("", store.KubeNamespace);
        Assert.Equal("", store.KubeSecretName);
        Assert.Equal("", store.KubeSecretType);
    }

    [Fact]
    public void KubernetesCertStore_Properties_CanBeSet()
    {
        // Arrange & Act
        var store = new KubernetesCertStore
        {
            KubeNamespace = "my-namespace",
            KubeSecretName = "my-secret",
            KubeSecretType = "kubernetes.io/tls"
        };

        // Assert
        Assert.Equal("my-namespace", store.KubeNamespace);
        Assert.Equal("my-secret", store.KubeSecretName);
        Assert.Equal("kubernetes.io/tls", store.KubeSecretType);
    }

    [Theory]
    [InlineData("default", "tls-cert", "kubernetes.io/tls")]
    [InlineData("kube-system", "opaque-secret", "Opaque")]
    [InlineData("production", "jks-store", "Opaque")]
    public void KubernetesCertStore_VariousValues_StoredCorrectly(string ns, string name, string type)
    {
        // Arrange & Act
        var store = new KubernetesCertStore
        {
            KubeNamespace = ns,
            KubeSecretName = name,
            KubeSecretType = type
        };

        // Assert
        Assert.Equal(ns, store.KubeNamespace);
        Assert.Equal(name, store.KubeSecretName);
        Assert.Equal(type, store.KubeSecretType);
    }

    #endregion

    #region KubeCreds Tests

    [Fact]
    public void KubeCreds_DefaultValues_AreEmptyStrings()
    {
        // Arrange & Act
        var creds = new KubeCreds();

        // Assert
        Assert.Equal("", creds.KubeServer);
        Assert.Equal("", creds.KubeToken);
        Assert.Equal("", creds.KubeCert);
    }

    [Fact]
    public void KubeCreds_Properties_CanBeSet()
    {
        // Arrange & Act
        var creds = new KubeCreds
        {
            KubeServer = "https://kubernetes.default.svc",
            KubeToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            KubeCert = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t..."
        };

        // Assert
        Assert.Equal("https://kubernetes.default.svc", creds.KubeServer);
        Assert.StartsWith("eyJ", creds.KubeToken);
        Assert.StartsWith("LS0", creds.KubeCert);
    }

    [Fact]
    public void KubeCreds_WithNullValues_AcceptsNull()
    {
        // Arrange & Act
        var creds = new KubeCreds
        {
            KubeServer = null!,
            KubeToken = null!,
            KubeCert = null!
        };

        // Assert
        Assert.Null(creds.KubeServer);
        Assert.Null(creds.KubeToken);
        Assert.Null(creds.KubeCert);
    }

    #endregion

    #region Cert Tests

    [Fact]
    public void Cert_DefaultValues_AreEmptyStrings()
    {
        // Arrange & Act
        var cert = new Cert();

        // Assert
        Assert.Equal("", cert.Alias);
        Assert.Equal("", cert.CertData);
        Assert.Equal("", cert.PrivateKey);
    }

    [Fact]
    public void Cert_Properties_CanBeSet()
    {
        // Arrange & Act
        var cert = new Cert
        {
            Alias = "my-certificate",
            CertData = "-----BEGIN CERTIFICATE-----\nMIIC...",
            PrivateKey = "-----BEGIN PRIVATE KEY-----\nMIIE..."
        };

        // Assert
        Assert.Equal("my-certificate", cert.Alias);
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", cert.CertData);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", cert.PrivateKey);
    }

    [Theory]
    [InlineData("thumbprint-alias", "certdata", "keydata")]
    [InlineData("CN=test.example.com", "base64cert", "base64key")]
    [InlineData("", "", "")]
    public void Cert_VariousValues_StoredCorrectly(string alias, string certData, string privateKey)
    {
        // Arrange & Act
        var cert = new Cert
        {
            Alias = alias,
            CertData = certData,
            PrivateKey = privateKey
        };

        // Assert
        Assert.Equal(alias, cert.Alias);
        Assert.Equal(certData, cert.CertData);
        Assert.Equal(privateKey, cert.PrivateKey);
    }

    #endregion

    #region InvalidK8SSecretException Tests

    [Fact]
    public void InvalidK8SSecretException_DefaultConstructor_CreatesException()
    {
        // Arrange & Act
        var ex = new InvalidK8SSecretException();

        // Assert
        Assert.NotNull(ex);
        Assert.IsType<InvalidK8SSecretException>(ex);
    }

    [Fact]
    public void InvalidK8SSecretException_WithMessage_ContainsMessage()
    {
        // Arrange
        const string message = "Secret format is invalid";

        // Act
        var ex = new InvalidK8SSecretException(message);

        // Assert
        Assert.Equal(message, ex.Message);
    }

    [Fact]
    public void InvalidK8SSecretException_WithMessageAndInnerException_ContainsBoth()
    {
        // Arrange
        const string message = "Secret format is invalid";
        var inner = new FormatException("Invalid format");

        // Act
        var ex = new InvalidK8SSecretException(message, inner);

        // Assert
        Assert.Equal(message, ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void InvalidK8SSecretException_CanBeThrown()
    {
        // Arrange & Act & Assert
        var ex = Assert.Throws<InvalidK8SSecretException>(() => ThrowInvalidK8SSecretException());
        Assert.Equal("Test exception", ex.Message);
    }

    private static void ThrowInvalidK8SSecretException()
    {
        throw new InvalidK8SSecretException("Test exception");
    }

    [Fact]
    public void InvalidK8SSecretException_InheritsFromException()
    {
        // Arrange & Act
        var ex = new InvalidK8SSecretException("test");

        // Assert
        Assert.IsAssignableFrom<Exception>(ex);
    }

    #endregion

    #region JkSisPkcs12Exception Tests

    [Fact]
    public void JkSisPkcs12Exception_DefaultConstructor_CreatesException()
    {
        // Arrange & Act
        var ex = new JkSisPkcs12Exception();

        // Assert
        Assert.NotNull(ex);
        Assert.IsType<JkSisPkcs12Exception>(ex);
    }

    [Fact]
    public void JkSisPkcs12Exception_WithMessage_ContainsMessage()
    {
        // Arrange
        const string message = "File is PKCS12 but was expected to be JKS";

        // Act
        var ex = new JkSisPkcs12Exception(message);

        // Assert
        Assert.Equal(message, ex.Message);
    }

    [Fact]
    public void JkSisPkcs12Exception_WithMessageAndInnerException_ContainsBoth()
    {
        // Arrange
        const string message = "Format mismatch";
        var inner = new InvalidOperationException("Cannot parse");

        // Act
        var ex = new JkSisPkcs12Exception(message, inner);

        // Assert
        Assert.Equal(message, ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void JkSisPkcs12Exception_CanBeThrown()
    {
        // Arrange & Act & Assert
        var ex = Assert.Throws<JkSisPkcs12Exception>(() => ThrowJkSisPkcs12Exception());
        Assert.Equal("Test exception", ex.Message);
    }

    private static void ThrowJkSisPkcs12Exception()
    {
        throw new JkSisPkcs12Exception("Test exception");
    }

    [Fact]
    public void JkSisPkcs12Exception_InheritsFromException()
    {
        // Arrange & Act
        var ex = new JkSisPkcs12Exception("test");

        // Assert
        Assert.IsAssignableFrom<Exception>(ex);
    }

    #endregion

    #region StoreNotFoundException Tests

    [Fact]
    public void StoreNotFoundException_DefaultConstructor_CreatesException()
    {
        // Arrange & Act
        var ex = new StoreNotFoundException();

        // Assert
        Assert.NotNull(ex);
        Assert.IsType<StoreNotFoundException>(ex);
    }

    [Fact]
    public void StoreNotFoundException_WithMessage_ContainsMessage()
    {
        // Arrange
        const string message = "Certificate store 'my-secret' not found in namespace 'default'";

        // Act
        var ex = new StoreNotFoundException(message);

        // Assert
        Assert.Equal(message, ex.Message);
    }

    [Fact]
    public void StoreNotFoundException_WithMessageAndInnerException_ContainsBoth()
    {
        // Arrange
        const string message = "Store not found";
        var inner = new InvalidOperationException("K8s API error");

        // Act
        var ex = new StoreNotFoundException(message, inner);

        // Assert
        Assert.Equal(message, ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void StoreNotFoundException_CanBeThrown()
    {
        // Arrange & Act & Assert
        var ex = Assert.Throws<StoreNotFoundException>(() => ThrowStoreNotFoundException());
        Assert.Equal("Test store not found", ex.Message);
    }

    private static void ThrowStoreNotFoundException()
    {
        throw new StoreNotFoundException("Test store not found");
    }

    [Fact]
    public void StoreNotFoundException_InheritsFromException()
    {
        // Arrange & Act
        var ex = new StoreNotFoundException("test");

        // Assert
        Assert.IsAssignableFrom<Exception>(ex);
    }

    #endregion
}
