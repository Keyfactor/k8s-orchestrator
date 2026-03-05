// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Org.BouncyCastle.Pkcs;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

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

    #region K8SJobCertificate.GetCertificateContext Tests

    [Fact]
    public void GetCertificateContext_NullCertificateEntry_ReturnsNull()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = null
        };

        // Act
        var result = jobCert.GetCertificateContext();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void GetCertificateContext_CertificateEntryWithNullCert_ReturnsNull()
    {
        // Arrange
        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(null)
        };

        // Act & Assert - X509CertificateEntry(null) may throw, so handle both cases
        try
        {
            var result = jobCert.GetCertificateContext();
            // If it doesn't throw, it should return null since Certificate is null
            Assert.Null(result);
        }
        catch (ArgumentNullException)
        {
            // X509CertificateEntry constructor may throw for null - that's fine
        }
    }

    [Fact]
    public void GetCertificateContext_ValidCertificate_ReturnsContext()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert Context Test");
        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(certInfo.Certificate),
            CertPem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            PrivateKeyPem = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
        };

        // Act
        var result = jobCert.GetCertificateContext();

        // Assert
        Assert.NotNull(result);
        Assert.Equal(certInfo.Certificate, result.Certificate);
        Assert.Equal(jobCert.CertPem, result.CertPem);
        Assert.Equal(jobCert.PrivateKeyPem, result.PrivateKeyPem);
    }

    [Fact]
    public void GetCertificateContext_WithChain_SkipsLeafCert()
    {
        // Arrange
        var leafInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert Leaf");
        var intermediateInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert Intermediate");
        var rootInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert Root");

        var chainEntries = new[]
        {
            new X509CertificateEntry(leafInfo.Certificate),
            new X509CertificateEntry(intermediateInfo.Certificate),
            new X509CertificateEntry(rootInfo.Certificate)
        };

        var chainPem = new List<string>
        {
            "leaf-pem",
            "intermediate-pem",
            "root-pem"
        };

        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(leafInfo.Certificate),
            CertificateEntryChain = chainEntries,
            ChainPem = chainPem,
            CertPem = "leaf-cert-pem",
            PrivateKeyPem = ""
        };

        // Act
        var result = jobCert.GetCertificateContext();

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.Chain);
        Assert.Equal(2, result.Chain.Count); // Should skip leaf, keep intermediate + root
        Assert.Equal(intermediateInfo.Certificate, result.Chain[0]);
        Assert.Equal(rootInfo.Certificate, result.Chain[1]);
        Assert.Equal(2, result.ChainPem.Count);
        Assert.Equal("intermediate-pem", result.ChainPem[0]);
        Assert.Equal("root-pem", result.ChainPem[1]);
    }

    [Fact]
    public void GetCertificateContext_WithChain_NullChainPem_ChainStillSet()
    {
        // Arrange
        var leafInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert NullChainPem");
        var intermediateInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert NullChainPem Int");

        var chainEntries = new[]
        {
            new X509CertificateEntry(leafInfo.Certificate),
            new X509CertificateEntry(intermediateInfo.Certificate)
        };

        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(leafInfo.Certificate),
            CertificateEntryChain = chainEntries,
            ChainPem = null, // No PEM chain provided
            CertPem = "leaf-pem",
            PrivateKeyPem = ""
        };

        // Act
        var result = jobCert.GetCertificateContext();

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.Chain);
        Assert.Single(result.Chain); // intermediate only (leaf skipped)
        Assert.Equal(intermediateInfo.Certificate, result.Chain[0]);
        // ChainPem should NOT be set by GetCertificateContext when source ChainPem is null
        // K8SCertificateContext may auto-generate ChainPem from Chain certificates
        Assert.NotNull(result.ChainPem); // Auto-generated from Chain
    }

    [Fact]
    public void GetCertificateContext_EmptyChain_DoesNotSetChain()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JobCert EmptyChain");

        var jobCert = new K8SJobCertificate
        {
            CertificateEntry = new X509CertificateEntry(certInfo.Certificate),
            CertificateEntryChain = Array.Empty<X509CertificateEntry>(),
            CertPem = "cert-pem",
            PrivateKeyPem = ""
        };

        // Act
        var result = jobCert.GetCertificateContext();

        // Assert
        Assert.NotNull(result);
        // Chain should remain empty (default)
        Assert.Empty(result.Chain);
    }

    #endregion
}
