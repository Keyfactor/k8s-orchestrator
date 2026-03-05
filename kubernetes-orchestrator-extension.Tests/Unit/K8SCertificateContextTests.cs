// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit;

/// <summary>
/// Tests for K8SCertificateContext model class.
/// </summary>
public class K8SCertificateContextTests
{
    #region Property Tests

    [Fact]
    public void DefaultConstructor_AllPropertiesHaveDefaults()
    {
        // Arrange & Act
        var context = new K8SCertificateContext();

        // Assert
        Assert.Null(context.Certificate);
        Assert.Null(context.PrivateKey);
        Assert.NotNull(context.Chain);
        Assert.Empty(context.Chain);
        Assert.False(context.HasPrivateKey);
    }

    [Fact]
    public void Thumbprint_WithNullCertificate_ReturnsEmpty()
    {
        // Arrange
        var context = new K8SCertificateContext { Certificate = null };

        // Act & Assert
        Assert.Equal(string.Empty, context.Thumbprint);
    }

    [Fact]
    public void Thumbprint_WithCertificate_ReturnsThumbprint()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test Cert");
        var context = new K8SCertificateContext { Certificate = certInfo.Certificate };

        // Act
        var thumbprint = context.Thumbprint;

        // Assert
        Assert.NotEmpty(thumbprint);
        Assert.Equal(40, thumbprint.Length); // SHA-1 hex is 40 chars
    }

    [Fact]
    public void SubjectCN_WithNullCertificate_ReturnsEmpty()
    {
        // Arrange
        var context = new K8SCertificateContext { Certificate = null };

        // Act & Assert
        Assert.Equal(string.Empty, context.SubjectCN);
    }

    [Fact]
    public void SubjectCN_WithCertificate_ReturnsCommonName()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test Subject CN");
        var context = new K8SCertificateContext { Certificate = certInfo.Certificate };

        // Act
        var cn = context.SubjectCN;

        // Assert
        Assert.NotEmpty(cn);
        Assert.Contains("Test Subject CN", cn);
    }

    [Fact]
    public void SubjectDN_WithCertificate_ReturnsDistinguishedName()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test DN");
        var context = new K8SCertificateContext { Certificate = certInfo.Certificate };

        // Act
        var dn = context.SubjectDN;

        // Assert
        Assert.NotEmpty(dn);
        Assert.Contains("CN=", dn);
    }

    [Fact]
    public void IssuerCN_WithCertificate_ReturnsIssuerCommonName()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test Issuer");
        var context = new K8SCertificateContext { Certificate = certInfo.Certificate };

        // Act
        var issuerCN = context.IssuerCN;

        // Assert
        Assert.NotEmpty(issuerCN);
    }

    [Fact]
    public void IssuerDN_WithCertificate_ReturnsIssuerDistinguishedName()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test Issuer DN");
        var context = new K8SCertificateContext { Certificate = certInfo.Certificate };

        // Act
        var issuerDN = context.IssuerDN;

        // Assert
        Assert.NotEmpty(issuerDN);
    }

    [Fact]
    public void NotBefore_WithNullCertificate_ReturnsMinValue()
    {
        // Arrange
        var context = new K8SCertificateContext { Certificate = null };

        // Act & Assert
        Assert.Equal(DateTime.MinValue, context.NotBefore);
    }

    [Fact]
    public void NotBefore_WithCertificate_ReturnsValidDate()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test NotBefore");
        var context = new K8SCertificateContext { Certificate = certInfo.Certificate };

        // Act
        var notBefore = context.NotBefore;

        // Assert
        Assert.NotEqual(DateTime.MinValue, notBefore);
        Assert.True(notBefore <= DateTime.UtcNow);
    }

    [Fact]
    public void NotAfter_WithNullCertificate_ReturnsMaxValue()
    {
        // Arrange
        var context = new K8SCertificateContext { Certificate = null };

        // Act & Assert
        Assert.Equal(DateTime.MaxValue, context.NotAfter);
    }

    [Fact]
    public void NotAfter_WithCertificate_ReturnsValidDate()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test NotAfter");
        var context = new K8SCertificateContext { Certificate = certInfo.Certificate };

        // Act
        var notAfter = context.NotAfter;

        // Assert
        Assert.NotEqual(DateTime.MaxValue, notAfter);
        Assert.True(notAfter > DateTime.UtcNow);
    }

    [Fact]
    public void SerialNumber_WithNullCertificate_ReturnsEmpty()
    {
        // Arrange
        var context = new K8SCertificateContext { Certificate = null };

        // Act & Assert
        Assert.Equal(string.Empty, context.SerialNumber);
    }

    [Fact]
    public void SerialNumber_WithCertificate_ReturnsSerialNumber()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test Serial");
        var context = new K8SCertificateContext { Certificate = certInfo.Certificate };

        // Act
        var serial = context.SerialNumber;

        // Assert
        Assert.NotEmpty(serial);
    }

    [Fact]
    public void KeyAlgorithm_WithNullCertificate_ReturnsEmpty()
    {
        // Arrange
        var context = new K8SCertificateContext { Certificate = null };

        // Act & Assert
        Assert.Equal(string.Empty, context.KeyAlgorithm);
    }

    [Theory]
    [InlineData(KeyType.Rsa2048, "RSA")]
    [InlineData(KeyType.EcP256, "EC")]
    public void KeyAlgorithm_WithCertificate_ReturnsAlgorithm(KeyType keyType, string expectedAlgorithm)
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(keyType, $"Test {keyType}");
        var context = new K8SCertificateContext { Certificate = certInfo.Certificate };

        // Act
        var algorithm = context.KeyAlgorithm;

        // Assert
        Assert.Contains(expectedAlgorithm, algorithm, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HasPrivateKey_WithNoKey_ReturnsFalse()
    {
        // Arrange
        var context = new K8SCertificateContext { PrivateKey = null };

        // Act & Assert
        Assert.False(context.HasPrivateKey);
    }

    [Fact]
    public void HasPrivateKey_WithKey_ReturnsTrue()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test HasKey");
        var context = new K8SCertificateContext { PrivateKey = certInfo.KeyPair.Private };

        // Act & Assert
        Assert.True(context.HasPrivateKey);
    }

    [Fact]
    public void CertPem_WithNullCertificate_ReturnsEmpty()
    {
        // Arrange
        var context = new K8SCertificateContext { Certificate = null };

        // Act & Assert
        Assert.Equal(string.Empty, context.CertPem);
    }

    [Fact]
    public void CertPem_WithCertificate_ReturnsPemString()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test PEM");
        var context = new K8SCertificateContext { Certificate = certInfo.Certificate };

        // Act
        var pem = context.CertPem;

        // Assert
        Assert.NotEmpty(pem);
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", pem);
        Assert.Contains("-----END CERTIFICATE-----", pem);
    }

    [Fact]
    public void CertPem_Setter_OverridesComputed()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test Override");
        var context = new K8SCertificateContext { Certificate = certInfo.Certificate };
        var originalPem = context.CertPem;

        // Act
        context.CertPem = "custom-pem-value";

        // Assert
        Assert.Equal("custom-pem-value", context.CertPem);
        Assert.NotEqual(originalPem, context.CertPem);
    }

    [Fact]
    public void PrivateKeyPem_WithNoKey_ReturnsEmpty()
    {
        // Arrange
        var context = new K8SCertificateContext { PrivateKey = null };

        // Act & Assert
        Assert.Equal(string.Empty, context.PrivateKeyPem);
    }

    [Fact]
    public void PrivateKeyPem_WithKey_ReturnsPemString()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test Key PEM");
        var context = new K8SCertificateContext { PrivateKey = certInfo.KeyPair.Private };

        // Act
        var pem = context.PrivateKeyPem;

        // Assert
        Assert.NotEmpty(pem);
        Assert.Contains("PRIVATE KEY", pem);
    }

    [Fact]
    public void ChainPem_WithEmptyChain_ReturnsEmptyList()
    {
        // Arrange
        var context = new K8SCertificateContext { Chain = new List<X509Certificate>() };

        // Act
        var chainPem = context.ChainPem;

        // Assert
        Assert.NotNull(chainPem);
        Assert.Empty(chainPem);
    }

    [Fact]
    public void Chain_CanBeSetAndRetrieved()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Chain Cert");
        var context = new K8SCertificateContext();

        // Act
        context.Chain = new List<X509Certificate> { certInfo.Certificate };

        // Assert
        Assert.Single(context.Chain);
        Assert.Same(certInfo.Certificate, context.Chain[0]);
    }

    #endregion

    #region Factory Method Tests

    [Fact]
    public void FromPkcs12_WithNullBytes_ThrowsArgumentException()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentException>(() => K8SCertificateContext.FromPkcs12(null, "password"));
    }

    [Fact]
    public void FromPkcs12_WithEmptyBytes_ThrowsArgumentException()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentException>(() => K8SCertificateContext.FromPkcs12(Array.Empty<byte>(), "password"));
    }

    [Fact]
    public void FromPkcs12_WithValidPkcs12_ReturnsContext()
    {
        // Arrange
        var pkcs12Bytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.Rsa2048, "password");

        // Act
        var context = K8SCertificateContext.FromPkcs12(pkcs12Bytes, "password");

        // Assert
        Assert.NotNull(context);
        Assert.NotNull(context.Certificate);
        Assert.NotEmpty(context.Thumbprint);
    }

    [Fact]
    public void FromPkcs12Store_WithNullStore_ThrowsArgumentNullException()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentNullException>(() => K8SCertificateContext.FromPkcs12Store(null));
    }

    [Fact]
    public void FromPem_WithNullString_ThrowsArgumentException()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentException>(() => K8SCertificateContext.FromPem(null));
    }

    [Fact]
    public void FromPem_WithEmptyString_ThrowsArgumentException()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentException>(() => K8SCertificateContext.FromPem(""));
    }

    [Fact]
    public void FromPem_WithWhitespace_ThrowsArgumentException()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentException>(() => K8SCertificateContext.FromPem("   "));
    }

    [Fact]
    public void FromPem_WithValidPem_ReturnsContext()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "FromPem Test");
        var pem = ConvertCertificateToPem(certInfo.Certificate);

        // Act
        var context = K8SCertificateContext.FromPem(pem);

        // Assert
        Assert.NotNull(context);
        Assert.NotNull(context.Certificate);
        Assert.NotEmpty(context.Thumbprint);
        Assert.False(context.HasPrivateKey); // PEM cert doesn't include key
    }

    [Fact]
    public void FromPemWithKey_WithNullCertPem_ThrowsArgumentException()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentException>(() => K8SCertificateContext.FromPemWithKey(null, "key"));
    }

    [Fact]
    public void FromPemWithKey_WithEmptyCertPem_ThrowsArgumentException()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentException>(() => K8SCertificateContext.FromPemWithKey("", "key"));
    }

    [Fact]
    public void FromPemWithKey_WithValidCertPem_ReturnsContext()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "FromPemWithKey Test");

        // Act
        var context = K8SCertificateContext.FromPemWithKey(ConvertCertificateToPem(certInfo.Certificate), ConvertPrivateKeyToPem(certInfo.KeyPair.Private));

        // Assert
        Assert.NotNull(context);
        Assert.NotNull(context.Certificate);
        Assert.NotEmpty(context.Thumbprint);
    }

    [Fact]
    public void FromDer_WithNullBytes_ThrowsArgumentException()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentException>(() => K8SCertificateContext.FromDer(null));
    }

    [Fact]
    public void FromDer_WithEmptyBytes_ThrowsArgumentException()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentException>(() => K8SCertificateContext.FromDer(Array.Empty<byte>()));
    }

    [Fact]
    public void FromCertificate_WithNullCertificate_ThrowsArgumentNullException()
    {
        // Arrange & Act & Assert
        Assert.Throws<ArgumentNullException>(() => K8SCertificateContext.FromCertificate(null));
    }

    [Fact]
    public void FromCertificate_WithValidCertificate_ReturnsContext()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "FromCert Test");

        // Act
        var context = K8SCertificateContext.FromCertificate(certInfo.Certificate, certInfo.KeyPair.Private);

        // Assert
        Assert.NotNull(context);
        Assert.Same(certInfo.Certificate, context.Certificate);
        Assert.Same(certInfo.KeyPair.Private, context.PrivateKey);
        Assert.True(context.HasPrivateKey);
    }

    [Fact]
    public void FromCertificate_WithChain_IncludesChain()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Chain Test");
        var chainCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Chain Cert");
        var chain = new List<X509Certificate> { chainCert.Certificate };

        // Act
        var context = K8SCertificateContext.FromCertificate(certInfo.Certificate, null, chain);

        // Assert
        Assert.Single(context.Chain);
    }

    [Fact]
    public void FromPkcs12_WithSpecificAlias_UsesProvidedAlias()
    {
        // Arrange
        var pkcs12Bytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.Rsa2048, "password", "my-alias");

        // Act
        var context = K8SCertificateContext.FromPkcs12(pkcs12Bytes, "password", "my-alias");

        // Assert
        Assert.NotNull(context);
        Assert.NotNull(context.Certificate);
        Assert.True(context.HasPrivateKey);
    }

    [Fact]
    public void FromPkcs12Store_WithValidStore_ExtractsContext()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Pkcs12Store Context");
        var storeBuilder = new Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder();
        var store = storeBuilder.Build();
        store.SetKeyEntry("test-alias",
            new Org.BouncyCastle.Pkcs.AsymmetricKeyEntry(certInfo.KeyPair.Private),
            new[] { new X509CertificateEntry(certInfo.Certificate) });

        // Act
        var context = K8SCertificateContext.FromPkcs12Store(store);

        // Assert
        Assert.NotNull(context);
        Assert.NotNull(context.Certificate);
        Assert.NotNull(context.PrivateKey);
    }

    [Fact]
    public void FromPkcs12Store_WithSpecificAlias_UsesAlias()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Pkcs12Store Alias");
        var storeBuilder = new Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder();
        var store = storeBuilder.Build();
        store.SetKeyEntry("specific-alias",
            new Org.BouncyCastle.Pkcs.AsymmetricKeyEntry(certInfo.KeyPair.Private),
            new[] { new X509CertificateEntry(certInfo.Certificate) });

        // Act
        var context = K8SCertificateContext.FromPkcs12Store(store, "specific-alias");

        // Assert
        Assert.NotNull(context);
        Assert.NotNull(context.Certificate);
    }

    [Fact]
    public void FromPem_WithChain_ExtractsChain()
    {
        // Arrange - create a PEM with multiple certificates
        var leafInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PEM Chain Leaf");
        var rootInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PEM Chain Root");
        var leafPem = ConvertCertificateToPem(leafInfo.Certificate);
        var rootPem = ConvertCertificateToPem(rootInfo.Certificate);
        var chainPem = leafPem + "\n" + rootPem;

        // Act
        var context = K8SCertificateContext.FromPem(chainPem);

        // Assert
        Assert.NotNull(context);
        Assert.NotNull(context.Certificate);
        Assert.NotEmpty(context.Chain);
        Assert.Single(context.Chain); // Root is the chain (leaf is the primary cert)
    }

    [Fact]
    public void FromPemWithKey_WithChainPem_ParsesChain()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PemWithKey Chain");
        var chainCert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PemWithKey Chain Cert");
        var certPem = ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = ConvertPrivateKeyToPem(certInfo.KeyPair.Private);
        var chainPem = ConvertCertificateToPem(chainCert.Certificate);

        // Act
        var context = K8SCertificateContext.FromPemWithKey(certPem, keyPem, chainPem);

        // Assert
        Assert.NotNull(context);
        Assert.NotNull(context.Certificate);
        Assert.NotEmpty(context.Chain);
    }

    [Fact]
    public void FromPemWithKey_WithNullPrivateKey_ContextStillCreated()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PemWithKey NullKey");
        var certPem = ConvertCertificateToPem(certInfo.Certificate);

        // Act
        var context = K8SCertificateContext.FromPemWithKey(certPem, null);

        // Assert
        Assert.NotNull(context);
        Assert.NotNull(context.Certificate);
        Assert.False(context.HasPrivateKey);
    }

    [Fact]
    public void FromDer_WithValidDer_ReturnsContext()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "DER Test");
        var derBytes = certInfo.Certificate.GetEncoded();

        // Act
        var context = K8SCertificateContext.FromDer(derBytes);

        // Assert
        Assert.NotNull(context);
        Assert.NotNull(context.Certificate);
        Assert.False(context.HasPrivateKey);
        Assert.NotEmpty(context.Thumbprint);
    }

    #endregion

    #region Export Method Tests

    [Fact]
    public void ExportCertificatePem_WithNoCertificate_ThrowsInvalidOperationException()
    {
        // Arrange
        var context = new K8SCertificateContext();

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => context.ExportCertificatePem());
    }

    [Fact]
    public void ExportCertificatePem_WithCertificate_ReturnsPem()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Export Test");
        var context = K8SCertificateContext.FromCertificate(certInfo.Certificate);

        // Act
        var pem = context.ExportCertificatePem();

        // Assert
        Assert.NotEmpty(pem);
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", pem);
    }

    [Fact]
    public void ExportCertificateDer_WithNoCertificate_ThrowsInvalidOperationException()
    {
        // Arrange
        var context = new K8SCertificateContext();

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => context.ExportCertificateDer());
    }

    [Fact]
    public void ExportCertificateDer_WithCertificate_ReturnsBytes()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "DER Export Test");
        var context = K8SCertificateContext.FromCertificate(certInfo.Certificate);

        // Act
        var der = context.ExportCertificateDer();

        // Assert
        Assert.NotNull(der);
        Assert.NotEmpty(der);
    }

    [Fact]
    public void ExportPrivateKeyPkcs8_WithNoKey_ThrowsInvalidOperationException()
    {
        // Arrange
        var context = new K8SCertificateContext();

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => context.ExportPrivateKeyPkcs8());
    }

    [Fact]
    public void ExportPrivateKeyPkcs8_WithKey_ReturnsBytes()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS8 Export Test");
        var context = K8SCertificateContext.FromCertificate(certInfo.Certificate, certInfo.KeyPair.Private);

        // Act
        var pkcs8 = context.ExportPrivateKeyPkcs8();

        // Assert
        Assert.NotNull(pkcs8);
        Assert.NotEmpty(pkcs8);
    }

    [Fact]
    public void ExportPrivateKeyPem_WithNoKey_ThrowsInvalidOperationException()
    {
        // Arrange
        var context = new K8SCertificateContext();

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => context.ExportPrivateKeyPem());
    }

    [Fact]
    public void ExportPrivateKeyPem_WithKey_ReturnsPem()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Key PEM Export");
        var context = K8SCertificateContext.FromCertificate(certInfo.Certificate, certInfo.KeyPair.Private);

        // Act
        var pem = context.ExportPrivateKeyPem();

        // Assert
        Assert.NotEmpty(pem);
        Assert.Contains("PRIVATE KEY", pem);
    }

    #endregion
}
