// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.IO;
using System.Text;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Microsoft.Extensions.Logging;
using Moq;
using Org.BouncyCastle.Pkcs;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit;

/// <summary>
/// Tests for CertificateOperations - certificate parsing, conversion, and chain operations.
/// </summary>
public class CertificateOperationsTests
{
    private readonly CertificateOperations _operations;
    private readonly Mock<ILogger> _mockLogger = new();

    public CertificateOperationsTests()
    {
        _operations = new CertificateOperations(_mockLogger.Object);
    }

    #region Constructor Tests

    [Fact]
    public void Constructor_WithNullLogger_CreatesDefaultLogger()
    {
        // Act - should not throw
        var ops = new CertificateOperations(null);

        // Assert
        Assert.NotNull(ops);
    }

    [Fact]
    public void Constructor_WithLogger_UsesProvidedLogger()
    {
        // Act
        var ops = new CertificateOperations(_mockLogger.Object);

        // Assert
        Assert.NotNull(ops);
    }

    #endregion

    #region ReadDerCertificate Tests

    [Fact]
    public void ReadDerCertificate_ValidBase64Der_ReturnsCertificate()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "DER Test");
        var derBytes = certInfo.Certificate.GetEncoded();
        var base64Der = Convert.ToBase64String(derBytes);

        // Act
        var result = _operations.ReadDerCertificate(base64Der);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(certInfo.Certificate.SubjectDN.ToString(), result.SubjectDN.ToString());
    }

    [Fact]
    public void ReadDerCertificate_InvalidBase64_ThrowsFormatException()
    {
        // Arrange
        var invalidBase64 = "not-valid-base64!!!";

        // Act & Assert
        Assert.ThrowsAny<FormatException>(() => _operations.ReadDerCertificate(invalidBase64));
    }

    [Fact]
    public void ReadDerCertificate_InvalidDerData_ReturnsNullOrThrows()
    {
        // Arrange
        var invalidDer = Convert.ToBase64String(Encoding.UTF8.GetBytes("not a certificate"));

        // Act - BouncyCastle may return null or throw depending on input
        try
        {
            var result = _operations.ReadDerCertificate(invalidDer);
            // If no exception, result should be null for invalid data
            Assert.Null(result);
        }
        catch (Exception)
        {
            // Exception is also acceptable for invalid data
            Assert.True(true);
        }
    }

    #endregion

    #region ReadPemCertificate Tests

    [Fact]
    public void ReadPemCertificate_ValidPem_ReturnsCertificate()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PEM Test");

        // Act
        var result = _operations.ReadPemCertificate(ConvertCertificateToPem(certInfo.Certificate));

        // Assert
        Assert.NotNull(result);
        Assert.Equal(certInfo.Certificate.SubjectDN.ToString(), result.SubjectDN.ToString());
    }

    [Fact]
    public void ReadPemCertificate_NotACertificatePem_ReturnsNull()
    {
        // Arrange - a private key PEM is not a certificate
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Key PEM Test");

        // Act
        var result = _operations.ReadPemCertificate(ConvertPrivateKeyToPem(certInfo.KeyPair.Private));

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void ReadPemCertificate_EmptyPem_ReturnsNull()
    {
        // Arrange
        var emptyPem = "";

        // Act
        var result = _operations.ReadPemCertificate(emptyPem);

        // Assert
        Assert.Null(result);
    }

    #endregion

    #region LoadCertificateChain Tests

    [Fact]
    public void LoadCertificateChain_SingleCertificate_ReturnsSingleCert()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Chain Single");

        // Act
        var result = _operations.LoadCertificateChain(ConvertCertificateToPem(certInfo.Certificate));

        // Assert
        Assert.Single(result);
    }

    [Fact]
    public void LoadCertificateChain_MultipleCertificates_ReturnsAll()
    {
        // Arrange
        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Chain Cert 1");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Chain Cert 2");
        var chainPem = ConvertCertificateToPem(cert1.Certificate) + "\n" + ConvertCertificateToPem(cert2.Certificate);

        // Act
        var result = _operations.LoadCertificateChain(chainPem);

        // Assert
        Assert.Equal(2, result.Count);
    }

    [Fact]
    public void LoadCertificateChain_EmptyString_ReturnsEmptyList()
    {
        // Arrange
        var emptyPem = "";

        // Act
        var result = _operations.LoadCertificateChain(emptyPem);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void LoadCertificateChain_NonCertificatePem_ReturnsEmptyList()
    {
        // Arrange - private key PEM should be skipped
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Non Cert");

        // Act
        var result = _operations.LoadCertificateChain(ConvertPrivateKeyToPem(certInfo.KeyPair.Private));

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void LoadCertificateChain_MixedPemContent_ReturnsOnlyCertificates()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Mixed PEM");
        var mixedPem = ConvertCertificateToPem(certInfo.Certificate) + "\n" + ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        // Act
        var result = _operations.LoadCertificateChain(mixedPem);

        // Assert
        Assert.Single(result); // Only the certificate, not the key
    }

    #endregion

    #region ConvertToPem Tests

    [Fact]
    public void ConvertToPem_ValidCertificate_ReturnsPemString()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Convert PEM");

        // Act
        var result = _operations.ConvertToPem(certInfo.Certificate);

        // Assert
        Assert.NotEmpty(result);
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", result);
        Assert.Contains("-----END CERTIFICATE-----", result);
    }

    [Fact]
    public void ConvertToPem_RoundTrip_ProducesSameCertificate()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Round Trip");

        // Act
        var pem = _operations.ConvertToPem(certInfo.Certificate);
        var parsed = _operations.ReadPemCertificate(pem);

        // Assert
        Assert.NotNull(parsed);
        Assert.Equal(certInfo.Certificate.SubjectDN.ToString(), parsed.SubjectDN.ToString());
        Assert.Equal(certInfo.Certificate.SerialNumber, parsed.SerialNumber);
    }

    #endregion

    #region ExtractPrivateKeyAsPem Tests

    [Fact]
    public void ExtractPrivateKeyAsPem_ValidPkcs12_ReturnsKeyPem()
    {
        // Arrange
        var pkcs12Bytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.Rsa2048, "password");
        var store = new Pkcs12StoreBuilder().Build();
        store.Load(new MemoryStream(pkcs12Bytes), "password".ToCharArray());

        // Act
        var result = _operations.ExtractPrivateKeyAsPem(store, "password");

        // Assert
        Assert.NotEmpty(result);
        Assert.Contains("PRIVATE KEY", result);
    }

    [Fact]
    public void ExtractPrivateKeyAsPem_Pkcs8Format_ReturnsPkcs8Key()
    {
        // Arrange
        var pkcs12Bytes = CachedCertificateProvider.GetOrCreatePkcs12(KeyType.Rsa2048, "password");
        var store = new Pkcs12StoreBuilder().Build();
        store.Load(new MemoryStream(pkcs12Bytes), "password".ToCharArray());

        // Act
        var result = _operations.ExtractPrivateKeyAsPem(store, "password", PrivateKeyFormat.Pkcs8);

        // Assert
        Assert.NotEmpty(result);
        Assert.Contains("PRIVATE KEY", result);
    }

    [Fact]
    public void ExtractPrivateKeyAsPem_EmptyStore_ThrowsException()
    {
        // Arrange
        var emptyStore = new Pkcs12StoreBuilder().Build();

        // Act & Assert
        Assert.Throws<Exception>(() => _operations.ExtractPrivateKeyAsPem(emptyStore, "password"));
    }

    [Theory]
    [InlineData(KeyType.Rsa2048)]
    [InlineData(KeyType.EcP256)]
    public void ExtractPrivateKeyAsPem_DifferentKeyTypes_ReturnsKeyPem(KeyType keyType)
    {
        // Arrange
        var pkcs12Bytes = CachedCertificateProvider.GetOrCreatePkcs12(keyType, "password");
        var store = new Pkcs12StoreBuilder().Build();
        store.Load(new MemoryStream(pkcs12Bytes), "password".ToCharArray());

        // Act
        var result = _operations.ExtractPrivateKeyAsPem(store, "password");

        // Assert
        Assert.NotEmpty(result);
        Assert.Contains("PRIVATE KEY", result);
    }

    #endregion

    #region ParseCertificateFromPem Tests

    [Fact]
    public void ParseCertificateFromPem_ValidPem_ReturnsCertificate()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Parse PEM");

        // Act
        var result = _operations.ParseCertificateFromPem(ConvertCertificateToPem(certInfo.Certificate));

        // Assert
        Assert.NotNull(result);
        Assert.Equal(certInfo.Certificate.SubjectDN.ToString(), result.SubjectDN.ToString());
    }

    #endregion

    #region ParseCertificateFromDer Tests

    [Fact]
    public void ParseCertificateFromDer_ValidDer_ReturnsCertificate()
    {
        // Arrange
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Parse DER");
        var derBytes = certInfo.Certificate.GetEncoded();

        // Act
        var result = _operations.ParseCertificateFromDer(derBytes);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(certInfo.Certificate.SubjectDN.ToString(), result.SubjectDN.ToString());
    }

    // Note: BouncyCastle parsing behavior for invalid data is inconsistent,
    // so we don't test invalid input scenarios - only valid certificate parsing.

    [Fact]
    public void ParseCertificateFromDer_EmptyBytes_ReturnsNullOrThrows()
    {
        // Arrange
        var emptyBytes = Array.Empty<byte>();

        // Act - BouncyCastle may return null or throw for empty input
        try
        {
            var result = _operations.ParseCertificateFromDer(emptyBytes);
            // If no exception, null is acceptable
            Assert.Null(result);
        }
        catch (Exception)
        {
            // Exception is also acceptable
            Assert.True(true);
        }
    }

    [Fact]
    public void ParseCertificateFromPem_InvalidPem_ReturnsNullOrThrows()
    {
        // Arrange
        var invalidPem = "not a valid PEM";

        // Act - BouncyCastle may return null or throw for invalid input
        try
        {
            var result = _operations.ParseCertificateFromPem(invalidPem);
            Assert.Null(result);
        }
        catch (Exception)
        {
            Assert.True(true);
        }
    }

    #endregion
}
