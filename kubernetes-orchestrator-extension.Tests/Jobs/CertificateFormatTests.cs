// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Utilities;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Jobs;

/// <summary>
/// Unit tests for DER and PEM certificate format detection and parsing.
/// Tests the ability to handle certificates without private keys from Command.
/// </summary>
public class CertificateFormatTests
{
    #region DER Format Detection Tests

    [Fact]
    public void IsDerFormat_ValidDerCertificate_ReturnsTrue()
    {
        // Arrange
        var derBytes = GenerateDerCertificate(KeyType.Rsa2048);

        // Act
        var result = CertificateUtilities.IsDerFormat(derBytes);

        // Assert
        Assert.True(result);
    }

    [Theory]
    [InlineData(KeyType.Rsa2048)]
    [InlineData(KeyType.Rsa4096)]
    [InlineData(KeyType.EcP256)]
    [InlineData(KeyType.EcP384)]
    [InlineData(KeyType.Ed25519)]
    public void IsDerFormat_VariousKeyTypes_ReturnsTrue(KeyType keyType)
    {
        // Arrange
        var derBytes = GenerateDerCertificate(keyType);

        // Act
        var result = CertificateUtilities.IsDerFormat(derBytes);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsDerFormat_Pkcs12Data_ReturnsFalse()
    {
        // Arrange - PKCS12 is not DER certificate format
        var certInfo = GenerateCertificate(KeyType.Rsa2048);
        var pkcs12Bytes = GeneratePkcs12(certInfo.Certificate, certInfo.KeyPair, "password");

        // Act
        var result = CertificateUtilities.IsDerFormat(pkcs12Bytes);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void IsDerFormat_RandomBytes_ReturnsFalse()
    {
        // Arrange
        var randomBytes = new byte[100];
        new Random().NextBytes(randomBytes);

        // Act
        var result = CertificateUtilities.IsDerFormat(randomBytes);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void IsDerFormat_EmptyBytes_ReturnsFalse()
    {
        // Arrange
        var emptyBytes = Array.Empty<byte>();

        // Act
        var result = CertificateUtilities.IsDerFormat(emptyBytes);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void IsDerFormat_NullBytes_ReturnsFalse()
    {
        // Act
        var result = CertificateUtilities.IsDerFormat(null);

        // Assert
        Assert.False(result);
    }

    #endregion

    #region Certificate Generation Without Private Key Tests

    [Fact]
    public void GenerateDerCertificate_ReturnsValidDerBytes()
    {
        // Arrange & Act
        var derBytes = GenerateDerCertificate(KeyType.Rsa2048);

        // Assert
        Assert.NotNull(derBytes);
        Assert.NotEmpty(derBytes);

        // Verify it can be parsed as a certificate
        var parser = new Org.BouncyCastle.X509.X509CertificateParser();
        var cert = parser.ReadCertificate(derBytes);
        Assert.NotNull(cert);
    }

    [Fact]
    public void GeneratePemCertificateOnly_ReturnsPemWithoutPrivateKey()
    {
        // Arrange & Act
        var pemCert = GeneratePemCertificateOnly(KeyType.Rsa2048);

        // Assert
        Assert.NotNull(pemCert);
        Assert.Contains("-----BEGIN CERTIFICATE-----", pemCert);
        Assert.Contains("-----END CERTIFICATE-----", pemCert);
        Assert.DoesNotContain("-----BEGIN PRIVATE KEY-----", pemCert);
        Assert.DoesNotContain("-----BEGIN RSA PRIVATE KEY-----", pemCert);
        Assert.DoesNotContain("-----BEGIN EC PRIVATE KEY-----", pemCert);
    }

    [Fact]
    public void GenerateBase64DerCertificate_ReturnsValidBase64()
    {
        // Arrange & Act
        var base64Der = GenerateBase64DerCertificate(KeyType.Rsa2048);

        // Assert
        Assert.NotNull(base64Der);

        // Verify it can be decoded
        var decoded = Convert.FromBase64String(base64Der);
        Assert.NotEmpty(decoded);

        // Verify it's a valid DER certificate
        Assert.True(CertificateUtilities.IsDerFormat(decoded));
    }

    #endregion

    #region Certificate Thumbprint Tests

    [Fact]
    public void GetThumbprint_DerCertificate_ReturnsValidThumbprint()
    {
        // Arrange
        var derBytes = GenerateDerCertificate(KeyType.Rsa2048);
        var parser = new Org.BouncyCastle.X509.X509CertificateParser();
        var cert = parser.ReadCertificate(derBytes);

        // Act
        var thumbprint = CertificateUtilities.GetThumbprint(cert);

        // Assert
        Assert.NotNull(thumbprint);
        Assert.NotEmpty(thumbprint);
        // SHA1 thumbprint is 40 hex characters
        Assert.Equal(40, thumbprint.Length);
        Assert.Matches("^[0-9A-Fa-f]+$", thumbprint);
    }

    #endregion

    #region PEM/DER Round-Trip Tests

    [Theory]
    [InlineData(KeyType.Rsa2048)]
    [InlineData(KeyType.EcP256)]
    [InlineData(KeyType.Ed25519)]
    public void DerToPem_RoundTrip_PreservesData(KeyType keyType)
    {
        // Arrange
        var certInfo = GenerateCertificate(keyType);
        var originalDer = certInfo.Certificate.GetEncoded();

        // Convert to PEM
        var pem = ConvertCertificateToPem(certInfo.Certificate);

        // Parse from PEM back to certificate
        using var reader = new System.IO.StringReader(pem);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
        var parsedCert = (Org.BouncyCastle.X509.X509Certificate)pemReader.ReadObject();

        // Get DER from parsed cert
        var roundTripDer = parsedCert.GetEncoded();

        // Assert
        Assert.Equal(originalDer, roundTripDer);
    }

    #endregion

    #region Certificate Chain Parsing Tests

    [Fact]
    public void CertificateChain_MultiplePemCertificates_ParsesAllCerts()
    {
        // Arrange - Create a PEM string with multiple certificates
        // GenerateCertificateChain returns List<CertificateInfo> with [0]=leaf, [1]=intermediate, [2]=root
        var chain = GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = ConvertCertificateToPem(chain[0].Certificate);
        var subCaPem = ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = ConvertCertificateToPem(chain[2].Certificate);

        // Combine into a single PEM string (like ca.crt would contain)
        var combinedPem = subCaPem + rootPem;

        // Act - Parse using PemReader loop (similar to LoadCertificateChain)
        var certificates = new List<Org.BouncyCastle.X509.X509Certificate>();
        using var stringReader = new System.IO.StringReader(combinedPem);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(stringReader);

        object pemObject;
        while ((pemObject = pemReader.ReadObject()) != null)
        {
            if (pemObject is Org.BouncyCastle.X509.X509Certificate cert)
            {
                certificates.Add(cert);
            }
        }

        // Assert
        Assert.Equal(2, certificates.Count);
        Assert.Contains(certificates, c => c.SubjectDN.ToString().Contains("Intermediate") || c.SubjectDN.ToString().Contains("Sub"));
        Assert.Contains(certificates, c => c.SubjectDN.ToString().Contains("Root"));
    }

    [Fact]
    public void CertificateChain_FullChainInSingleField_ParsesAllThreeCerts()
    {
        // Arrange - Create a full chain (Leaf + Sub-CA + Root) in a single PEM string
        // GenerateCertificateChain returns List<CertificateInfo> with [0]=leaf, [1]=intermediate, [2]=root
        var chain = GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = ConvertCertificateToPem(chain[0].Certificate);
        var subCaPem = ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = ConvertCertificateToPem(chain[2].Certificate);

        var fullChainPem = leafPem + subCaPem + rootPem;

        // Act
        var certificates = new List<Org.BouncyCastle.X509.X509Certificate>();
        using var stringReader = new System.IO.StringReader(fullChainPem);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(stringReader);

        object pemObject;
        while ((pemObject = pemReader.ReadObject()) != null)
        {
            if (pemObject is Org.BouncyCastle.X509.X509Certificate cert)
            {
                certificates.Add(cert);
            }
        }

        // Assert
        Assert.Equal(3, certificates.Count);
        Assert.Contains(certificates, c => c.SubjectDN.ToString().Contains("Leaf"));
        Assert.Contains(certificates, c => c.SubjectDN.ToString().Contains("Intermediate") || c.SubjectDN.ToString().Contains("Sub"));
        Assert.Contains(certificates, c => c.SubjectDN.ToString().Contains("Root"));
    }

    [Fact]
    public void CertificateChain_SingleCertificate_ParsesOneCert()
    {
        // Arrange - Single certificate PEM
        var certInfo = GenerateCertificate(KeyType.Rsa2048);
        var certPem = ConvertCertificateToPem(certInfo.Certificate);

        // Act
        var certificates = new List<Org.BouncyCastle.X509.X509Certificate>();
        using var stringReader = new System.IO.StringReader(certPem);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(stringReader);

        object pemObject;
        while ((pemObject = pemReader.ReadObject()) != null)
        {
            if (pemObject is Org.BouncyCastle.X509.X509Certificate cert)
            {
                certificates.Add(cert);
            }
        }

        // Assert
        Assert.Single(certificates);
    }

    [Fact]
    public void CertificateChain_EmptyString_ReturnsEmptyList()
    {
        // Arrange
        var emptyPem = "";

        // Act
        var certificates = new List<Org.BouncyCastle.X509.X509Certificate>();
        using var stringReader = new System.IO.StringReader(emptyPem);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(stringReader);

        object pemObject;
        while ((pemObject = pemReader.ReadObject()) != null)
        {
            if (pemObject is Org.BouncyCastle.X509.X509Certificate cert)
            {
                certificates.Add(cert);
            }
        }

        // Assert
        Assert.Empty(certificates);
    }

    #endregion
}
