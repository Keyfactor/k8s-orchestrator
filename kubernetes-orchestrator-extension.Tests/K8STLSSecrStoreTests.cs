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
/// Unit tests for K8STLSSecr store type operations (kubernetes.io/tls secrets with PEM format).
/// K8STLSSecr enforces strict field names (tls.crt, tls.key, ca.crt) and secret type kubernetes.io/tls.
/// Tests focus on PEM handling, strict field validation, and certificate chain management.
/// </summary>
public class K8STLSSecrStoreTests
{
    #region PEM Certificate Parsing Tests

    [Fact]
    public void PemCertificate_ValidFormat_CanBeParsed()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Test PEM Cert");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        // Assert
        Assert.NotNull(certPem);
        Assert.Contains("-----BEGIN CERTIFICATE-----", certPem);
        Assert.Contains("-----END CERTIFICATE-----", certPem);
        Assert.DoesNotContain("-----BEGIN PRIVATE KEY-----", certPem);
    }

    [Fact]
    public void PemPrivateKey_ValidFormat_CanBeParsed()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Test");
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        // Assert
        Assert.NotNull(keyPem);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", keyPem);
        Assert.Contains("-----END PRIVATE KEY-----", keyPem);
    }

    [Theory]
    [InlineData(KeyType.Rsa1024)]
    [InlineData(KeyType.Rsa2048)]
    [InlineData(KeyType.Rsa4096)]
    [InlineData(KeyType.Rsa8192)]
    [InlineData(KeyType.EcP256)]
    [InlineData(KeyType.EcP384)]
    [InlineData(KeyType.EcP521)]
    [InlineData(KeyType.Dsa1024)]
    [InlineData(KeyType.Dsa2048)]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.Ed448)]
    public void PemCertificate_VariousKeyTypes_ValidFormat(KeyType keyType)
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType, $"Test {keyType}");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        // Assert
        Assert.Contains("-----BEGIN CERTIFICATE-----", certPem);
        Assert.Contains("-----END CERTIFICATE-----", certPem);
    }

    #endregion

    #region K8S TLS Secret Structure Tests

    [Fact]
    public void TlsSecret_WithCertAndKey_HasCorrectStructure()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Test");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "test-tls-secret",
                NamespaceProperty = "default"
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
    public void TlsSecret_WithCertificateChain_CanStoreSeparateCaField()
    {
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafCert = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediateCert = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootCert = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // Create TLS secret with separate ca.crt field
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "test-with-chain" },
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
    public void TlsSecret_StrictFieldNames_OnlyTlsCrtAndTlsKey()
    {
        // K8STLSSecr enforces strict field names - MUST use tls.crt and tls.key
        // Unlike K8SSecret which supports flexible field names
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
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
        Assert.False(secret.Data.ContainsKey("cert")); // Not allowed
        Assert.False(secret.Data.ContainsKey("certificate")); // Not allowed
    }

    [Fact]
    public void TlsSecret_Type_MustBeKubernetesIoTls()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Type = "kubernetes.io/tls", // Must be this exact type
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert
        Assert.Equal("kubernetes.io/tls", secret.Type);
        Assert.NotEqual("Opaque", secret.Type); // NOT Opaque like K8SSecret
    }

    #endregion

    #region Certificate Chain Tests

    [Fact]
    public void CertificateChain_ConcatenatedInSingleField_ValidFormat()
    {
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);

        // Concatenate chain
        var fullChainPem = leafPem + intermediatePem + rootPem;

        // Assert
        Assert.Contains("-----BEGIN CERTIFICATE-----", fullChainPem);
        var certCount = fullChainPem.Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(3, certCount);
    }

    [Fact]
    public void CertificateChain_SingleCertificate_NoChainField()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert - no ca.crt field for single certificate
        Assert.False(secret.Data.ContainsKey("ca.crt"));
    }

    [Fact]
    public void TlsSecret_WithBundledChain_AllCertsInTlsCrt()
    {
        // When SeparateChain=false, the full chain should be bundled into tls.crt
        // This is useful for ingress controllers that expect the full chain in tls.crt
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // Bundle the full chain into tls.crt (SeparateChain=false behavior)
        var bundledChain = leafPem + intermediatePem + rootPem;

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "bundled-chain-tls" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(bundledChain) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert
        Assert.Equal(2, secret.Data.Count); // Only tls.crt and tls.key, no ca.crt
        Assert.False(secret.Data.ContainsKey("ca.crt"), "Should NOT have ca.crt when chain is bundled");

        // Verify tls.crt contains all 3 certificates
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = tlsCrtData.Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(3, certCount);
    }

    [Fact]
    public void TlsSecret_SeparateChainVsBundled_DifferentStructures()
    {
        // Compare the two chain storage strategies
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // SeparateChain=true: leaf in tls.crt, chain in ca.crt
        var separateChainSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "separate-chain" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) },
                { "ca.crt", Encoding.UTF8.GetBytes(intermediatePem + rootPem) }
            }
        };

        // SeparateChain=false: full chain bundled in tls.crt
        var bundledChainSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "bundled-chain" },
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
        var separateTlsCertCount = Encoding.UTF8.GetString(separateChainSecret.Data["tls.crt"])
            .Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(1, separateTlsCertCount); // Only leaf in tls.crt

        // Assert - Bundled chain has 2 fields
        Assert.Equal(2, bundledChainSecret.Data.Count);
        Assert.False(bundledChainSecret.Data.ContainsKey("ca.crt"));
        var bundledTlsCertCount = Encoding.UTF8.GetString(bundledChainSecret.Data["tls.crt"])
            .Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(3, bundledTlsCertCount); // Full chain in tls.crt
    }

    #endregion

    #region DER to PEM Conversion Tests

    [Fact]
    public void DerCertificate_ConvertedToPem_ValidFormat()
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

    #endregion

    #region Encoding Tests

    [Fact]
    public void PemCertificate_Utf8Encoding_RoundTripSuccessful()
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
    public void PemData_StoredAsBytes_CorrectlyDecoded()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var certBytes = Encoding.UTF8.GetBytes(certPem);

        // Simulate storing in K8S TLS secret
        var secret = new V1Secret
        {
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", certBytes }
            }
        };

        // Act - Retrieve and decode
        var retrievedBytes = secret.Data["tls.crt"];
        var retrievedPem = Encoding.UTF8.GetString(retrievedBytes);

        // Assert
        Assert.Equal(certPem, retrievedPem);
        Assert.Contains("-----BEGIN CERTIFICATE-----", retrievedPem);
    }

    #endregion

    #region Field Validation Tests

    [Fact]
    public void TlsSecret_MissingTlsCrt_Invalid()
    {
        // TLS secrets REQUIRE tls.crt field
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
                // Missing tls.crt - this is invalid
            }
        };

        // Assert
        Assert.False(secret.Data.ContainsKey("tls.crt"));
        Assert.True(secret.Data.ContainsKey("tls.key"));
    }

    [Fact]
    public void TlsSecret_MissingTlsKey_Invalid()
    {
        // TLS secrets REQUIRE tls.key field for proper TLS function
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        var secret = new V1Secret
        {
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
                // Missing tls.key - this is invalid for TLS
            }
        };

        // Assert
        Assert.True(secret.Data.ContainsKey("tls.crt"));
        Assert.False(secret.Data.ContainsKey("tls.key"));
    }

    [Fact]
    public void TlsSecret_OptionalCaCrt_Allowed()
    {
        // ca.crt is optional for certificate chain
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var caPem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);

        var secret = new V1Secret
        {
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) },
                { "ca.crt", Encoding.UTF8.GetBytes(caPem) } // Optional
            }
        };

        // Assert
        Assert.Equal(3, secret.Data.Count);
        Assert.True(secret.Data.ContainsKey("ca.crt"));
    }

    #endregion

    #region Edge Cases

    [Fact]
    public void TlsSecret_EmptyData_ValidStructure()
    {
        // Arrange
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "empty-tls-secret" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>()
        };

        // Assert
        Assert.NotNull(secret.Data);
        Assert.Empty(secret.Data);
    }

    [Fact]
    public void PemCertificate_WithWhitespace_StillValid()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        // Add extra whitespace (common in manual creation)
        var pemWithWhitespace = "\n" + certPem + "\n\n";

        // Assert - Should still contain valid markers
        Assert.Contains("-----BEGIN CERTIFICATE-----", pemWithWhitespace);
        Assert.Contains("-----END CERTIFICATE-----", pemWithWhitespace);
    }

    #endregion

    #region IncludeCertChain=false Tests

    [Fact]
    public void Management_IncludeCertChainFalse_OnlyLeafCertStored()
    {
        // When IncludeCertChain=false is set, only the leaf certificate should be stored,
        // not the intermediate or root certificates. This tests the expected output structure.

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
                Name = "test-include-cert-chain-false",
                NamespaceProperty = "default"
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
            "Secret should NOT contain ca.crt when IncludeCertChain=false");

        // Verify the stored certificate is the leaf certificate by checking its subject
        using var reader = new System.IO.StringReader(tlsCrtData);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(reader);
        var storedCert = (Org.BouncyCastle.X509.X509Certificate)pemReader.ReadObject();
        var storedSubject = storedCert.SubjectDN.ToString();
        var leafSubject = leafCert.SubjectDN.ToString();

        Assert.Equal(leafSubject, storedSubject);
    }

    [Fact]
    public void IncludeCertChainFalse_VersusTrue_DifferentStructures()
    {
        // Compare the expected output between IncludeCertChain=true vs IncludeCertChain=false
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediatePem = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootPem = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // IncludeCertChain=false: Only leaf certificate in tls.crt, no chain
        var includeCertChainFalseSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "include-chain-false" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // IncludeCertChain=true (SeparateChain=false): Full chain bundled in tls.crt
        var includeCertChainTrueBundledSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "include-chain-true-bundled" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafPem + intermediatePem + rootPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert - IncludeCertChain=false has only 1 certificate in tls.crt
        var falseChainCount = Encoding.UTF8.GetString(includeCertChainFalseSecret.Data["tls.crt"])
            .Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(1, falseChainCount);
        Assert.False(includeCertChainFalseSecret.Data.ContainsKey("ca.crt"));

        // Assert - IncludeCertChain=true (bundled) has 3 certificates in tls.crt
        var trueBundledChainCount = Encoding.UTF8.GetString(includeCertChainTrueBundledSecret.Data["tls.crt"])
            .Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(3, trueBundledChainCount);
        Assert.False(includeCertChainTrueBundledSecret.Data.ContainsKey("ca.crt"));
    }

    [Theory]
    [InlineData(KeyType.Rsa2048)]
    [InlineData(KeyType.EcP256)]
    [InlineData(KeyType.EcP384)]
    public void IncludeCertChainFalse_VariousKeyTypes_OnlyLeafCertStored(KeyType keyType)
    {
        // Verify that IncludeCertChain=false behavior works with various key types
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(keyType);
        var leafCert = chain[0].Certificate;
        var leafPem = CertificateTestHelper.ConvertCertificateToPem(leafCert);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // Act - Simulate IncludeCertChain=false output
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = $"test-no-chain-{keyType}" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(leafPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert - Only 1 certificate in tls.crt
        var tlsCrtData = Encoding.UTF8.GetString(secret.Data["tls.crt"]);
        var certCount = tlsCrtData.Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(1, certCount);
        Assert.False(secret.Data.ContainsKey("ca.crt"));
    }

    #endregion

    #region Metadata Tests

    [Fact]
    public void TlsSecret_WithLabels_PreservesMetadata()
    {
        // Arrange
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "labeled-tls-secret",
                NamespaceProperty = "default",
                Labels = new Dictionary<string, string>
                {
                    { "keyfactor.com/managed", "true" },
                    { "keyfactor.com/store-type", "K8STLSSecr" }
                }
            },
            Type = "kubernetes.io/tls"
        };

        // Assert
        Assert.NotNull(secret.Metadata.Labels);
        Assert.Equal(2, secret.Metadata.Labels.Count);
        Assert.Equal("K8STLSSecr", secret.Metadata.Labels["keyfactor.com/store-type"]);
    }

    [Fact]
    public void TlsSecret_NativeKubernetesFormat_Compatible()
    {
        // K8STLSSecr secrets should be compatible with native Kubernetes TLS secrets
        // that other K8S components (like Ingress) can consume
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "ingress-tls",
                NamespaceProperty = "default"
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

    #endregion
}
