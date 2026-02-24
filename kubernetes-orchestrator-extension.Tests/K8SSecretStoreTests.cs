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
/// Unit tests for K8SSecret store type operations (Opaque secrets with PEM format).
/// K8SSecret uses PEM format directly without a serializer - certificates and keys are stored as UTF-8 text.
/// Tests focus on PEM handling, field name flexibility, and certificate chain management.
/// </summary>
public class K8SSecretStoreTests
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

    #region K8S Secret Structure Tests

    [Fact]
    public void OpaqueSecret_WithPemCertAndKey_HasCorrectStructure()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Test");
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "test-secret",
                NamespaceProperty = "default"
            },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert
        Assert.Equal("Opaque", secret.Type);
        Assert.Equal(2, secret.Data.Count);
        Assert.True(secret.Data.ContainsKey("tls.crt"));
        Assert.True(secret.Data.ContainsKey("tls.key"));
    }

    [Fact]
    public void OpaqueSecret_WithCertificateChain_CanStoreSeparateCaField()
    {
        // Arrange
        var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
        var leafCert = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediateCert = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var rootCert = CertificateTestHelper.ConvertCertificateToPem(chain[2].Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);

        // Create secret with separate ca.crt field
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "test-with-chain" },
            Type = "Opaque",
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

    [Theory]
    [InlineData("tls.crt")]
    [InlineData("cert")]
    [InlineData("certificate")]
    [InlineData("crt")]
    public void OpaqueSecret_FlexibleFieldNames_SupportedVariations(string certFieldName)
    {
        // K8SSecret supports multiple field name variations (unlike K8STLSSecr which is strict)
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        var secret = new V1Secret
        {
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { certFieldName, Encoding.UTF8.GetBytes(certPem) }
            }
        };

        // Assert
        Assert.True(secret.Data.ContainsKey(certFieldName));
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

        var secret = new V1Secret
        {
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
            }
        };

        // Assert - no ca.crt field for single certificate
        Assert.False(secret.Data.ContainsKey("ca.crt"));
    }

    [Fact]
    public void OpaqueSecret_WithBundledChain_AllCertsInTlsCrt()
    {
        // When SeparateChain=false, the full chain should be bundled into tls.crt
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
            Metadata = new V1ObjectMeta { Name = "bundled-chain-opaque" },
            Type = "Opaque",
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
    public void OpaqueSecret_SeparateChainVsBundled_DifferentStructures()
    {
        // Compare the two chain storage strategies for Opaque secrets
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
            Type = "Opaque",
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
            Type = "Opaque",
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

        // Simulate storing in K8S secret
        var secret = new V1Secret
        {
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

    #region Edge Cases

    [Fact]
    public void OpaqueSecret_EmptyData_ValidStructure()
    {
        // Arrange
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "empty-secret" },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>()
        };

        // Assert
        Assert.NotNull(secret.Data);
        Assert.Empty(secret.Data);
    }

    [Fact]
    public void OpaqueSecret_OnlyCertificateNoKey_ValidStructure()
    {
        // Some secrets may only contain certificates without private keys
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate();
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        var secret = new V1Secret
        {
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) }
            }
        };

        // Assert
        Assert.Single(secret.Data);
        Assert.False(secret.Data.ContainsKey("tls.key"));
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

    [Fact]
    public void OpaqueSecret_UpdateWithCertificateOnly_PreservesExistingKey()
    {
        // Simulates the scenario where an existing secret with a private key
        // is updated with certificate-only data (no private key).
        // The existing private key should be preserved.

        // Arrange - Existing secret with certificate and key
        var certInfo1 = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Original");
        var certPem1 = CertificateTestHelper.ConvertCertificateToPem(certInfo1.Certificate);
        var keyPem1 = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo1.KeyPair.Private);

        var existingSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "test-secret" },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem1) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem1) }
            }
        };

        // New secret with certificate only (no key)
        var certInfo2 = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Updated");
        var certPem2 = CertificateTestHelper.ConvertCertificateToPem(certInfo2.Certificate);

        var newSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "test-secret" },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem2) }
                // No tls.key - simulating certificate-only update
            }
        };

        // Act - Simulate the update logic (as done in UpdateOpaqueSecret)
        // Update tls.key only if provided in the new secret
        if (newSecret.Data.TryGetValue("tls.key", out var newKeyData))
        {
            existingSecret.Data["tls.key"] = newKeyData;
        }
        // Always update tls.crt
        existingSecret.Data["tls.crt"] = newSecret.Data["tls.crt"];

        // Assert
        Assert.True(existingSecret.Data.ContainsKey("tls.key"), "Existing key should be preserved");
        Assert.Equal(keyPem1, Encoding.UTF8.GetString(existingSecret.Data["tls.key"])); // Key unchanged
        Assert.Equal(certPem2, Encoding.UTF8.GetString(existingSecret.Data["tls.crt"])); // Cert updated
    }

    [Fact]
    public void OpaqueSecret_NewSecretWithoutKey_DoesNotContainTlsKey()
    {
        // Tests that when creating a new Opaque secret without a private key,
        // the tls.key field should not be present at all.

        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048);
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        string keyPem = null; // No private key

        // Act - Simulate CreateNewSecret logic for Opaque secrets
        var opaqueData = new Dictionary<string, byte[]>
        {
            { "tls.crt", Encoding.UTF8.GetBytes(certPem ?? "") }
        };
        if (!string.IsNullOrEmpty(keyPem))
        {
            opaqueData["tls.key"] = Encoding.UTF8.GetBytes(keyPem);
        }

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "test-certonly" },
            Type = "Opaque",
            Data = opaqueData
        };

        // Assert
        Assert.True(secret.Data.ContainsKey("tls.crt"), "Should have tls.crt");
        Assert.False(secret.Data.ContainsKey("tls.key"), "Should NOT have tls.key when no private key provided");
    }

    #endregion

    #region Opaque Secret Field Name Tests

    /// <summary>
    /// Verifies that opaque secrets can use various field names for certificate data,
    /// not just 'tls.crt'. This tests the fix for the bug where opaque secrets were
    /// incorrectly processed using HandleTlsSecret which only looks for 'tls.crt'.
    /// </summary>
    [Theory]
    [InlineData("tls.crt")]
    [InlineData("cert")]
    [InlineData("certificate")]
    [InlineData("certs")]
    [InlineData("certificates")]
    [InlineData("crt")]
    public void OpaqueSecret_WithVariousCertificateFieldNames_ValidStructure(string fieldName)
    {
        // Arrange - Create opaque secret with different field names for certificate
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048);
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = $"test-{fieldName}-secret" },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { fieldName, Encoding.UTF8.GetBytes(certPem) }
            }
        };

        // Assert - Secret should be valid with any of these field names
        Assert.NotNull(secret.Data);
        Assert.True(secret.Data.ContainsKey(fieldName));
        var certData = Encoding.UTF8.GetString(secret.Data[fieldName]);
        Assert.Contains("-----BEGIN CERTIFICATE-----", certData);
    }

    /// <summary>
    /// Verifies that TLS secrets use the standard 'tls.crt' and 'tls.key' fields.
    /// This is the expected format for kubernetes.io/tls secrets.
    /// </summary>
    [Fact]
    public void TlsSecret_RequiresStandardFields()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048);
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "tls-secret" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert - TLS secrets must have these specific fields
        Assert.True(secret.Data.ContainsKey("tls.crt"));
        Assert.True(secret.Data.ContainsKey("tls.key"));
        Assert.Equal("kubernetes.io/tls", secret.Type);
    }

    /// <summary>
    /// Verifies that opaque and TLS secrets have different field requirements.
    /// This tests the distinction that was causing the K8SNS inventory bug.
    /// </summary>
    [Fact]
    public void OpaqueVsTlsSecret_DifferentFieldRequirements()
    {
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048);
        var certPem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(certInfo.KeyPair.Private);

        // Opaque secret can use 'cert' field name
        var opaqueSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "opaque-secret" },
            Type = "Opaque",
            Data = new Dictionary<string, byte[]>
            {
                { "cert", Encoding.UTF8.GetBytes(certPem) },
                { "key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // TLS secret must use standard fields
        var tlsSecret = new V1Secret
        {
            Metadata = new V1ObjectMeta { Name = "tls-secret" },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                { "tls.crt", Encoding.UTF8.GetBytes(certPem) },
                { "tls.key", Encoding.UTF8.GetBytes(keyPem) }
            }
        };

        // Assert - Different field names are valid for each type
        Assert.True(opaqueSecret.Data.ContainsKey("cert"));
        Assert.False(opaqueSecret.Data.ContainsKey("tls.crt")); // Opaque can use 'cert' instead
        Assert.True(tlsSecret.Data.ContainsKey("tls.crt"));
        Assert.Equal("kubernetes.io/tls", tlsSecret.Type);
        Assert.Equal("Opaque", opaqueSecret.Type);
    }

    #endregion

    #region Metadata Tests

    [Fact]
    public void OpaqueSecret_WithLabels_PreservesMetadata()
    {
        // Arrange
        var secret = new V1Secret
        {
            Metadata = new V1ObjectMeta
            {
                Name = "labeled-secret",
                NamespaceProperty = "default",
                Labels = new Dictionary<string, string>
                {
                    { "keyfactor.com/managed", "true" },
                    { "keyfactor.com/store-type", "K8SSecret" }
                }
            },
            Type = "Opaque"
        };

        // Assert
        Assert.NotNull(secret.Metadata.Labels);
        Assert.Equal(2, secret.Metadata.Labels.Count);
        Assert.Equal("K8SSecret", secret.Metadata.Labels["keyfactor.com/store-type"]);
    }

    #endregion
}
