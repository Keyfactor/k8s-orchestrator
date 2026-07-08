// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Text;
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Services;

/// <summary>
/// Unit tests for JobCertificateParser covering DER, PEM, PKCS12, and error paths.
/// </summary>
public class JobCertificateParserTests
{
    private readonly JobCertificateParser _parser;
    private readonly ILogger _logger;

    public JobCertificateParserTests()
    {
        _logger = new Mock<ILogger>().Object;
        _parser = new JobCertificateParser(_logger);
    }

    #region Helper Methods

    private static ManagementJobConfiguration CreateConfig(string base64Contents, string password = null, string storePassword = null)
    {
        return new ManagementJobConfiguration
        {
            JobCertificate = new ManagementJobCertificate
            {
                Contents = base64Contents,
                PrivateKeyPassword = password
            },
            CertificateStoreDetails = new CertificateStore
            {
                StorePassword = storePassword
            }
        };
    }

    private static ManagementJobConfiguration CreateNullCertConfig()
    {
        return new ManagementJobConfiguration
        {
            JobCertificate = null,
            CertificateStoreDetails = null
        };
    }

    #endregion

    #region Null/Empty Input Tests

    [Fact]
    public void Parse_NullJobCertificate_ReturnsEmptyJobCert()
    {
        var config = CreateNullCertConfig();

        var result = _parser.Parse(config, false);

        Assert.NotNull(result);
        Assert.Null(result.CertBytes);
        Assert.False(result.HasPrivateKey);
    }

    [Fact]
    public void Parse_EmptyContents_ReturnsEmptyJobCert()
    {
        var config = CreateConfig("");

        var result = _parser.Parse(config, false);

        Assert.NotNull(result);
        Assert.Null(result.CertBytes);
    }

    [Fact]
    public void Parse_EmptyBase64Data_ReturnsEmptyJobCert()
    {
        // Base64 of empty byte array
        var config = CreateConfig(Convert.ToBase64String(Array.Empty<byte>()));

        var result = _parser.Parse(config, false);

        Assert.NotNull(result);
        Assert.Null(result.CertBytes);
    }

    #endregion

    #region DER Format Tests

    [Fact]
    public void Parse_DerCertificate_ParsesCorrectly()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "DER Parser Test");
        var derBytes = certInfo.Certificate.GetEncoded();
        var config = CreateConfig(Convert.ToBase64String(derBytes));

        var result = _parser.Parse(config, false);

        Assert.NotNull(result);
        Assert.NotNull(result.CertPem);
        Assert.Contains("-----BEGIN CERTIFICATE-----", result.CertPem);
        Assert.NotNull(result.CertBytes);
        Assert.NotNull(result.CertThumbprint);
        Assert.NotNull(result.CertificateEntry);
        Assert.False(result.HasPrivateKey);
        Assert.NotNull(result.CertificateEntryChain);
        Assert.Single(result.CertificateEntryChain);
        Assert.NotNull(result.ChainPem);
        Assert.Single(result.ChainPem);
    }

    [Fact]
    public void Parse_DerCertificate_WithIncludeCertChain_StillParses()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "DER Chain Test");
        var derBytes = certInfo.Certificate.GetEncoded();
        var config = CreateConfig(Convert.ToBase64String(derBytes));

        // includeCertChain=true with DER triggers a warning but still parses
        var result = _parser.Parse(config, true);

        Assert.NotNull(result);
        Assert.NotNull(result.CertPem);
        Assert.False(result.HasPrivateKey);
    }

    [Fact]
    public void Parse_DerCertificate_SetsCorrectFields()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "DER EC Test");
        var derBytes = certInfo.Certificate.GetEncoded();
        var config = CreateConfig(Convert.ToBase64String(derBytes));

        var result = _parser.Parse(config, false);

        Assert.Equal(certInfo.Certificate, result.CertificateEntry.Certificate);
        Assert.Equal(derBytes, result.CertBytes);
    }

    #endregion

    #region PEM Format Tests

    [Fact]
    public void Parse_SinglePemCertificate_ParsesCorrectly()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PEM Parser Test");
        var pem = CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate);
        var config = CreateConfig(Convert.ToBase64String(Encoding.UTF8.GetBytes(pem)));

        var result = _parser.Parse(config, false);

        Assert.NotNull(result);
        Assert.NotNull(result.CertPem);
        Assert.Contains("-----BEGIN CERTIFICATE-----", result.CertPem);
        Assert.NotNull(result.CertBytes);
        Assert.NotNull(result.CertThumbprint);
        Assert.NotNull(result.CertificateEntry);
        Assert.False(result.HasPrivateKey);
        Assert.NotNull(result.CertificateEntryChain);
        Assert.Single(result.CertificateEntryChain);
        Assert.NotNull(result.ChainPem);
        Assert.Single(result.ChainPem);
    }

    [Fact]
    public void Parse_MultiplePemCertificates_ParsesMultiple()
    {
        var cert1 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PEM Multi Test 1");
        var cert2 = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PEM Multi Test 2");

        // Build PEM with explicit BEGIN/END markers to ensure BouncyCastle PemReader parses both
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN CERTIFICATE-----");
        sb.AppendLine(Convert.ToBase64String(cert1.Certificate.GetEncoded()));
        sb.AppendLine("-----END CERTIFICATE-----");
        sb.AppendLine("-----BEGIN CERTIFICATE-----");
        sb.AppendLine(Convert.ToBase64String(cert2.Certificate.GetEncoded()));
        sb.AppendLine("-----END CERTIFICATE-----");
        var config = CreateConfig(Convert.ToBase64String(Encoding.UTF8.GetBytes(sb.ToString())));

        var result = _parser.Parse(config, false);

        Assert.NotNull(result);
        Assert.NotNull(result.CertPem);
        Assert.False(result.HasPrivateKey);
        Assert.NotNull(result.CertificateEntryChain);
        Assert.Equal(2, result.CertificateEntryChain.Length);
        Assert.NotNull(result.ChainPem);
        Assert.Equal(2, result.ChainPem.Count);
    }

    [Fact]
    public void Parse_PemCertificate_SetsLeafAsFirst()
    {
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048, "PEM Leaf First Test");
        var sb = new StringBuilder();
        foreach (var certInfo in chain)
        {
            sb.Append(CertificateTestHelper.ConvertCertificateToPem(certInfo.Certificate));
        }
        var config = CreateConfig(Convert.ToBase64String(Encoding.UTF8.GetBytes(sb.ToString())));

        var result = _parser.Parse(config, false);

        // First cert in chain should be the leaf
        Assert.Equal(chain[0].Certificate, result.CertificateEntry.Certificate);
    }

    #endregion

    #region PKCS12 Format Tests

    [Fact]
    public void Parse_Pkcs12WithKey_ParsesCorrectly()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Parser Test");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(
            certInfo.Certificate, certInfo.KeyPair, "testpass", "testalias");
        var config = CreateConfig(Convert.ToBase64String(pkcs12Bytes), "testpass", "storepass");

        var result = _parser.Parse(config, true);

        Assert.NotNull(result);
        Assert.NotNull(result.CertPem);
        Assert.Contains("-----BEGIN CERTIFICATE-----", result.CertPem);
        Assert.NotNull(result.CertBytes);
        Assert.NotNull(result.CertThumbprint);
        Assert.True(result.HasPrivateKey);
        Assert.NotNull(result.PrivateKeyPem);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", result.PrivateKeyPem);
        Assert.NotNull(result.PrivateKeyBytes);
        Assert.NotNull(result.PrivateKeyParameter);
        Assert.NotNull(result.Pkcs12);
        Assert.Equal("testpass", result.Password);
    }

    [Fact]
    public void Parse_Pkcs12WithChain_IncludesChain()
    {
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048, "PKCS12 Chain Test");
        var leafInfo = chain[0];
        var chainCerts = new[] { chain[1].Certificate, chain[2].Certificate };
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(
            leafInfo.Certificate, leafInfo.KeyPair, "pass", "leaf", chainCerts);
        var config = CreateConfig(Convert.ToBase64String(pkcs12Bytes), "pass");

        var result = _parser.Parse(config, true);

        Assert.NotNull(result);
        Assert.True(result.HasPrivateKey);
        Assert.NotNull(result.CertificateEntryChain);
        Assert.True(result.CertificateEntryChain.Length >= 1);
        Assert.NotNull(result.ChainPem);
    }

    [Fact]
    public void Parse_Pkcs12_SetsStorePassword()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 StorePass Test");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(
            certInfo.Certificate, certInfo.KeyPair, "certpass", "alias1");
        var config = CreateConfig(Convert.ToBase64String(pkcs12Bytes), "certpass", "mystorepass");

        var result = _parser.Parse(config, false);

        Assert.Equal("mystorepass", result.StorePassword);
    }

    #endregion

    #region Invalid Data Tests

    [Fact]
    public void Parse_InvalidData_ThrowsInvalidOperationException()
    {
        // Random bytes that aren't PKCS12, DER, or PEM
        var randomBytes = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        var config = CreateConfig(Convert.ToBase64String(randomBytes));

        Assert.Throws<InvalidOperationException>(() => _parser.Parse(config, false));
    }

    [Fact]
    public void Parse_SetsPasswordFromConfig()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Password Test");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(
            certInfo.Certificate, certInfo.KeyPair, "mypassword", "alias1");
        var config = CreateConfig(Convert.ToBase64String(pkcs12Bytes), "mypassword");

        var result = _parser.Parse(config, false);

        Assert.Equal("mypassword", result.Password);
    }

    [Fact]
    public void Parse_NullPassword_DefaultsToEmpty()
    {
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "NullPass Test");
        var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(
            certInfo.Certificate, certInfo.KeyPair, "", "alias1");
        var config = CreateConfig(Convert.ToBase64String(pkcs12Bytes), null);

        var result = _parser.Parse(config, false);

        Assert.Equal("", result.Password);
    }

    #endregion
}
