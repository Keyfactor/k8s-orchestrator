// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Text;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Newtonsoft.Json;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Services;

/// <summary>
/// Unit tests for CertificateChainExtractor covering null/empty inputs,
/// DER fallback, ca.crt chain handling, and the ExtractFromSecretData overloads.
/// </summary>
public class CertificateChainExtractorTests
{
    #region Kubeconfig helper (local, no cluster needed)

    private static string BuildLocalKubeconfig()
    {
        var config = new Dictionary<string, object>
        {
            ["apiVersion"] = "v1",
            ["kind"] = "Config",
            ["current-context"] = "test-ctx",
            ["clusters"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = "test-cluster",
                    ["cluster"] = new Dictionary<string, object> { ["server"] = "https://127.0.0.1:6443" }
                }
            },
            ["users"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = "test-user",
                    ["user"] = new Dictionary<string, object> { ["token"] = "test-token" }
                }
            },
            ["contexts"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["name"] = "test-ctx",
                    ["context"] = new Dictionary<string, object>
                    {
                        ["cluster"] = "test-cluster",
                        ["user"] = "test-user",
                        ["namespace"] = "default"
                    }
                }
            }
        };
        return JsonConvert.SerializeObject(config);
    }

    private static KubeCertificateManagerClient CreateKubeClient()
        => new KubeCertificateManagerClient(BuildLocalKubeconfig());

    #endregion

    #region ExtractCertificates(string) — null / whitespace inputs

    [Fact]
    public void ExtractCertificates_NullString_ReturnsEmpty()
    {
        var extractor = new CertificateChainExtractor(null);

        var result = extractor.ExtractCertificates((string)null);

        Assert.Empty(result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    public void ExtractCertificates_WhitespaceString_ReturnsEmpty(string input)
    {
        var extractor = new CertificateChainExtractor(null);

        var result = extractor.ExtractCertificates(input);

        Assert.Empty(result);
    }

    #endregion

    #region ExtractCertificates(string) — DER fallback path

    [Fact]
    public void ExtractCertificates_Base64DerCert_UsesDerFallbackAndReturnsPem()
    {
        // Pass a base64-encoded DER cert (not PEM), so LoadCertificateChain fails
        // and ReadDerCertificate succeeds — exercising lines 68-75.
        var certInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "ChainExtractor DER");
        var derBase64 = Convert.ToBase64String(certInfo.Certificate.GetEncoded());

        var kubeClient = CreateKubeClient();
        var extractor = new CertificateChainExtractor(kubeClient);

        var result = extractor.ExtractCertificates(derBase64);

        Assert.Single(result);
        Assert.Contains("-----BEGIN CERTIFICATE-----", result[0]);
    }

    [Fact]
    public void ExtractCertificates_InvalidData_ReturnsEmptyAndLogsWarning()
    {
        // Data that is neither PEM nor DER — exercises the else/warning branch at line 78.
        var junk = Convert.ToBase64String(new byte[] { 0x01, 0x02, 0x03, 0x04 });

        var kubeClient = CreateKubeClient();
        var extractor = new CertificateChainExtractor(kubeClient);

        // Should not throw; logs a warning and returns empty
        var result = extractor.ExtractCertificates(junk);

        Assert.Empty(result);
    }

    #endregion

    #region ExtractCertificates(byte[]) — null / empty inputs

    [Fact]
    public void ExtractCertificates_NullBytes_ReturnsEmpty()
    {
        var extractor = new CertificateChainExtractor(null);

        var result = extractor.ExtractCertificates((byte[])null);

        Assert.Empty(result);
    }

    [Fact]
    public void ExtractCertificates_EmptyBytes_ReturnsEmpty()
    {
        var extractor = new CertificateChainExtractor(null);

        var result = extractor.ExtractCertificates(Array.Empty<byte>());

        Assert.Empty(result);
    }

    #endregion

    #region ExtractAndAppendUnique(byte[]) — null / empty inputs

    [Fact]
    public void ExtractAndAppendUnique_NullBytes_ReturnsZero()
    {
        var extractor = new CertificateChainExtractor(null);
        var existing = new List<string>();

        var count = extractor.ExtractAndAppendUnique((byte[])null, existing);

        Assert.Equal(0, count);
        Assert.Empty(existing);
    }

    [Fact]
    public void ExtractAndAppendUnique_EmptyBytes_ReturnsZero()
    {
        var extractor = new CertificateChainExtractor(null);
        var existing = new List<string>();

        var count = extractor.ExtractAndAppendUnique(Array.Empty<byte>(), existing);

        Assert.Equal(0, count);
        Assert.Empty(existing);
    }

    #endregion

    #region ExtractFromSecretData — null secretData

    [Fact]
    public void ExtractFromSecretData_NullSecretData_ReturnsEmpty()
    {
        var extractor = new CertificateChainExtractor(null);

        var result = extractor.ExtractFromSecretData(null, new[] { "tls.crt" }, "my-secret", "default");

        Assert.Empty(result);
    }

    #endregion

    #region ExtractFromSecretData — ca.crt adds chain certs (addedCount > 0 log branch)

    [Fact]
    public void ExtractFromSecretData_WithCaCrt_AddsCaCertsToList()
    {
        // Exercises line 191: _logger.LogDebug("Added {Count} CA certificate(s) from ca.crt", addedCount)
        var caCertInfo = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "ChainExtractor CA");
        var caPem = ConvertCertificateToPem(caCertInfo.Certificate);
        var caBytes = Encoding.UTF8.GetBytes(caPem);

        var leafCertInfo = CachedCertificateProvider.GetOrCreate(KeyType.EcP256, "ChainExtractor Leaf");
        var leafPem = ConvertCertificateToPem(leafCertInfo.Certificate);
        var leafBytes = Encoding.UTF8.GetBytes(leafPem);

        var secretData = new Dictionary<string, byte[]>
        {
            ["tls.crt"] = leafBytes,
            ["ca.crt"] = caBytes
        };

        var kubeClient = CreateKubeClient();
        var extractor = new CertificateChainExtractor(kubeClient);

        var result = extractor.ExtractFromSecretData(secretData, new[] { "tls.crt" }, "test-secret", "default");

        // tls.crt (leaf) + ca.crt → 2 certs
        Assert.Equal(2, result.Count);
    }

    [Fact]
    public void ExtractFromSecretData_EmptySecretData_ReturnsEmpty()
    {
        var kubeClient = CreateKubeClient();
        var extractor = new CertificateChainExtractor(kubeClient);

        var result = extractor.ExtractFromSecretData(
            new Dictionary<string, byte[]>(),
            new[] { "tls.crt" },
            "test-secret",
            "default");

        Assert.Empty(result);
    }

    #endregion
}
