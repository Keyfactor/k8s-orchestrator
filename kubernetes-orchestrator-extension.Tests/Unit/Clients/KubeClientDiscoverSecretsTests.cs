// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Linq;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Clients;

/// <summary>
/// Tests for <see cref="KubeCertificateManagerClient.DiscoverSecrets"/> Opaque-secret filtering (GitHub issue #101):
/// an Opaque secret is only reported when it has at least one data key matching the allowed keys.
/// The kubernetes API is mocked, so no network I/O occurs.
/// </summary>
public class KubeClientDiscoverSecretsTests
{
    private const string Ns = "app-ns";

    private static readonly string[] JksKeys = { "jks", "keystore.jks", "truststore.jks" };
    private static readonly string[] Pkcs12Keys = { "pkcs12", "p12", "pfx", "keystore.p12", "keystore.pfx" };
    private static readonly string[] PemKeys =
    {
        "tls.crt", "certificate", "cert", "crt", "cert.pem", "certificate.pem",
        "tls.key", "key", "private-key", "key.pem", "private-key.pem", "ca.crt", "ca", "ca-bundle", "ca-bundle.crt"
    };

    #region Helpers

    private static V1Secret Secret(string name, string type, params string[] dataKeys) => new()
    {
        Metadata = new V1ObjectMeta { Name = name, NamespaceProperty = Ns },
        Type = type,
        Data = dataKeys.ToDictionary(k => k, _ => new byte[] { 1, 2, 3 })
    };

    private static V1Secret NoData(string name, string type) => new()
    {
        Metadata = new V1ObjectMeta { Name = name, NamespaceProperty = Ns },
        Type = type,
        Data = null
    };

    /// <summary>
    /// Builds a client whose API calls are served from <paramref name="secrets"/> (all in namespace <see cref="Ns"/>).
    /// Single-secret reads are forbidden: discovery must rely on the list response (which carries each secret's Data).
    /// </summary>
    private static KubeCertificateManagerClient CreateClient(params V1Secret[] secrets) =>
        MockedKubeClientFactory.Create(secrets, new[] { Ns }, allowSecretReads: false).Client;

    private static List<string> Names(IEnumerable<string> locations) =>
        locations.Select(l => l.Split('/').Last()).OrderBy(n => n).ToList();

    #endregion

    #region Opaque filtering

    [Fact]
    public void DiscoverSecrets_Opaque_OnlyReturnsSecretsWithAnAllowedKey()
    {
        var client = CreateClient(
            Secret("has-cert", "Opaque", "tls.crt", "tls.key"),
            Secret("unrelated", "Opaque", "username", "password"),
            Secret("has-ca-crt", "Opaque", "ca.crt"));

        var locations = client.DiscoverSecrets(PemKeys, "Opaque", Ns);

        Assert.Equal(new[] { "has-ca-crt", "has-cert" }, Names(locations));
        Assert.All(locations, l => Assert.Contains($"/{Ns}/secrets/", l));
    }

    [Fact]
    public void DiscoverSecrets_Opaque_NoAllowedKeys_NotReturned()
    {
        var client = CreateClient(Secret("only-other", "Opaque", "foo", "bar.txt"));

        Assert.Empty(client.DiscoverSecrets(PemKeys, "Opaque", Ns));
    }

    [Fact]
    public void DiscoverSecrets_Opaque_NullOrEmptyData_NotReturned()
    {
        var client = CreateClient(NoData("null-data", "Opaque"), Secret("empty-data", "Opaque"));

        Assert.Empty(client.DiscoverSecrets(PemKeys, "Opaque", Ns));
    }

    [Fact]
    public void DiscoverSecrets_Opaque_NullAllowedKeys_DoesNotFilter()
    {
        var client = CreateClient(Secret("anything", "Opaque", "foo"));

        Assert.Single(client.DiscoverSecrets(null, "Opaque", Ns));
    }

    [Fact]
    public void DiscoverSecrets_Opaque_EmptyAllowedKeys_DoesNotFilter()
    {
        var client = CreateClient(Secret("anything", "Opaque", "foo"));

        Assert.Single(client.DiscoverSecrets(new string[0], "Opaque", Ns));
    }

    [Fact]
    public void DiscoverSecrets_Opaque_CustomPattern_IsHonoured()
    {
        var client = CreateClient(
            Secret("by-pattern", "Opaque", "my-bundle"),
            Secret("by-suffix", "Opaque", "prod.my-bundle"),
            Secret("other", "Opaque", "something-else"));

        var locations = client.DiscoverSecrets(PemKeys.Append("my-bundle").ToArray(), "Opaque", Ns);

        Assert.Equal(new[] { "by-pattern", "by-suffix" }, Names(locations));
    }

    [Fact]
    public void DiscoverSecrets_Opaque_IgnoresSecretsOfOtherTypes()
    {
        var client = CreateClient(
            Secret("tls-secret", "kubernetes.io/tls", "tls.crt", "tls.key"),
            Secret("opaque-secret", "Opaque", "tls.crt"));

        Assert.Equal(new[] { "opaque-secret" }, Names(client.DiscoverSecrets(PemKeys, "Opaque", Ns)));
    }

    #endregion

    #region Keystore key naming (JKS / PKCS12)

    [Theory]
    [InlineData("jks")]
    [InlineData("keystore.jks")]
    [InlineData("truststore.jks")]
    [InlineData("my-app.jks")]
    [InlineData("MyApp.JKS")]
    [InlineData("tls.jks")]
    public void DiscoverSecrets_Jks_ValidKeystoreFieldNames_AreDiscovered(string fieldName)
    {
        var client = CreateClient(Secret("ks", "Opaque", fieldName));

        Assert.Single(client.DiscoverSecrets(JksKeys, "Opaque", Ns));
    }

    [Theory]
    [InlineData("keystore")]
    [InlineData("keystore.jks.bak")]
    [InlineData("keystore.p12")]
    [InlineData("notjks")]
    public void DiscoverSecrets_Jks_NonKeystoreFieldNames_AreNotDiscovered(string fieldName)
    {
        var client = CreateClient(Secret("not-ks", "Opaque", fieldName));

        Assert.Empty(client.DiscoverSecrets(JksKeys, "Opaque", Ns));
    }

    [Theory]
    [InlineData("pkcs12")]
    [InlineData("p12")]
    [InlineData("pfx")]
    [InlineData("keystore.p12")]
    [InlineData("keystore.pfx")]
    [InlineData("tls.pfx")]
    [InlineData("tls.pkcs12")]
    [InlineData("Server.PFX")]
    public void DiscoverSecrets_Pkcs12_ValidKeystoreFieldNames_AreDiscovered(string fieldName)
    {
        var client = CreateClient(Secret("ks", "Opaque", fieldName));

        Assert.Single(client.DiscoverSecrets(Pkcs12Keys, "Opaque", Ns));
    }

    [Fact]
    public void DiscoverSecrets_Pkcs12_JksOnlySecret_IsNotDiscovered()
    {
        var client = CreateClient(Secret("jks-only", "Opaque", "keystore.jks"));

        Assert.Empty(client.DiscoverSecrets(Pkcs12Keys, "Opaque", Ns));
    }

    [Fact]
    public void DiscoverSecrets_Jks_CustomExtension_IsAdditiveToDefaults()
    {
        var client = CreateClient(
            Secret("default-name", "Opaque", "keystore.jks"),
            Secret("custom-ext", "Opaque", "store.jceks"),
            Secret("neither", "Opaque", "store.bin"));

        var keys = JksKeys.Append("jceks").ToArray();

        Assert.Equal(new[] { "custom-ext", "default-name" }, Names(client.DiscoverSecrets(keys, "Opaque", Ns)));
    }

    #endregion

    #region TLS secrets are unaffected

    [Fact]
    public void DiscoverSecrets_Tls_IgnoresAllowedKeysAndStillRequiresTlsCrtAndKey()
    {
        var client = CreateClient(
            Secret("good-tls", "kubernetes.io/tls", "tls.crt", "tls.key"),
            Secret("tls-missing-key", "kubernetes.io/tls", "tls.crt"));

        // Allowed keys that match nothing in the secret must not hide a valid TLS secret.
        var locations = client.DiscoverSecrets(new[] { "jks" }, "kubernetes.io/tls", Ns);

        Assert.Equal(new[] { "good-tls" }, Names(locations));
    }

    #endregion

    #region No per-secret reads (list response is used directly)

    [Fact]
    public void DiscoverSecrets_UsesListResponse_AndNeverReadsIndividualSecrets()
    {
        var kube = MockedKubeClientFactory.Create(new[]
        {
            Secret("good-tls", "kubernetes.io/tls", "tls.crt", "tls.key"),
            Secret("tls-no-key", "kubernetes.io/tls", "tls.crt"),
            NoData("tls-null-data", "kubernetes.io/tls"),
            Secret("opaque-cert", "Opaque", "cert.pem"),
            Secret("opaque-other", "Opaque", "username"),
            NoData("opaque-null-data", "Opaque"),
            Secret("opaque-empty-data", "Opaque"),
            Secret("sa-token", "kubernetes.io/service-account-token", "token")
        }, new[] { Ns }, allowSecretReads: false);

        var tls = kube.Client.DiscoverSecrets(PemKeys, "kubernetes.io/tls", Ns);
        var opaque = kube.Client.DiscoverSecrets(PemKeys, "Opaque", Ns);

        // Same results as when each secret was re-read after listing
        Assert.Equal(new[] { "good-tls" }, Names(tls));
        Assert.Equal(new[] { "opaque-cert" }, Names(opaque));
        Assert.All(tls.Concat(opaque), l => Assert.Contains($"/{Ns}/secrets/", l));

        // One list per call, and no GET /secrets/{name} at all
        Assert.Equal(0, kube.ReadSecretCallCount);
        Assert.Equal(2, kube.ListSecretsCallCount);
    }

    [Fact]
    public void DiscoverSecrets_AllNamespaces_MakesOneListCallPerNamespace_AndNoReads()
    {
        var kube = MockedKubeClientFactory.Create(new[]
        {
            MockedKubeClientFactory.Secret("ns-a", "a1", "Opaque", new Dictionary<string, byte[]> { ["tls.crt"] = new byte[] { 1 } }),
            MockedKubeClientFactory.Secret("ns-a", "a2", "Opaque", new Dictionary<string, byte[]> { ["tls.crt"] = new byte[] { 1 } }),
            MockedKubeClientFactory.Secret("ns-b", "b1", "Opaque", new Dictionary<string, byte[]> { ["tls.crt"] = new byte[] { 1 } }),
            MockedKubeClientFactory.Secret("ns-c", "c1", "Opaque", new Dictionary<string, byte[]> { ["unrelated"] = new byte[] { 1 } })
        }, allowSecretReads: false);

        var locations = kube.Client.DiscoverSecrets(PemKeys, "Opaque", "all");

        Assert.Equal(new[] { "a1", "a2", "b1" }, Names(locations));
        Assert.Equal(3, kube.ListSecretsCallCount); // 3 namespaces, not 3 + 4 secrets
        Assert.Equal(0, kube.ReadSecretCallCount);
    }

    #endregion

    #region HasAllowedDataKey

    [Theory]
    [InlineData("tls.crt", "tls.crt", true)]
    [InlineData("TLS.CRT", "tls.crt", true)]
    [InlineData("ca.crt", "crt", true)]
    [InlineData("keystore.jks", "jks", true)]
    [InlineData("keystore.jks", ".jks", true)]
    [InlineData("keystore.jks", " jks ", true)]
    [InlineData("jks", "jks", true)]
    [InlineData("keystore", "jks", false)]
    [InlineData("notjks", "jks", false)]
    [InlineData("jks.bak", "jks", false)]
    [InlineData("keystore.jks", "", false)]
    [InlineData("keystore.jks", ".", false)]
    public void HasAllowedDataKey_MatchesEqualOrDotSuffix_CaseInsensitive(string key, string allowed, bool expected)
    {
        Assert.Equal(expected, KubeCertificateManagerClient.HasAllowedDataKey(new[] { key }, new[] { allowed }));
    }

    [Fact]
    public void HasAllowedDataKey_NullInputs_ReturnFalse()
    {
        Assert.False(KubeCertificateManagerClient.HasAllowedDataKey(null, new[] { "jks" }));
        Assert.False(KubeCertificateManagerClient.HasAllowedDataKey(new[] { "jks" }, null));
    }

    #endregion
}
