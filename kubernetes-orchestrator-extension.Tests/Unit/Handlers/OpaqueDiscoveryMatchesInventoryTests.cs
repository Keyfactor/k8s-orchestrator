// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Handlers;

/// <summary>
/// K8SSecret (Opaque) discovery must report exactly the secrets that K8SSecret inventory can read: a secret is
/// discovered only if it has a data key (exact match) that inventory reads as a certificate, or that matches a
/// job-supplied pattern. Private-key-only / CA-only / "*.crt"-suffixed secrets must not be reported.
/// K8SJKS discovery keeps the ".&lt;allowed&gt;" suffix rule.
/// </summary>
public class OpaqueDiscoveryMatchesInventoryTests
{
    private const string Ns = "app-ns";

    private static ISecretOperationContext Context(string ns, string secretName = "")
    {
        var mock = new Mock<ISecretOperationContext>();
        mock.Setup(c => c.KubeNamespace).Returns(ns);
        mock.Setup(c => c.KubeSecretName).Returns(secretName);
        mock.Setup(c => c.StorePath).Returns(string.IsNullOrEmpty(secretName) ? ns : $"{ns}/{secretName}");
        mock.Setup(c => c.StorePassword).Returns(string.Empty);
        mock.Setup(c => c.PasswordSecretPath).Returns(string.Empty);
        mock.Setup(c => c.PasswordFieldName).Returns(string.Empty);
        mock.Setup(c => c.SeparateChain).Returns(false);
        mock.Setup(c => c.IncludeCertChain).Returns(false);
        mock.Setup(c => c.CertificateDataFieldName).Returns(string.Empty);
        return mock.Object;
    }

    private static string CertPem() => CertificateTestHelper.ConvertCertificateToPem(
        CachedCertificateProvider.GetOrCreate(CertificateTestHelper.KeyType.Rsa2048, "opaque-discovery-vs-inventory")
            .Certificate);

    private static MockedKubeClient ClientWith(params (string name, string[] keys)[] secrets)
    {
        var pem = Encoding.UTF8.GetBytes(CertPem());
        var token = Encoding.UTF8.GetBytes(CertificateTestHelper.ConvertPrivateKeyToPem(
            CachedCertificateProvider.GetOrCreate(CertificateTestHelper.KeyType.Rsa2048, "opaque-discovery-vs-inventory")
                .KeyPair.Private));
        // Private-key style fields hold non-certificate data, as they would in a real secret.
        byte[] PayloadFor(string key) => key.EndsWith("key", System.StringComparison.Ordinal) && key != "ca.crt" ? token : pem;
        return MockedKubeClientFactory.Create(secrets.Select(s =>
            MockedKubeClientFactory.Secret(Ns, s.name, "Opaque", s.keys.ToDictionary(k => k, PayloadFor))).ToArray());
    }

    private static List<string> Names(IEnumerable<string> locations) =>
        locations.Select(l => l.Split('/').Last()).OrderBy(n => n).ToList();

    /// <summary>The key list DiscoveryBase hands to the handler: job patterns merged with the handler defaults.</summary>
    private static string[] AsDiscoveryBaseWouldPass(OpaqueSecretHandler handler, params string[] patterns) =>
        patterns.Concat(handler.AllowedKeys).ToArray();

    private static OpaqueSecretHandler NewHandler(MockedKubeClient kube) =>
        new(kube.Client, new Mock<ILogger>().Object, Context(Ns));

    [Theory]
    [InlineData("server.crt")]
    [InlineData("api.key")]
    [InlineData("tls.key")]
    [InlineData("key")]
    [InlineData("ca")]
    [InlineData("ca.crt")]
    [InlineData("private-key")]
    [InlineData("prod.cert.pem")]
    public void K8SSecret_Discovery_SkipsSecretsInventoryCannotReadAsCertificate(string dataKey)
    {
        var kube = ClientWith(("not-a-cert-store", new[] { dataKey }));
        var handler = NewHandler(kube);

        Assert.Empty(handler.DiscoverStores(AsDiscoveryBaseWouldPass(handler), Ns));
        Assert.Empty(handler.DiscoverStores(null, Ns));
    }

    [Theory]
    [InlineData("tls.crt")]
    [InlineData("cert.pem")]
    [InlineData("certificate")]
    [InlineData("cert")]
    [InlineData("crt")]
    [InlineData("certificate.pem")]
    public void K8SSecret_Discovery_IncludesSecretsWithInventoryReadableCertificateKey(string dataKey)
    {
        var kube = ClientWith(("cert-store", new[] { dataKey }));
        var handler = NewHandler(kube);

        Assert.Equal(new[] { "cert-store" }, Names(handler.DiscoverStores(AsDiscoveryBaseWouldPass(handler), Ns)));
    }

    [Fact]
    public void K8SSecret_Discovery_IncludesSecretWhoseOnlyKeyMatchesAPattern()
    {
        var kube = ClientWith(("by-pattern", new[] { "my-bundle" }), ("other", new[] { "something-else" }));
        var handler = NewHandler(kube);

        var locations = handler.DiscoverStores(AsDiscoveryBaseWouldPass(handler, "my-bundle"), Ns);

        Assert.Equal(new[] { "by-pattern" }, Names(locations));
    }

    [Fact]
    public void K8SSecret_Discovery_PatternsAreExactNotSuffix()
    {
        var kube = ClientWith(("suffixed", new[] { "prod.my-bundle" }));
        var handler = NewHandler(kube);

        Assert.Empty(handler.DiscoverStores(AsDiscoveryBaseWouldPass(handler, "my-bundle"), Ns));
    }

    [Fact]
    public void K8SSecret_Discovery_AgreesWithInventory()
    {
        var keysToTry = new[]
        {
            "tls.crt", "cert.pem", "certificate", "server.crt", "api.key", "tls.key", "ca", "ca.crt", "key"
        };
        var kube = ClientWith(keysToTry.Select(k => ($"s-{k.Replace('.', '-')}", new[] { k })).ToArray());
        var discoverer = NewHandler(kube);
        var discovered = Names(discoverer.DiscoverStores(AsDiscoveryBaseWouldPass(discoverer), Ns));

        var inventoried = new List<string>();
        foreach (var key in keysToTry)
        {
            var name = $"s-{key.Replace('.', '-')}";
            var inv = new OpaqueSecretHandler(kube.Client, new Mock<ILogger>().Object, Context(Ns, name));
            // Deliberate exception: inventory also reads a lone "ca"/"ca.crt" as CA certificates, but CA-only
            // secrets are not reported as K8SSecret stores by design.
            // Inventory may also throw on a lone private-key field (it tries to parse it as a certificate); either
            // way such a secret yields no certificate.
            var certs = new List<string>();
            try { certs = inv.GetCertificates(1); }
            catch (System.Exception) { /* nothing readable */ }

            if (certs.Count > 0 && key != "ca" && key != "ca.crt") inventoried.Add(name);
        }

        Assert.Equal(inventoried.OrderBy(n => n).ToList(), discovered);
    }

    [Fact]
    public void K8SJks_Discovery_StillFindsKeystoreJks_WithSuffixRule()
    {
        var kube = ClientWith(("jks-store", new[] { "keystore.jks" }), ("custom", new[] { "my.jks" }),
            ("not-jks", new[] { "tls.crt" }));
        var handler = new JksSecretHandler(kube.Client, new Mock<ILogger>().Object, Context(Ns));

        var locations = handler.DiscoverStores(handler.AllowedKeys, Ns);

        Assert.Equal(new[] { "custom", "jks-store" }, Names(locations));
    }
}
