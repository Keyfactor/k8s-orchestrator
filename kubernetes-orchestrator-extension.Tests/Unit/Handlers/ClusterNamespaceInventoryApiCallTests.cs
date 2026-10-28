// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using KeyType = Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper.KeyType;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Handlers;

/// <summary>
/// GitHub issue #104: K8SCluster / K8SNS inventory must list each namespace's secrets once and must not re-read
/// every secret by name, while producing exactly the inventory the previous implementation produced.
/// </summary>
public class ClusterNamespaceInventoryApiCallTests
{
    private const string NsA = "perf-a";
    private const string NsB = "perf-b";

    private static ISecretOperationContext Context(string ns, string secretName = "")
    {
        var mock = new Mock<ISecretOperationContext>();
        mock.Setup(c => c.KubeNamespace).Returns(ns);
        mock.Setup(c => c.KubeSecretName).Returns(secretName);
        mock.Setup(c => c.StorePath).Returns(ns);
        mock.Setup(c => c.StorePassword).Returns(string.Empty);
        mock.Setup(c => c.PasswordSecretPath).Returns(string.Empty);
        mock.Setup(c => c.PasswordFieldName).Returns(string.Empty);
        mock.Setup(c => c.SeparateChain).Returns(false);
        mock.Setup(c => c.IncludeCertChain).Returns(true);
        mock.Setup(c => c.CertificateDataFieldName).Returns(string.Empty);
        return mock.Object;
    }

    private static byte[] B(string s) => Encoding.UTF8.GetBytes(s);

    /// <summary>TLS with/without ca.crt, Opaque cert+key, cert only, key-only, password-only, plus ignored secrets.</summary>
    private static List<V1Secret> MixedSecrets()
    {
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048, "perf-chain");
        var leaf = CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate);
        var intermediate = CertificateTestHelper.ConvertCertificateToPem(chain[1].Certificate);
        var key = CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private);
        var other = CertificateTestHelper.ConvertCertificateToPem(
            CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "perf-other").Certificate);

        return new List<V1Secret>
        {
            MockedKubeClientFactory.Secret(NsA, "tls-no-ca", "kubernetes.io/tls",
                new Dictionary<string, byte[]> { ["tls.crt"] = B(leaf), ["tls.key"] = B(key) }),
            MockedKubeClientFactory.Secret(NsA, "tls-with-ca", "kubernetes.io/tls",
                new Dictionary<string, byte[]>
                    { ["tls.crt"] = B(leaf), ["tls.key"] = B(key), ["ca.crt"] = B(intermediate) }),
            MockedKubeClientFactory.Secret(NsA, "tls-no-key", "kubernetes.io/tls",
                new Dictionary<string, byte[]> { ["tls.crt"] = B(leaf) }),
            MockedKubeClientFactory.Secret(NsA, "opaque-cert-key", "Opaque",
                new Dictionary<string, byte[]> { ["tls.crt"] = B(leaf), ["tls.key"] = B(key) }),
            MockedKubeClientFactory.Secret(NsA, "opaque-cert-only", "Opaque",
                new Dictionary<string, byte[]> { ["cert"] = B(other) }),
            MockedKubeClientFactory.Secret(NsA, "opaque-key-only", "Opaque",
                new Dictionary<string, byte[]> { ["tls.key"] = B(key) }),
            MockedKubeClientFactory.Secret(NsA, "opaque-password-only", "Opaque",
                new Dictionary<string, byte[]> { ["password"] = B("hunter2\n") }),
            MockedKubeClientFactory.Secret(NsA, "docker", "kubernetes.io/dockerconfigjson",
                new Dictionary<string, byte[]> { [".dockerconfigjson"] = B("{}") }),
            MockedKubeClientFactory.Secret(NsB, "tls-b", "kubernetes.io/tls",
                new Dictionary<string, byte[]> { ["tls.crt"] = B(other), ["tls.key"] = B(key) }),
            MockedKubeClientFactory.Secret(NsB, "opaque-b", "Opaque",
                new Dictionary<string, byte[]> { ["crt"] = B(leaf) })
        };
    }

    private static int NamespaceListCount(MockedKubeClient kube) => kube.Core.Invocations.Count(i =>
        i.Method.Name == "ListNamespaceWithHttpMessagesAsync");

    private static string Serialize(IEnumerable<InventoryEntry> entries) => string.Join("\n",
        entries.Select(e => $"{e.Alias}|{e.HasPrivateKey}|{string.Join("~", e.Certificates)}"));

    /// <summary>
    /// The pre-#104 algorithm, rebuilt from public pieces: discover twice (tls, then every Opaque), then run an inner
    /// handler per discovered path, each of which re-reads its secret by name.
    /// </summary>
    private static List<InventoryEntry> LegacyInventory(MockedKubeClient kube, string ns, bool cluster)
    {
        var entries = new List<InventoryEntry>();
        var tls = kube.Client.DiscoverSecrets(new[] { "tls.crt" }, "kubernetes.io/tls", ns);
        var opaque = kube.Client.DiscoverSecrets(null, "Opaque", ns,
            opaqueKeyMatch: Keyfactor.Extensions.Orchestrator.K8S.Enums.OpaqueKeyMatch.AllSecrets);
        foreach (var (paths, type) in new[] { (tls, "tls"), (opaque, "opaque") })
        foreach (var path in paths)
        {
            var parts = path.Split('/');
            var secretNs = parts[1];
            var name = parts[^1];
            var ctx = Context(secretNs, name);
            ISecretHandler h = type == "tls"
                ? new TlsSecretHandler(kube.Client, new Mock<ILogger>().Object, ctx)
                : new OpaqueSecretHandler(kube.Client, new Mock<ILogger>().Object, ctx);
            foreach (var e in h.GetInventoryEntries(1))
            {
                e.Alias = cluster ? $"{secretNs}/secrets/{type}/{name}" : $"{type}/{name}";
                entries.Add(e);
            }
        }

        return entries;
    }

    [Fact]
    public void Cluster_Inventory_ListsOncePerNamespace_AndNeverReadsSecretsByName()
    {
        var kube = MockedKubeClientFactory.Create(MixedSecrets());
        var handler = new ClusterSecretHandler(kube.Client, new Mock<ILogger>().Object, Context(NsA));

        var entries = handler.GetInventoryEntries(1);

        Assert.NotEmpty(entries);
        Assert.Equal(1, NamespaceListCount(kube));
        Assert.Equal(2, kube.ListSecretsCallCount); // two namespaces, one list each
        Assert.Equal(0, kube.ReadSecretCallCount);
    }

    [Fact]
    public void Namespace_Inventory_ListsOnce_AndNeverReadsSecretsByName()
    {
        var kube = MockedKubeClientFactory.Create(MixedSecrets());
        var handler = new NamespaceSecretHandler(kube.Client, new Mock<ILogger>().Object, Context(NsA));

        var entries = handler.GetInventoryEntries(1);

        Assert.NotEmpty(entries);
        Assert.Equal(1, NamespaceListCount(kube));
        Assert.Equal(1, kube.ListSecretsCallCount);
        Assert.Equal(0, kube.ReadSecretCallCount);
    }

    [Fact]
    public void Cluster_Inventory_OutputMatchesLegacyAlgorithm()
    {
        var secrets = MixedSecrets();
        var expected = LegacyInventory(MockedKubeClientFactory.Create(secrets), "all", cluster: true);

        var kube = MockedKubeClientFactory.Create(secrets);
        var actual = new ClusterSecretHandler(kube.Client, new Mock<ILogger>().Object, Context(NsA))
            .GetInventoryEntries(1);

        Assert.Equal(Serialize(expected), Serialize(actual));
        AssertMixedShape(actual, $"{NsA}/secrets/");
        Assert.Contains(actual, e => e.Alias == $"{NsB}/secrets/tls/tls-b");
        Assert.Contains(actual, e => e.Alias == $"{NsB}/secrets/opaque/opaque-b");
    }

    [Fact]
    public void Namespace_Inventory_OutputMatchesLegacyAlgorithm()
    {
        var secrets = MixedSecrets();
        var expected = LegacyInventory(MockedKubeClientFactory.Create(secrets), NsA, cluster: false);

        var kube = MockedKubeClientFactory.Create(secrets);
        var actual = new NamespaceSecretHandler(kube.Client, new Mock<ILogger>().Object, Context(NsA))
            .GetInventoryEntries(1);

        Assert.Equal(Serialize(expected), Serialize(actual));
        AssertMixedShape(actual, "");
        Assert.DoesNotContain(actual, e => e.Alias.Contains("-b"));
    }

    private static void AssertMixedShape(List<InventoryEntry> actual, string prefix)
    {
        InventoryEntry Get(string alias) => Assert.Single(actual, e => e.Alias == prefix + alias);

        Assert.Single(Get("tls/tls-no-ca").Certificates);
        Assert.True(Get("tls/tls-no-ca").HasPrivateKey);
        Assert.True(Get("tls/tls-with-ca").Certificates.Count >= 1);
        Assert.True(Get("tls/tls-with-ca").HasPrivateKey);
        Assert.DoesNotContain(actual, e => e.Alias == prefix + "tls/tls-no-key"); // discovery requires tls.key
        Assert.True(Get("opaque/opaque-cert-key").HasPrivateKey);
        Assert.Single(Get("opaque/opaque-cert-key").Certificates);
        Assert.False(Get("opaque/opaque-cert-only").HasPrivateKey);
        Assert.Single(Get("opaque/opaque-cert-only").Certificates);
        Assert.Empty(Get("opaque/opaque-key-only").Certificates);
        Assert.True(Get("opaque/opaque-key-only").HasPrivateKey);
        Assert.Empty(Get("opaque/opaque-password-only").Certificates);
        Assert.False(Get("opaque/opaque-password-only").HasPrivateKey);
        Assert.DoesNotContain(actual, e => e.Alias.EndsWith("docker"));
        // TLS entries first, then Opaque, as before.
        Assert.True(actual.FindLastIndex(e => e.Alias.Contains("tls/")) <
                    actual.FindIndex(e => e.Alias.Contains("opaque/")));
    }
}
