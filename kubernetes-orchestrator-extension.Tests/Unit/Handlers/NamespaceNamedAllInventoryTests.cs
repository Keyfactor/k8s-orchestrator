// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

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
/// "all" is a wildcard only in discovery-job input and in the K8SCluster inventory request. A K8SNS store whose
/// namespace is literally named "all" (a valid Kubernetes name) must inventory that namespace and nothing else.
/// </summary>
public class NamespaceNamedAllInventoryTests
{
    private const string AllNs = "all";
    private const string TeamA = "team-a";
    private const string TeamB = "team-b";

    private static ISecretOperationContext Context(string ns)
    {
        var mock = new Mock<ISecretOperationContext>();
        mock.Setup(c => c.KubeNamespace).Returns(ns);
        mock.Setup(c => c.KubeSecretName).Returns(string.Empty);
        mock.Setup(c => c.StorePath).Returns(ns);
        mock.Setup(c => c.StorePassword).Returns(string.Empty);
        mock.Setup(c => c.PasswordSecretPath).Returns(string.Empty);
        mock.Setup(c => c.PasswordFieldName).Returns(string.Empty);
        mock.Setup(c => c.SeparateChain).Returns(false);
        mock.Setup(c => c.IncludeCertChain).Returns(true);
        mock.Setup(c => c.CertificateDataFieldName).Returns(string.Empty);
        return mock.Object;
    }

    /// <summary>One TLS and one Opaque secret in each of the namespaces "all", "team-a" and "team-b".</summary>
    private static MockedKubeClient Cluster()
    {
        var cert = CertificateTestHelper.ConvertCertificateToPem(
            CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "all-ns").Certificate);
        byte[] B(string s) => Encoding.UTF8.GetBytes(s);

        var secrets = new List<V1Secret>();
        foreach (var ns in new[] { AllNs, TeamA, TeamB })
        {
            secrets.Add(MockedKubeClientFactory.Secret(ns, $"tls-in-{ns}", "kubernetes.io/tls",
                new Dictionary<string, byte[]> { ["tls.crt"] = B(cert) }));
            secrets.Add(MockedKubeClientFactory.Secret(ns, $"opaque-in-{ns}", "Opaque",
                new Dictionary<string, byte[]> { ["cert"] = B(cert) }));
        }

        return MockedKubeClientFactory.Create(secrets, new[] { "default" }, allowSecretReads: false);
    }

    private static List<InventoryEntry> NamespaceInventory(MockedKubeClient kube, string ns)
        => new NamespaceSecretHandler(kube.Client, new Mock<ILogger>().Object, Context(ns)).GetInventoryEntries(1);

    [Fact]
    public void NamespaceInventory_NamespaceLiterallyNamedAll_ReturnsOnlyThatNamespacesSecrets()
    {
        var kube = Cluster();

        var entries = NamespaceInventory(kube, AllNs);

        Assert.Equal(new[] { $"tls/tls-in-{AllNs}", $"opaque/opaque-in-{AllNs}" }, entries.Select(e => e.Alias).ToArray());
        // Only the "all" namespace may have been listed: nothing from team-a / team-b can reach this store.
        Assert.Equal(new[] { AllNs }, kube.ListedSecretNamespaces.ToArray());
    }

    [Theory]
    [InlineData("All")]
    [InlineData("ALL")]
    [InlineData(" all ")]
    public void NamespaceInventory_AllInAnyCasing_IsStillOnlyThatNamespace(string storeNamespace)
    {
        var kube = Cluster();

        var entries = NamespaceInventory(kube, storeNamespace);

        Assert.Equal(2, entries.Count);
        Assert.Equal(new[] { AllNs }, kube.ListedSecretNamespaces.ToArray());
    }

    [Fact]
    public void NamespaceInventory_OrdinaryNamespace_IsUnchanged()
    {
        var kube = Cluster();

        var entries = NamespaceInventory(kube, TeamA);

        Assert.Equal(new[] { $"tls/tls-in-{TeamA}", $"opaque/opaque-in-{TeamA}" }, entries.Select(e => e.Alias).ToArray());
        Assert.Equal(new[] { TeamA }, kube.ListedSecretNamespaces.ToArray());
    }

    [Fact]
    public void NamespaceInventory_MissingNamespace_ReturnsNothing()
    {
        var kube = Cluster();

        Assert.Empty(NamespaceInventory(kube, "does-not-exist"));
        Assert.Empty(kube.ListedSecretNamespaces);
    }

    [Fact]
    public void ClusterInventory_StillCoversEveryNamespace_IncludingOneNamedAll()
    {
        var kube = Cluster();

        var entries = new ClusterSecretHandler(kube.Client, new Mock<ILogger>().Object, Context("ignored-by-cluster"))
            .GetInventoryEntries(1);

        var aliases = entries.Select(e => e.Alias).ToHashSet();
        foreach (var ns in new[] { AllNs, TeamA, TeamB })
        {
            Assert.Contains($"{ns}/secrets/tls/tls-in-{ns}", aliases);
            Assert.Contains($"{ns}/secrets/opaque/opaque-in-{ns}", aliases);
        }

        Assert.Equal(6, entries.Count);
        // "default" holds no secrets but is a namespace of the cluster, so it is listed too.
        Assert.Equal(4, kube.ListedSecretNamespaces.Count);
    }

    [Fact]
    public void Discovery_DirsAll_StillMeansEveryNamespace_EvenWhenOneIsNamedAll()
    {
        var kube = Cluster();
        var handler = new NamespaceSecretHandler(kube.Client, new Mock<ILogger>().Object, Context(AllNs));

        var locations = handler.DiscoverStores(null, "all");

        // The discovery keyword is a wildcard: all four namespaces ("default", "all", "team-a", "team-b").
        Assert.Equal(4, locations.Count);
        Assert.All(new[] { "default", AllNs, TeamA, TeamB },
            ns => Assert.Contains(locations, l => l.EndsWith($"/namespace/{ns}")));
    }
}
