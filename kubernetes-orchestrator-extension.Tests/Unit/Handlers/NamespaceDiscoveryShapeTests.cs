// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Handlers;

/// <summary>
/// K8SNS discovery (GitHub issue #102): a K8SNS store is a whole namespace, so discovery returns one
/// <c>&lt;cluster&gt;/namespace/&lt;ns&gt;</c> location per namespace matched by "Directories to search"
/// (1.x behaviour), and every returned location must be resolvable by <see cref="StorePathResolver"/> for K8SNS.
/// </summary>
public class NamespaceDiscoveryShapeTests
{
    private const string Cluster = "test-cluster";

    private static ISecretOperationContext Context(string ns = "default")
    {
        var mock = new Mock<ISecretOperationContext>();
        mock.Setup(c => c.KubeNamespace).Returns(ns);
        mock.Setup(c => c.KubeSecretName).Returns(string.Empty);
        mock.Setup(c => c.StorePath).Returns(ns);
        mock.Setup(c => c.StorePassword).Returns(string.Empty);
        mock.Setup(c => c.PasswordSecretPath).Returns(string.Empty);
        mock.Setup(c => c.PasswordFieldName).Returns(string.Empty);
        mock.Setup(c => c.SeparateChain).Returns(false);
        mock.Setup(c => c.IncludeCertChain).Returns(false);
        mock.Setup(c => c.CertificateDataFieldName).Returns(string.Empty);
        return mock.Object;
    }

    /// <summary>Cluster with namespaces team-a (a cert secret), team-b (a non-cert secret), team-c (empty), kube-system.</summary>
    private static NamespaceSecretHandler CreateHandler(string contextNamespace = "default")
    {
        var kube = MockedKubeClientFactory.Create(
            new[]
            {
                MockedKubeClientFactory.Secret("team-a", "web", "Opaque",
                    new Dictionary<string, byte[]> { ["tls.crt"] = new byte[] { 1 } }),
                MockedKubeClientFactory.Secret("team-b", "other", "Opaque",
                    new Dictionary<string, byte[]> { ["config.yaml"] = new byte[] { 1 } })
            },
            new[] { "team-c", "kube-system", "default" });

        return new NamespaceSecretHandler(kube.Client, new Mock<ILogger>().Object, Context(contextNamespace));
    }

    private static string[] Namespaces(IEnumerable<string> locations) =>
        locations.Select(l => l.Split('/').Last()).OrderBy(n => n).ToArray();

    [Theory]
    [InlineData("all")]
    [InlineData("All")]
    [InlineData("ALL")]
    [InlineData(" all ")]
    public void DiscoverStores_All_ReturnsOneNamespaceLocationPerNamespace(string directories)
    {
        var locations = CreateHandler().DiscoverStores(null, directories);

        Assert.Equal(new[] { "default", "kube-system", "team-a", "team-b", "team-c" }, Namespaces(locations));
        Assert.All(locations, l => Assert.StartsWith($"{Cluster}/namespace/", l));
    }

    [Fact]
    public void DiscoverStores_Csv_ReturnsOnlyMatchedNamespaces()
    {
        var locations = CreateHandler().DiscoverStores(null, "team-a, team-c");

        Assert.Equal(new[] { $"{Cluster}/namespace/team-a", $"{Cluster}/namespace/team-c" },
            locations.OrderBy(l => l).ToArray());
    }

    [Fact]
    public void DiscoverStores_DoesNotEmitPerSecretPaths()
    {
        var locations = CreateHandler().DiscoverStores(null, "all");

        Assert.DoesNotContain(locations, l => l.Contains("/secrets/"));
    }

    [Fact]
    public void DiscoverStores_ReportsEveryMatchedNamespace_EvenWithoutQualifyingSecrets()
    {
        // 1.x behaviour: team-b only holds a non-certificate secret and team-c is empty, both are still reported.
        var locations = CreateHandler().DiscoverStores(null, "team-b,team-c");

        Assert.Equal(new[] { "team-b", "team-c" }, Namespaces(locations));
    }

    [Fact]
    public void DiscoverStores_JobPatternsDoNotFilterNamespaces()
    {
        var locations = CreateHandler().DiscoverStores(new[] { "jks" }, "team-a,team-b");

        Assert.Equal(new[] { "team-a", "team-b" }, Namespaces(locations));
    }

    [Fact]
    public void DiscoverStores_UnmatchedNamespace_ReturnsEmpty()
    {
        Assert.Empty(CreateHandler().DiscoverStores(null, "does-not-exist"));
    }

    [Fact]
    public void DiscoverStores_BlankDirectories_ReturnsEmpty_CallerOwnsTheDefault()
    {
        // The "default" fallback lives in DiscoveryBase.GetNamespacesToSearch, so the handler never sees a blank CSV
        // from a job; called directly with one it matches nothing rather than guessing a namespace.
        Assert.Empty(CreateHandler("team-a").DiscoverStores(null, ""));
    }

    [Fact]
    public void DiscoverStores_ReturnedLocations_ResolveForK8SNSStoreType()
    {
        var locations = CreateHandler().DiscoverStores(null, "all");
        Assert.NotEmpty(locations);

        var resolver = new StorePathResolver();
        foreach (var location in locations)
        {
            var result = resolver.Resolve(location, "K8SNS", "", "");

            Assert.True(result.Success, $"'{location}' did not resolve for K8SNS: {result.Warning}");
            Assert.Equal(location.Split('/').Last(), result.Namespace);
            Assert.Equal("", result.SecretName);
        }
    }

    [Fact]
    public void DiscoverStores_ReturnedLocations_AreNotRejectedAsFourPartPaths()
    {
        // Regression for #102: the 2.x per-secret shape was rejected by StorePathResolver for K8SNS.
        var perSecretPath = $"{Cluster}/team-a/secrets/web";
        var rejected = new StorePathResolver().Resolve(perSecretPath, "K8SNS", "", "");
        Assert.False(rejected.Success);

        foreach (var location in CreateHandler().DiscoverStores(null, "all"))
            Assert.True(new StorePathResolver().Resolve(location, "K8SNS", "", "").Success);
    }
}
