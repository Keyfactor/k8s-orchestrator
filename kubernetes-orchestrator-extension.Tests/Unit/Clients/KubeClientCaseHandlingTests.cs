// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Linq;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Clients;

/// <summary>
/// Case-handling consistency in <c>KubeCertificateManagerClient</c> (PR #103 review nits):
/// namespace-name filtering and JKS/PKCS12 inventory field selection must be case-insensitive,
/// matching discovery and the 'all' / 'ignoreddirs' keywords.
/// </summary>
public class KubeClientCaseHandlingTests
{
    private static readonly byte[] Bytes = { 1, 2, 3 };

    #region Namespace name matching

    [Theory]
    [InlineData("Team-A")]
    [InlineData("TEAM-A")]
    [InlineData("team-a")]
    public void DiscoverSecrets_NamespaceMode_NamesMatchCaseInsensitively(string requested)
    {
        var client = MockedKubeClientFactory
            .Create(new List<k8s.Models.V1Secret>(), new[] { "team-a", "team-b" }).Client;

        var locations = client.DiscoverSecrets(null, "namespace", requested);

        var location = Assert.Single(locations);
        Assert.EndsWith("/namespace/team-a", location);
    }

    [Fact]
    public void DiscoverSecrets_NamespaceMode_OneLocationPerNamespace_ShapeIsClusterSlashNamespaceSlashName()
    {
        var client = MockedKubeClientFactory
            .Create(new List<k8s.Models.V1Secret>(), new[] { "ns-1", "ns-2", "ns-3" }).Client;

        // allowedKeys are ignored in namespace mode: passing null or patterns must give the same output.
        var withNull = client.DiscoverSecrets(null, "namespace", "ns-1,ns-2");
        var withKeys = client.DiscoverSecrets(new[] { "tls.crt", "jks" }, "namespace", "ns-1,ns-2");

        Assert.Equal(withNull, withKeys);
        Assert.Equal(new[] { "ns-1", "ns-2" }, withNull.Select(l => l.Split('/').Last()).OrderBy(n => n));
        Assert.All(withNull, l =>
        {
            var parts = l.Split('/');
            Assert.Equal("namespace", parts[^2]);
        });
        Assert.Equal(withNull.Count, withNull.Distinct().Count());
    }

    #endregion

    #region JKS / PKCS12 inventory field selection

    [Theory]
    [InlineData("KEYSTORE.JKS")]
    [InlineData("keystore.jks")]
    [InlineData("Store.Jks")]
    public void GetJksSecret_FieldNameCaseDiffersFromAllowedKeys_FieldIsInventoried(string field)
    {
        var secret = MockedKubeClientFactory.Secret("ns", "js", "Opaque",
            new Dictionary<string, byte[]> { [field] = Bytes, ["other"] = Bytes });
        var client = MockedKubeClientFactory.Create(new[] { secret }).Client;

        var result = client.GetJksSecret("js", "ns", allowedKeys: new List<string> { "jks" });

        Assert.Equal(new[] { field }, result.Inventory.Keys);
    }

    [Theory]
    [InlineData("KEYSTORE.P12")]
    [InlineData("store.PFX")]
    [InlineData("Keystore.Pkcs12")]
    public void GetPkcs12Secret_FieldNameCaseDiffersFromAllowedKeys_FieldIsInventoried(string field)
    {
        var secret = MockedKubeClientFactory.Secret("ns", "ps", "Opaque",
            new Dictionary<string, byte[]> { [field] = Bytes, ["other"] = Bytes });
        var client = MockedKubeClientFactory.Create(new[] { secret }).Client;

        var result = client.GetPkcs12Secret("ps", "ns",
            allowedKeys: new List<string> { "p12", "pfx", "pkcs12" });

        Assert.Equal(new[] { field }, result.Inventory.Keys);
    }

    #endregion
}
