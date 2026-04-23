// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Extensions.Orchestrator.K8S.Services;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Services;

public class StorePathResolverTests
{
    private readonly StorePathResolver _resolver = new();

    #region Single Part Paths

    [Fact]
    public void Resolve_SinglePart_RegularStore_SetsSecretName()
    {
        var result = _resolver.Resolve("my-secret", "CertStores.K8SSecret.Inventory", "", "");

        Assert.Equal("my-secret", result.SecretName);
        Assert.Equal("", result.Namespace);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_SinglePart_RegularStore_PreservesExistingSecretName()
    {
        var result = _resolver.Resolve("new-secret", "CertStores.K8SSecret.Inventory", "", "existing-secret");

        Assert.Equal("existing-secret", result.SecretName);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_SinglePart_NamespaceStore_SetsNamespace()
    {
        var result = _resolver.Resolve("my-namespace", "CertStores.K8SNS.Inventory", "", "");

        Assert.Equal("my-namespace", result.Namespace);
        Assert.Equal("", result.SecretName);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_SinglePart_NamespaceStore_PreservesExistingNamespace()
    {
        var result = _resolver.Resolve("new-ns", "CertStores.K8SNS.Inventory", "existing-ns", "");

        Assert.Equal("existing-ns", result.Namespace);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_SinglePart_ClusterStore_ClearsNamespaceAndSecret()
    {
        var result = _resolver.Resolve("my-cluster", "CertStores.K8SCluster.Inventory", "ns", "secret");

        Assert.Equal("", result.Namespace);
        Assert.Equal("", result.SecretName);
        Assert.True(result.Success);
        Assert.NotNull(result.Warning); // Should warn about clearing values
    }

    #endregion

    #region Two Part Paths

    [Fact]
    public void Resolve_TwoPart_RegularStore_SetsNamespaceAndSecret()
    {
        var result = _resolver.Resolve("my-ns/my-secret", "CertStores.K8SSecret.Inventory", "", "");

        Assert.Equal("my-ns", result.Namespace);
        Assert.Equal("my-secret", result.SecretName);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_TwoPart_RegularStore_PreservesExistingValues()
    {
        var result = _resolver.Resolve("new-ns/new-secret", "CertStores.K8SSecret.Inventory", "existing-ns", "existing-secret");

        Assert.Equal("existing-ns", result.Namespace);
        Assert.Equal("existing-secret", result.SecretName);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_TwoPart_NamespaceStore_SetsNamespace()
    {
        var result = _resolver.Resolve("cluster/my-namespace", "CertStores.K8SNS.Inventory", "", "");

        Assert.Equal("my-namespace", result.Namespace);
        Assert.Equal("", result.SecretName);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_TwoPart_ClusterStore_ReturnsWarning()
    {
        var result = _resolver.Resolve("cluster/something", "CertStores.K8SCluster.Inventory", "", "");

        Assert.NotNull(result.Warning);
        Assert.True(result.Success);
    }

    #endregion

    #region Three Part Paths

    [Fact]
    public void Resolve_ThreePart_RegularStore_SetsNamespaceAndSecret()
    {
        var result = _resolver.Resolve("cluster/my-ns/my-secret", "CertStores.K8SSecret.Inventory", "", "");

        Assert.Equal("my-ns", result.Namespace);
        Assert.Equal("my-secret", result.SecretName);
        Assert.True(result.Success);
    }

    [Theory]
    [InlineData("secret")]
    [InlineData("secrets")]
    [InlineData("tls")]
    [InlineData("certificate")]
    [InlineData("namespace")]
    public void Resolve_ThreePart_WithReservedKeyword_ReinterpretsAsNamespaceTypeSecret(string keyword)
    {
        var result = _resolver.Resolve($"my-ns/{keyword}/my-secret", "CertStores.K8SSecret.Inventory", "", "");

        Assert.Equal("my-ns", result.Namespace);
        Assert.Equal("my-secret", result.SecretName);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_ThreePart_NamespaceStore_SetsNamespace()
    {
        var result = _resolver.Resolve("cluster/namespace/my-ns", "CertStores.K8SNS.Inventory", "", "");

        Assert.Equal("my-ns", result.Namespace);
        Assert.Equal("", result.SecretName);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_ThreePart_NamespaceStore_ClearsSecretName()
    {
        var result = _resolver.Resolve("cluster/namespace/my-ns", "CertStores.K8SNS.Inventory", "", "existing-secret");

        Assert.Equal("", result.SecretName);
        Assert.NotNull(result.Warning); // Should warn about clearing secret name
    }

    [Fact]
    public void Resolve_ThreePart_ClusterStore_ReturnsError()
    {
        var result = _resolver.Resolve("a/b/c", "CertStores.K8SCluster.Inventory", "", "");

        Assert.False(result.Success);
        Assert.NotNull(result.Warning);
    }

    #endregion

    #region Four Part Paths

    [Fact]
    public void Resolve_FourPart_RegularStore_SetsNamespaceAndSecret()
    {
        var result = _resolver.Resolve("cluster/my-ns/tls/my-secret", "CertStores.K8SSecret.Inventory", "", "");

        Assert.Equal("my-ns", result.Namespace);
        Assert.Equal("my-secret", result.SecretName);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_FourPart_ClusterStore_ReturnsError()
    {
        var result = _resolver.Resolve("a/b/c/d", "CertStores.K8SCluster.Inventory", "", "");

        Assert.False(result.Success);
        Assert.NotNull(result.Warning);
    }

    [Fact]
    public void Resolve_FourPart_NamespaceStore_ReturnsError()
    {
        var result = _resolver.Resolve("a/b/c/d", "CertStores.K8SNS.Inventory", "", "");

        Assert.False(result.Success);
        Assert.NotNull(result.Warning);
    }

    #endregion

    #region Edge Cases

    [Fact]
    public void Resolve_EmptyPath_ReturnsCurrentValues()
    {
        var result = _resolver.Resolve("", "CertStores.K8SSecret.Inventory", "existing-ns", "existing-secret");

        Assert.Equal("existing-ns", result.Namespace);
        Assert.Equal("existing-secret", result.SecretName);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_NullPath_ReturnsCurrentValues()
    {
        var result = _resolver.Resolve(null, "CertStores.K8SSecret.Inventory", "existing-ns", "existing-secret");

        Assert.Equal("existing-ns", result.Namespace);
        Assert.Equal("existing-secret", result.SecretName);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_FivePart_ReturnsFailure()
    {
        // Paths with 5+ segments are treated as an error per CRIT-4/MED-4 (input validation hardening)
        var result = _resolver.Resolve("a/b/c/d/e", "CertStores.K8SSecret.Inventory", "", "");

        Assert.False(result.Success);
        Assert.NotNull(result.Warning); // Should explain why path is invalid
    }

    [Fact]
    public void Resolve_CaseInsensitiveCapabilityMatch()
    {
        // Test with lowercase
        var result1 = _resolver.Resolve("my-ns", "certstores.k8sns.inventory", "", "");
        Assert.Equal("my-ns", result1.Namespace);

        // Test with mixed case
        var result2 = _resolver.Resolve("my-cluster", "CertStores.K8SCLUSTER.Inventory", "ns", "secret");
        Assert.Equal("", result2.Namespace);
        Assert.Equal("", result2.SecretName);
    }

    [Fact]
    public void Resolve_JksStore_SetsNamespaceAndSecret()
    {
        var result = _resolver.Resolve("my-ns/my-jks", "CertStores.K8SJKS.Inventory", "", "");

        Assert.Equal("my-ns", result.Namespace);
        Assert.Equal("my-jks", result.SecretName);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_Pkcs12Store_SetsNamespaceAndSecret()
    {
        var result = _resolver.Resolve("my-ns/my-pkcs12", "CertStores.K8SPKCS12.Inventory", "", "");

        Assert.Equal("my-ns", result.Namespace);
        Assert.Equal("my-pkcs12", result.SecretName);
        Assert.True(result.Success);
    }

    [Fact]
    public void Resolve_TlsStore_SetsNamespaceAndSecret()
    {
        var result = _resolver.Resolve("my-ns/my-tls", "CertStores.K8STLSSecr.Inventory", "", "");

        Assert.Equal("my-ns", result.Namespace);
        Assert.Equal("my-tls", result.SecretName);
        Assert.True(result.Success);
    }

    #endregion
}
