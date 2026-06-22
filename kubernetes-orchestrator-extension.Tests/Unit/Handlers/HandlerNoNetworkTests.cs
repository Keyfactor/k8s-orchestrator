// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Microsoft.Extensions.Logging;
using Moq;
using Newtonsoft.Json;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Handlers;

/// <summary>
/// Unit tests for CertificateSecretHandler, ClusterSecretHandler, and NamespaceSecretHandler
/// that exercise non-network methods: properties, NotSupportedException throws, and alias parsing.
/// </summary>
public class HandlerNoNetworkTests
{
    #region Kubeconfig / handler factory helpers

    private static string BuildKubeconfig()
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
        => new KubeCertificateManagerClient(BuildKubeconfig());

    private static ILogger CreateLogger()
        => new Mock<ILogger>().Object;

    private static ISecretOperationContext MakeContext(string ns = "default", string name = "test-secret")
    {
        var mock = new Mock<ISecretOperationContext>();
        mock.Setup(c => c.KubeNamespace).Returns(ns);
        mock.Setup(c => c.KubeSecretName).Returns(name);
        mock.Setup(c => c.StorePath).Returns($"{ns}/{name}");
        mock.Setup(c => c.StorePassword).Returns(string.Empty);
        mock.Setup(c => c.PasswordSecretPath).Returns(string.Empty);
        mock.Setup(c => c.PasswordFieldName).Returns(string.Empty);
        mock.Setup(c => c.SeparateChain).Returns(false);
        mock.Setup(c => c.IncludeCertChain).Returns(false);
        mock.Setup(c => c.CertificateDataFieldName).Returns(string.Empty);
        return mock.Object;
    }

    #endregion

    #region CertificateSecretHandler — properties and unsupported operations

    [Fact]
    public void CertificateSecretHandler_AllowedKeys_IsEmpty()
    {
        var handler = new CertificateSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Empty(handler.AllowedKeys);
    }

    [Fact]
    public void CertificateSecretHandler_SecretTypeName_IsCertificate()
    {
        var handler = new CertificateSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Equal("certificate", handler.SecretTypeName);
    }

    [Fact]
    public void CertificateSecretHandler_SupportsManagement_IsFalse()
    {
        var handler = new CertificateSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.False(handler.SupportsManagement);
    }

    [Fact]
    public void CertificateSecretHandler_HasPrivateKey_ReturnsFalse()
    {
        var handler = new CertificateSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.False(handler.HasPrivateKey());
    }

    [Fact]
    public void CertificateSecretHandler_HandleAdd_ThrowsNotSupportedException()
    {
        var handler = new CertificateSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Throws<NotSupportedException>(() => handler.HandleAdd(null, "alias", false));
    }

    [Fact]
    public void CertificateSecretHandler_HandleRemove_ThrowsNotSupportedException()
    {
        var handler = new CertificateSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Throws<NotSupportedException>(() => handler.HandleRemove("alias"));
    }

    [Fact]
    public void CertificateSecretHandler_CreateEmptyStore_ThrowsNotSupportedException()
    {
        var handler = new CertificateSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Throws<NotSupportedException>(() => handler.CreateEmptyStore());
    }

    #endregion

    #region ClusterSecretHandler — properties and unsupported operations

    [Fact]
    public void ClusterSecretHandler_AllowedKeys_ContainsTlsCrt()
    {
        var handler = new ClusterSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Contains("tls.crt", handler.AllowedKeys);
    }

    [Fact]
    public void ClusterSecretHandler_SecretTypeName_IsCluster()
    {
        var handler = new ClusterSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Equal("cluster", handler.SecretTypeName);
    }

    [Fact]
    public void ClusterSecretHandler_SupportsManagement_IsTrue()
    {
        var handler = new ClusterSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.True(handler.SupportsManagement);
    }

    [Fact]
    public void ClusterSecretHandler_HasPrivateKey_ReturnsTrue()
    {
        var handler = new ClusterSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.True(handler.HasPrivateKey());
    }

    [Fact]
    public void ClusterSecretHandler_CreateEmptyStore_ThrowsNotSupportedException()
    {
        var handler = new ClusterSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Throws<NotSupportedException>(() => handler.CreateEmptyStore());
    }

    [Fact]
    public void ClusterSecretHandler_HandleAdd_ShortAlias_ThrowsArgumentException()
    {
        // ParseClusterAlias requires at least 4 parts separated by '/'
        var handler = new ClusterSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Throws<ArgumentException>(() => handler.HandleAdd(null, "ns/name", false));
    }

    [Fact]
    public void ClusterSecretHandler_HandleRemove_ShortAlias_ThrowsArgumentException()
    {
        var handler = new ClusterSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Throws<ArgumentException>(() => handler.HandleRemove("ns/name"));
    }

    [Fact]
    public void ClusterSecretHandler_HandleAdd_UnsupportedInnerType_ThrowsNotSupportedException()
    {
        // Four-part alias with an unsupported type triggers CreateInnerHandler's _ => throw
        var handler = new ClusterSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Throws<NotSupportedException>(() => handler.HandleAdd(null, "ns/secrets/jks/my-store", false));
    }

    #endregion

    #region NamespaceSecretHandler — properties and unsupported operations

    [Fact]
    public void NamespaceSecretHandler_AllowedKeys_ContainsTlsCrt()
    {
        var handler = new NamespaceSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Contains("tls.crt", handler.AllowedKeys);
    }

    [Fact]
    public void NamespaceSecretHandler_SecretTypeName_IsNamespace()
    {
        var handler = new NamespaceSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Equal("namespace", handler.SecretTypeName);
    }

    [Fact]
    public void NamespaceSecretHandler_SupportsManagement_IsTrue()
    {
        var handler = new NamespaceSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.True(handler.SupportsManagement);
    }

    [Fact]
    public void NamespaceSecretHandler_HasPrivateKey_ReturnsTrue()
    {
        var handler = new NamespaceSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.True(handler.HasPrivateKey());
    }

    [Fact]
    public void NamespaceSecretHandler_CreateEmptyStore_ThrowsNotSupportedException()
    {
        var handler = new NamespaceSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Throws<NotSupportedException>(() => handler.CreateEmptyStore());
    }

    [Fact]
    public void NamespaceSecretHandler_HandleAdd_ShortAlias_ThrowsArgumentException()
    {
        // ParseNamespaceAlias requires at least 2 parts separated by '/'
        var handler = new NamespaceSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Throws<ArgumentException>(() => handler.HandleAdd(null, "onlyone", false));
    }

    [Fact]
    public void NamespaceSecretHandler_HandleRemove_ShortAlias_ThrowsArgumentException()
    {
        var handler = new NamespaceSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Throws<ArgumentException>(() => handler.HandleRemove("onlyone"));
    }

    [Fact]
    public void NamespaceSecretHandler_HandleAdd_UnsupportedInnerType_ThrowsNotSupportedException()
    {
        // Two-part alias with an unsupported type triggers CreateInnerHandler's _ => throw
        var handler = new NamespaceSecretHandler(CreateKubeClient(), CreateLogger(), MakeContext());
        Assert.Throws<NotSupportedException>(() => handler.HandleAdd(null, "jks/my-store", false));
    }

    #endregion

    #region SanitizeClusterName — B-035 regression guard

    // When a store is configured with username/password auth (no kubeconfig), GetClusterName()
    // falls back to GetHost(), which returns the raw API server URL such as "https://10.43.0.1/".
    // Embedding that URL as the first segment of a location string (clusterName/namespace/secrets/name)
    // produces paths like "https://10.43.0.1//cert-manager/secrets/lab-ca" that break parsing in
    // ClusterSecretHandler.ProcessSecretEntry (parts[1] becomes "" instead of the namespace).
    // SanitizeClusterName must strip the URL down to just the host component.

    [Theory]
    [InlineData("https://10.43.0.1/", "10.43.0.1")]
    [InlineData("https://10.43.0.1:6443/", "10.43.0.1")]
    [InlineData("https://k8s.example.com/", "k8s.example.com")]
    [InlineData("http://127.0.0.1:8080", "127.0.0.1")]
    public void SanitizeClusterName_AbsoluteUri_ReturnsHostOnly(string input, string expected)
    {
        var result = KubeCertificateManagerClient.SanitizeClusterName(input);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("local")]
    [InlineData("my-cluster")]
    [InlineData("kf-integrations")]
    public void SanitizeClusterName_PlainName_ReturnedUnchanged(string input)
    {
        var result = KubeCertificateManagerClient.SanitizeClusterName(input);
        Assert.Equal(input, result);
    }

    [Fact]
    public void SanitizeClusterName_Null_ReturnsNull()
    {
        var result = KubeCertificateManagerClient.SanitizeClusterName(null);
        Assert.Null(result);
    }

    [Fact]
    public void SanitizeClusterName_EmptyString_ReturnsEmptyString()
    {
        var result = KubeCertificateManagerClient.SanitizeClusterName(string.Empty);
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void SanitizeClusterName_UrlAsClusterName_ProducesValidLocationPath()
    {
        // Regression test: location strings built with a raw URL as clusterName produced
        // paths that ClusterSecretHandler.ProcessSecretEntry could not parse.
        // After sanitization, parts[1] (the namespace) must equal "cert-manager", not "".
        var rawUrl = "https://10.43.0.1/";
        var namespaceName = "cert-manager";
        var secretName = "lab-root-ca-secret";

        var sanitized = KubeCertificateManagerClient.SanitizeClusterName(rawUrl);
        var location = $"{sanitized}/{namespaceName}/secrets/{secretName}";
        var parts = location.Split('/');

        Assert.True(parts.Length >= 4, "Location must have at least 4 segments for ProcessSecretEntry to parse");
        Assert.Equal("cert-manager", parts[1]);
        Assert.Equal("lab-root-ca-secret", parts[^1]);
    }

    #endregion
}
