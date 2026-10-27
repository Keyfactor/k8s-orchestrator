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
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Handlers;

/// <summary>
/// The Opaque allowed-key filter added for discovery (GitHub issue #101) must NOT affect K8SCluster / K8SNS
/// inventory, which enumerates every Opaque secret in the cluster / namespace.
/// </summary>
public class ClusterNamespaceInventoryVsDiscoveryTests
{
    private const string Ns = "app-ns";

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
        mock.Setup(c => c.IncludeCertChain).Returns(false);
        mock.Setup(c => c.CertificateDataFieldName).Returns(string.Empty);
        return mock.Object;
    }

    private static MockedKubeClient ClientWithSecrets()
    {
        var pem = CertificateTestHelper.ConvertCertificateToPem(
            CachedCertificateProvider.GetOrCreate(CertificateTestHelper.KeyType.Rsa2048, "inventory-vs-discovery")
                .Certificate);

        return MockedKubeClientFactory.Create(new[]
        {
            // cert.pem is not in the old hard-coded inventory list (tls.crt, certificate, cert, crt)
            MockedKubeClientFactory.Secret(Ns, "pem-only", "Opaque",
                new Dictionary<string, byte[]> { ["cert.pem"] = Encoding.UTF8.GetBytes(pem) }),
            // no cert-ish key at all
            MockedKubeClientFactory.Secret(Ns, "unrelated", "Opaque",
                new Dictionary<string, byte[]> { ["config.yaml"] = new byte[] { 1, 2, 3 } })
        });
    }

    [Fact]
    public void Cluster_Inventory_IncludesOpaqueSecretWithOnlyCertPem()
    {
        var kube = ClientWithSecrets();
        var log = new CapturingLogger();
        var handler = new ClusterSecretHandler(kube.Client, log, Context(Ns));

        var entries = handler.GetInventoryEntries(1);

        Assert.True(entries.Any(e => e.Alias == $"{Ns}/secrets/opaque/pem-only" && e.Certificates.Count == 1), log.Dump());
        // Every Opaque secret is enumerated by inventory, as before the discovery filter was introduced.
        Assert.True(entries.Any(e => e.Alias == $"{Ns}/secrets/opaque/unrelated"), log.Dump());
    }

    [Fact]
    public void Namespace_Inventory_IncludesOpaqueSecretWithOnlyCertPem()
    {
        var kube = ClientWithSecrets();
        var log = new CapturingLogger();
        var handler = new NamespaceSecretHandler(kube.Client, log, Context(Ns));

        var entries = handler.GetInventoryEntries(1);

        Assert.True(entries.Any(e => e.Alias == "opaque/pem-only" && e.Certificates.Count == 1), log.Dump());
        Assert.True(entries.Any(e => e.Alias == "opaque/unrelated"), log.Dump());
    }

    [Fact]
    public void Cluster_Discovery_StillFiltersByAllowedKey()
    {
        var kube = ClientWithSecrets();
        var handler = new ClusterSecretHandler(kube.Client, new Mock<ILogger>().Object, Context(Ns));

        // Default keys: pem-only has cert.pem (allowed), unrelated has no allowed key.
        var defaults = handler.DiscoverStores(null, "all");
        Assert.Single(defaults);
        Assert.EndsWith($"/{Ns}/secrets/pem-only", defaults[0]);

        // Job-supplied keys replace the defaults entirely: cert.pem is not matched by "jks".
        Assert.Empty(handler.DiscoverStores(new[] { "jks" }, "all"));
    }

    private sealed class CapturingLogger : ILogger
    {
        private readonly List<string> _lines = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            _lines.Add($"{logLevel}: {formatter(state, exception)} {exception}");

        public string Dump() => string.Join("\n", _lines.Where(l => !l.StartsWith("Trace") && !l.StartsWith("Debug")));
    }
}
