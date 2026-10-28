// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using TlsDiscovery = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8STLSSecr.Discovery;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Jobs;

/// <summary>
/// End-to-end (through <c>DiscoveryBase.ProcessJob</c>, no cluster) regression test for the customer-reported bug:
///
/// SYMPTOM: a K8STLSSecr Discovery job with "Directories to search" = <c>all</c> completed successfully but
/// found 0 stores, even though the cluster contained TLS secrets in many namespaces.
///
/// ROOT CAUSE: <c>DiscoveryBase</c> re-parsed <c>config.JobProperties.ToString()</c> as JSON. The framework supplies
/// <c>JobProperties</c> as a plain <c>Dictionary&lt;string, object&gt;</c>, so <c>ToString()</c> is the CLR type name,
/// the JSON parse threw, the error was swallowed (logged as "Failed to parse discovery directories") and an empty
/// namespace string was passed to the handler, which then filtered out every namespace. It also looked up the key
/// <c>Directories</c> while Command actually sends <c>dirs</c>.
/// </summary>
public class DiscoveryRegressionTests
{
    /// <summary>
    /// Real TLS discovery job whose Kubernetes API is replaced by an in-memory fake once the job has built its client.
    /// The hook is <c>GetNamespacesToSearch</c> (called by <c>ProcessJob</c> after the handler is created, before
    /// discovery runs); it rewires the very client instance the handler already holds, then defers to the real logic.
    /// </summary>
    private sealed class FakeClusterTlsDiscovery : TlsDiscovery
    {
        private readonly IEnumerable<V1Secret> _secrets;
        private readonly IEnumerable<string> _namespaces;
        public readonly CapturingLogger CapturedLog = new();
        public string NamespacesPassedToHandler { get; private set; }

        public FakeClusterTlsDiscovery(IEnumerable<V1Secret> secrets, IEnumerable<string> namespaces)
            : base(new Mock<IPAMSecretResolver>().Object)
        {
            _secrets = secrets;
            _namespaces = namespaces;
            Logger = CapturedLog;
        }

        protected override string GetNamespacesToSearch(DiscoveryJobConfiguration config)
        {
            MockedKubeClientFactory.Attach(KubeClient, _secrets, _namespaces, allowSecretReads: false);
            NamespacesPassedToHandler = base.GetNamespacesToSearch(config);
            return NamespacesPassedToHandler;
        }
    }

    /// <summary>Minimal ILogger that records every message (including formatted warnings).</summary>
    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (Entries) Entries.Add((logLevel, formatter(state, exception)));
        }
    }

    private static V1Secret TlsSecret(string ns, string name) => MockedKubeClientFactory.Secret(
        ns, name, "kubernetes.io/tls",
        new Dictionary<string, byte[]> { ["tls.crt"] = new byte[] { 1, 2, 3 }, ["tls.key"] = new byte[] { 4, 5, 6 } });

    private static DiscoveryJobConfiguration CustomerConfig(string dirs = "all") => new()
    {
        Capability = "K8STLSSecr",
        ClientMachine = "customer-cluster",
        ServerUsername = string.Empty,
        ServerPassword = MockedKubeClientFactory.BuildKubeconfig(),
        UseSSL = true,
        JobHistoryId = 42,
        // EXACTLY what Keyfactor Command sends: a plain Dictionary with lower-case keys and blank optional values.
        JobProperties = new Dictionary<string, object>
        {
            { "dirs", dirs },
            { "extensions", "" },
            { "ignoreddirs", "" },
            { "patterns", "" }
        }
    };

    [Fact]
    public void Regression_Discovery_DirectoriesAll_PlainDictionary_ReturnsSecretsFromEveryNamespace()
    {
        // Arrange - several namespaces (none of them needs to be "default"), TLS secrets in most of them
        var secrets = new List<V1Secret>
        {
            TlsSecret("team-a", "web-tls"),
            TlsSecret("team-a", "api-tls"),
            TlsSecret("team-b", "ingress-tls"),
            TlsSecret("kube-system", "webhook-tls"),
            // Opaque secret with a cert-ish key: must NOT be reported by a K8STLSSecr (kubernetes.io/tls) discovery
            MockedKubeClientFactory.Secret("team-b", "opaque-cert", "Opaque",
                new Dictionary<string, byte[]> { ["tls.crt"] = new byte[] { 1 } })
        };
        var discovery = new FakeClusterTlsDiscovery(secrets, new[] { "default", "empty-ns", "team-a", "team-b", "kube-system" });
        var discovered = new List<string>();

        // Act
        var result = discovery.ProcessJob(CustomerConfig(), items =>
        {
            discovered.AddRange(items);
            return true;
        });

        // Assert - the job must hand 'all' to the handler (the buggy code handed over an empty string) ...
        Assert.Equal(OrchestratorJobStatusJobResult.Success, result.Result);
        Assert.Equal("all", discovery.NamespacesPassedToHandler);

        // ... and every TLS secret in every namespace must be returned (none skipped).
        Assert.Equal(4, discovered.Count);
        Assert.Contains(discovered, d => d.EndsWith("/team-a/secrets/web-tls"));
        Assert.Contains(discovered, d => d.EndsWith("/team-a/secrets/api-tls"));
        Assert.Contains(discovered, d => d.EndsWith("/team-b/secrets/ingress-tls"));
        Assert.Contains(discovered, d => d.EndsWith("/kube-system/secrets/webhook-tls"));
        Assert.DoesNotContain(discovered, d => d.EndsWith("/opaque-cert"));

        // The bug was silent: the only trace was this warning. It must not be logged any more.
        Assert.DoesNotContain(discovery.CapturedLog.Entries,
            e => e.Message.Contains("Failed to parse discovery directories"));
        Assert.DoesNotContain(discovery.CapturedLog.Entries,
            e => e.Level >= LogLevel.Warning && e.Message.Contains("Discovery found 0 stores"));
    }

    [Theory]
    [InlineData("all")]
    [InlineData("All")]
    [InlineData(" ALL ")]
    public void Regression_Discovery_DirectoriesAll_AnyCasing_ReturnsSecretsFromEveryNamespace(string dirs)
    {
        var secrets = new[] { TlsSecret("ns-one", "one"), TlsSecret("ns-two", "two") };
        var discovery = new FakeClusterTlsDiscovery(secrets, new[] { "default", "ns-one", "ns-two" });
        var discovered = new List<string>();

        var result = discovery.ProcessJob(CustomerConfig(dirs), items =>
        {
            discovered.AddRange(items);
            return true;
        });

        Assert.Equal(OrchestratorJobStatusJobResult.Success, result.Result);
        Assert.Equal(2, discovered.Count);
        Assert.Contains(discovered, d => d.EndsWith("/ns-one/secrets/one"));
        Assert.Contains(discovered, d => d.EndsWith("/ns-two/secrets/two"));
    }

    [Fact]
    public void Discovery_BlankDirs_FallsBackToDefaultNamespaceOnly()
    {
        // Blank 'dirs' falls back to the 'default' namespace: secrets elsewhere must not be returned.
        var secrets = new[] { TlsSecret("default", "in-default"), TlsSecret("team-a", "elsewhere") };
        var discovery = new FakeClusterTlsDiscovery(secrets, new[] { "default", "team-a" });
        var discovered = new List<string>();

        var result = discovery.ProcessJob(CustomerConfig(""), items =>
        {
            discovered.AddRange(items);
            return true;
        });

        Assert.Equal(OrchestratorJobStatusJobResult.Success, result.Result);
        Assert.Equal("default", discovery.NamespacesPassedToHandler);
        Assert.Single(discovered);
        Assert.EndsWith("/default/secrets/in-default", discovered[0]);
    }
}
