// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Linq;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Moq;
using Xunit;
using ClusterDiscovery = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SCluster.Discovery;
using JksDiscovery = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SJKS.Discovery;
using NsDiscovery = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SNS.Discovery;
using Pkcs12Discovery = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SPKCS12.Discovery;
using SecretDiscovery = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SSecret.Discovery;
using TlsDiscovery = Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8STLSSecr.Discovery;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Jobs;

/// <summary>
/// 'Directories to ignore' must be applied BEFORE any API call lists the secrets of an ignored namespace.
/// A service account that lacks <c>list secrets</c> in an ignored namespace (typically kube-system) with
/// <c>dirs=all, ignoreddirs=kube-system</c> must not fail the whole discovery job.
/// Every Discovery job class is exercised through <c>DiscoveryBase.ProcessJob</c> against an in-memory cluster in which
/// listing secrets in the ignored namespace answers HTTP 403.
/// </summary>
public class DiscoveryIgnoredNamespaceTests
{
    private const string Ignored = "kube-system";

    /// <summary>Wires the in-memory cluster into the client a real Discovery job built for itself.</summary>
    private sealed class Rig
    {
        private readonly IEnumerable<V1Secret> _secrets;
        private readonly IEnumerable<string> _namespaces;
        private readonly IEnumerable<string> _forbidden;
        public MockedKubeClient Kube { get; private set; }

        public Rig(IEnumerable<V1Secret> secrets, IEnumerable<string> namespaces, IEnumerable<string> forbidden)
        {
            _secrets = secrets;
            _namespaces = namespaces;
            _forbidden = forbidden;
        }

        public void Attach(Keyfactor.Extensions.Orchestrator.K8S.Clients.KubeCertificateManagerClient client)
            => Kube = MockedKubeClientFactory.Attach(client, _secrets, _namespaces, allowSecretReads: false, _forbidden);
    }

    // Each real Discovery class, with the in-memory cluster attached once ProcessJob has created the client
    // (GetNamespacesToSearch runs after the handler is created and before discovery).
    private sealed class Tls : TlsDiscovery
    {
        private readonly Rig _rig;
        public Tls(Rig rig) : base(new Mock<IPAMSecretResolver>().Object) => _rig = rig;

        protected override string GetNamespacesToSearch(DiscoveryJobConfiguration config)
        {
            _rig.Attach(KubeClient);
            return base.GetNamespacesToSearch(config);
        }
    }

    private sealed class Opaque : SecretDiscovery
    {
        private readonly Rig _rig;
        public Opaque(Rig rig) : base(new Mock<IPAMSecretResolver>().Object) => _rig = rig;

        protected override string GetNamespacesToSearch(DiscoveryJobConfiguration config)
        {
            _rig.Attach(KubeClient);
            return base.GetNamespacesToSearch(config);
        }
    }

    private sealed class Jks : JksDiscovery
    {
        private readonly Rig _rig;
        public Jks(Rig rig) : base(new Mock<IPAMSecretResolver>().Object) => _rig = rig;

        protected override string GetNamespacesToSearch(DiscoveryJobConfiguration config)
        {
            _rig.Attach(KubeClient);
            return base.GetNamespacesToSearch(config);
        }
    }

    private sealed class Pkcs12 : Pkcs12Discovery
    {
        private readonly Rig _rig;
        public Pkcs12(Rig rig) : base(new Mock<IPAMSecretResolver>().Object) => _rig = rig;

        protected override string GetNamespacesToSearch(DiscoveryJobConfiguration config)
        {
            _rig.Attach(KubeClient);
            return base.GetNamespacesToSearch(config);
        }
    }

    private sealed class Namespace : NsDiscovery
    {
        private readonly Rig _rig;
        public Namespace(Rig rig) : base(new Mock<IPAMSecretResolver>().Object) => _rig = rig;

        protected override string GetNamespacesToSearch(DiscoveryJobConfiguration config)
        {
            _rig.Attach(KubeClient);
            return base.GetNamespacesToSearch(config);
        }
    }

    private sealed class Cluster : ClusterDiscovery
    {
        private readonly Rig _rig;
        public Cluster(Rig rig) : base(new Mock<IPAMSecretResolver>().Object) => _rig = rig;

        protected override string GetNamespacesToSearch(DiscoveryJobConfiguration config)
        {
            _rig.Attach(KubeClient);
            return base.GetNamespacesToSearch(config);
        }
    }

    private static V1Secret Secret(string ns, string name, string type, string dataKey) =>
        MockedKubeClientFactory.Secret(ns, name, type,
            new Dictionary<string, byte[]> { [dataKey] = new byte[] { 1, 2, 3 } });

    /// <summary>The same two secrets (one in a normal namespace, one in kube-system) for every store type.</summary>
    private static List<V1Secret> SecretsFor(string storeType)
    {
        var (type, key) = storeType switch
        {
            "K8STLSSecr" => ("kubernetes.io/tls", "tls.crt"),
            "K8SSecret" => ("Opaque", "tls.crt"),
            "K8SJKS" => ("Opaque", "keystore.jks"),
            "K8SPKCS12" => ("Opaque", "keystore.pfx"),
            "K8SCluster" => ("kubernetes.io/tls", "tls.crt"),
            _ => ("Opaque", "tls.crt") // K8SNS reports namespaces, not secrets
        };
        return new List<V1Secret> { Secret("team-a", "keep-me", type, key), Secret(Ignored, "skip-me", type, key) };
    }

    private static DiscoveryBase JobFor(string storeType, Rig rig) => storeType switch
    {
        "K8STLSSecr" => new Tls(rig),
        "K8SSecret" => new Opaque(rig),
        "K8SJKS" => new Jks(rig),
        "K8SPKCS12" => new Pkcs12(rig),
        "K8SNS" => new Namespace(rig),
        "K8SCluster" => new Cluster(rig),
        _ => throw new System.ArgumentOutOfRangeException(nameof(storeType))
    };

    private static DiscoveryJobConfiguration Config(string storeType, string dirs, string ignoredDirs) => new()
    {
        Capability = storeType,
        ClientMachine = "customer-cluster",
        ServerUsername = string.Empty,
        ServerPassword = MockedKubeClientFactory.BuildKubeconfig(),
        UseSSL = true,
        JobHistoryId = 7,
        JobProperties = new Dictionary<string, object>
        {
            { "dirs", dirs },
            { "extensions", "" },
            { "ignoreddirs", ignoredDirs },
            { "patterns", "" }
        }
    };

    public static IEnumerable<object[]> StoreTypes() => new[]
    {
        new object[] { "K8STLSSecr" }, new object[] { "K8SSecret" }, new object[] { "K8SJKS" },
        new object[] { "K8SPKCS12" }, new object[] { "K8SNS" }, new object[] { "K8SCluster" }
    };

    [Theory]
    [MemberData(nameof(StoreTypes))]
    public void Discovery_IgnoredNamespaceWithoutListPermission_DoesNotFailJob_AndIsNeverListed(string storeType)
    {
        var rig = new Rig(SecretsFor(storeType), new[] { "default", "team-a", "team-b", Ignored }, new[] { Ignored });
        var discovered = new List<string>();

        // Case/whitespace variations of the ignored name must still be recognised.
        var result = JobFor(storeType, rig).ProcessJob(Config(storeType, "all", $"  {Ignored.ToUpperInvariant()} "), items =>
        {
            discovered.AddRange(items);
            return true;
        });

        Assert.True(result.Result == OrchestratorJobStatusJobResult.Success,
            $"{storeType}: discovery failed although the only unreadable namespace is ignored: {result.FailureMessage}");
        Assert.DoesNotContain(Ignored, rig.Kube.ListedSecretNamespaces);
        Assert.DoesNotContain(discovered, d => d.Contains($"/{Ignored}/") || d.EndsWith($"/{Ignored}"));
        Assert.Contains(discovered, d => d.Contains("/team-a/secrets/keep-me") || d.EndsWith("/namespace/team-a"));
    }

    [Theory]
    [MemberData(nameof(StoreTypes))]
    public void Discovery_UnreadableNamespaceThatIsNotIgnored_StillFailsTheJob(string storeType)
    {
        // Control: the 403 is real. Without the ignore entry the job must still surface the failure
        // (K8SNS never lists secrets, so it cannot hit it).
        if (storeType == "K8SNS") return;

        var rig = new Rig(SecretsFor(storeType), new[] { "default", "team-a", Ignored }, new[] { Ignored });

        var result = JobFor(storeType, rig).ProcessJob(Config(storeType, "all", "team-b"), _ => true);

        Assert.Equal(OrchestratorJobStatusJobResult.Failure, result.Result);
        Assert.Contains(Ignored, rig.Kube.ListedSecretNamespaces);
    }

    [Fact]
    public void Discovery_ExplicitDirsWithIgnoredEntry_DoesNotListTheIgnoredNamespace()
    {
        var rig = new Rig(SecretsFor("K8STLSSecr"), new[] { "default", "team-a", Ignored }, new[] { Ignored });
        var discovered = new List<string>();

        var result = JobFor("K8STLSSecr", rig).ProcessJob(Config("K8STLSSecr", $"team-a,{Ignored}", Ignored), items =>
        {
            discovered.AddRange(items);
            return true;
        });

        Assert.Equal(OrchestratorJobStatusJobResult.Success, result.Result);
        Assert.Equal(new[] { "team-a" }, rig.Kube.ListedSecretNamespaces);
        Assert.Single(discovered);
    }

    [Fact]
    public void Discovery_EveryMatchedNamespaceIgnored_ListsNothingAndSucceeds()
    {
        var rig = new Rig(SecretsFor("K8STLSSecr"), new[] { "default", Ignored }, new[] { Ignored });
        var discovered = new List<string>();

        var result = JobFor("K8STLSSecr", rig).ProcessJob(Config("K8STLSSecr", Ignored, Ignored), items =>
        {
            discovered.AddRange(items);
            return true;
        });

        Assert.Equal(OrchestratorJobStatusJobResult.Success, result.Result);
        Assert.Empty(rig.Kube.ListedSecretNamespaces);
        Assert.Empty(discovered);
    }

    [Fact]
    public void Discovery_IgnoredNamespaces_OnlyListNonIgnoredNamespaces_InOrder()
    {
        var secrets = new List<V1Secret>
        {
            Secret("team-a", "a", "kubernetes.io/tls", "tls.crt"),
            Secret("team-b", "b", "kubernetes.io/tls", "tls.crt"),
            Secret("team-c", "c", "kubernetes.io/tls", "tls.crt")
        };
        var rig = new Rig(secrets, new[] { "default", "team-a", "team-b", "team-c" }, new string[0]);
        var discovered = new List<string>();

        var result = JobFor("K8STLSSecr", rig).ProcessJob(Config("K8STLSSecr", "all", "default;Team-B"), items =>
        {
            discovered.AddRange(items);
            return true;
        });

        Assert.Equal(OrchestratorJobStatusJobResult.Success, result.Result);
        Assert.Equal(new[] { "team-a", "team-c" }, rig.Kube.ListedSecretNamespaces.ToArray());
        Assert.Equal(2, discovered.Count);
    }
}
