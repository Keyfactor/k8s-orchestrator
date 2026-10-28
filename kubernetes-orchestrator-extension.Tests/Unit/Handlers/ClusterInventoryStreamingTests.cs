// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
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
/// K8SCluster inventory must not keep the whole cluster's raw secret data (private keys) resident for the whole job:
/// each namespace's secrets are listed, converted to their inventory entries and released before the next namespace
/// is listed. The API-call budget (one namespace list, one secret list per namespace, no per-secret GET) and the
/// output order stay exactly as before (see <see cref="ClusterNamespaceInventoryApiCallTests"/>).
/// </summary>
public class ClusterInventoryStreamingTests
{
    private static readonly string[] Namespaces = { "ns-a", "ns-b", "ns-c" };

    /// <summary>
    /// A secret data dictionary that records, on a shared timeline, when the inventory handlers (as opposed to the
    /// client's discovery predicates) read the secret's data - i.e. when the secret is converted into its entry.
    /// </summary>
    private sealed class ConversionTrackingData : IDictionary<string, byte[]>
    {
        private readonly Dictionary<string, byte[]> _inner;
        private readonly string _owner;
        private readonly List<string> _timeline;

        public ConversionTrackingData(string owner, Dictionary<string, byte[]> inner, List<string> timeline)
        {
            _owner = owner;
            _inner = inner;
            _timeline = timeline;
        }

        private void Touch()
        {
            // Only reads made from inside an inventory secret handler count as "the secret is being converted".
            var byHandler = new StackTrace(false).GetFrames().Any(f =>
                f.GetMethod()?.DeclaringType?.Name is "TlsSecretHandler" or "OpaqueSecretHandler");
            if (byHandler)
                lock (_timeline) _timeline.Add($"convert:{_owner}");
        }

        public byte[] this[string key]
        {
            get { Touch(); return _inner[key]; }
            set => _inner[key] = value;
        }

        public ICollection<string> Keys { get { Touch(); return _inner.Keys; } }
        public ICollection<byte[]> Values { get { Touch(); return _inner.Values; } }
        public int Count { get { Touch(); return _inner.Count; } }
        public bool IsReadOnly => false;
        public void Add(string key, byte[] value) => _inner.Add(key, value);
        public void Add(KeyValuePair<string, byte[]> item) => ((IDictionary<string, byte[]>)_inner).Add(item);
        public void Clear() => _inner.Clear();
        public bool Contains(KeyValuePair<string, byte[]> item) { Touch(); return _inner.Contains(item); }
        public bool ContainsKey(string key) { Touch(); return _inner.ContainsKey(key); }
        public void CopyTo(KeyValuePair<string, byte[]>[] array, int arrayIndex)
        {
            Touch();
            ((IDictionary<string, byte[]>)_inner).CopyTo(array, arrayIndex);
        }
        public bool Remove(string key) => _inner.Remove(key);
        public bool Remove(KeyValuePair<string, byte[]> item) => ((IDictionary<string, byte[]>)_inner).Remove(item);
        public bool TryGetValue(string key, out byte[] value) { Touch(); return _inner.TryGetValue(key, out value); }
        public IEnumerator<KeyValuePair<string, byte[]>> GetEnumerator() { Touch(); return _inner.GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private static ISecretOperationContext Context()
    {
        var mock = new Mock<ISecretOperationContext>();
        mock.Setup(c => c.KubeNamespace).Returns("ns-a");
        mock.Setup(c => c.KubeSecretName).Returns(string.Empty);
        mock.Setup(c => c.StorePath).Returns("ns-a");
        mock.Setup(c => c.StorePassword).Returns(string.Empty);
        mock.Setup(c => c.PasswordSecretPath).Returns(string.Empty);
        mock.Setup(c => c.PasswordFieldName).Returns(string.Empty);
        mock.Setup(c => c.SeparateChain).Returns(false);
        mock.Setup(c => c.IncludeCertChain).Returns(true);
        mock.Setup(c => c.CertificateDataFieldName).Returns(string.Empty);
        return mock.Object;
    }

    /// <summary>A TLS secret (with key) and an Opaque secret (with key) in every namespace; data access is timed.</summary>
    private static List<V1Secret> Secrets(List<string> timeline)
    {
        var chain = CachedCertificateProvider.GetOrCreateChain(KeyType.Rsa2048, "stream-chain");
        var cert = Encoding.UTF8.GetBytes(CertificateTestHelper.ConvertCertificateToPem(chain[0].Certificate));
        var key = Encoding.UTF8.GetBytes(CertificateTestHelper.ConvertPrivateKeyToPem(chain[0].KeyPair.Private));

        V1Secret Make(string ns, string name, string type, Dictionary<string, byte[]> data)
        {
            var secret = MockedKubeClientFactory.Secret(ns, name, type, null);
            secret.Data = new ConversionTrackingData($"{ns}/{name}", data, timeline);
            return secret;
        }

        var secrets = new List<V1Secret>();
        foreach (var ns in Namespaces)
        {
            secrets.Add(Make(ns, $"tls-{ns}", "kubernetes.io/tls",
                new Dictionary<string, byte[]> { ["tls.crt"] = cert, ["tls.key"] = key }));
            secrets.Add(Make(ns, $"opaque-{ns}", "Opaque",
                new Dictionary<string, byte[]> { ["tls.crt"] = cert, ["tls.key"] = key }));
        }

        return secrets;
    }

    [Fact]
    public void ClusterInventory_ConvertsEachNamespacesSecretsBeforeListingTheNext()
    {
        var timeline = new List<string>();
        var kube = MockedKubeClientFactory.Create(Secrets(timeline), allowSecretReads: false,
            onSecretsListed: ns => { lock (timeline) timeline.Add($"list:{ns}"); });

        var entries = new ClusterSecretHandler(kube.Client, new Mock<ILogger>().Object, Context())
            .GetInventoryEntries(1);

        Assert.Equal(6, entries.Count);
        Assert.Equal(Namespaces.Select(n => $"list:{n}"), timeline.Where(e => e.StartsWith("list:")));

        // Every namespace's secrets must have been converted (otherwise the check below would be vacuous) ...
        foreach (var ns in Namespaces)
            Assert.Contains(timeline, e => e.StartsWith($"convert:{ns}/"));

        // ... and all of namespace N's secrets are converted before namespace N+1 is listed, so the previous
        // namespace's secret data is no longer needed (and no longer referenced) by then.
        for (var i = 1; i < Namespaces.Length; i++)
        {
            var listNext = timeline.IndexOf($"list:{Namespaces[i]}");
            var lastConvertOfPrevious = timeline.FindLastIndex(e => e.StartsWith($"convert:{Namespaces[i - 1]}/"));
            Assert.True(lastConvertOfPrevious < listNext,
                $"Secrets of {Namespaces[i - 1]} were still being converted after {Namespaces[i]} was listed. " +
                $"Timeline: {string.Join(" | ", timeline)}");
        }
    }

    [Fact]
    public void ClusterInventory_KeepsLegacyOrder_AllTlsThenAllOpaque_AcrossNamespaces()
    {
        var kube = MockedKubeClientFactory.Create(Secrets(new List<string>()), allowSecretReads: false);

        var aliases = new ClusterSecretHandler(kube.Client, new Mock<ILogger>().Object, Context())
            .GetInventoryEntries(1).Select(e => e.Alias).ToArray();

        Assert.Equal(new[]
        {
            "ns-a/secrets/tls/tls-ns-a", "ns-b/secrets/tls/tls-ns-b", "ns-c/secrets/tls/tls-ns-c",
            "ns-a/secrets/opaque/opaque-ns-a", "ns-b/secrets/opaque/opaque-ns-b", "ns-c/secrets/opaque/opaque-ns-c"
        }, aliases);
    }

    [Fact]
    public void EnumerateClusterInventorySecrets_ListsOneNamespaceAtATime_OnlyAsTheCallerAdvances()
    {
        var kube = MockedKubeClientFactory.Create(Secrets(new List<string>()), allowSecretReads: false);

        var sequence = kube.Client.EnumerateClusterInventorySecrets();

        // Nothing is listed until the caller asks for a secret (the namespace list is the only up-front call).
        Assert.Empty(kube.ListedSecretNamespaces);

        using var e = sequence.GetEnumerator();
        Assert.True(e.MoveNext());
        Assert.Equal("ns-a", e.Current.Namespace);
        Assert.Equal(new[] { "ns-a" }, kube.ListedSecretNamespaces.ToArray());

        // ns-a holds a TLS and an Opaque secret: the second one still comes from the same list ...
        Assert.True(e.MoveNext());
        Assert.Equal("ns-a", e.Current.Namespace);
        Assert.Equal(new[] { "ns-a" }, kube.ListedSecretNamespaces.ToArray());

        // ... and only moving past it lists the next namespace.
        Assert.True(e.MoveNext());
        Assert.Equal("ns-b", e.Current.Namespace);
        Assert.Equal(new[] { "ns-a", "ns-b" }, kube.ListedSecretNamespaces.ToArray());
    }

    [Fact]
    public void EnumerateClusterInventorySecrets_StopsEarly_DoesNotListNamespacesNotReached()
    {
        var kube = MockedKubeClientFactory.Create(Secrets(new List<string>()), allowSecretReads: false);

        var first = kube.Client.EnumerateClusterInventorySecrets().First();

        Assert.Equal("ns-a", first.Namespace);
        Assert.Equal(new[] { "ns-a" }, kube.ListedSecretNamespaces.ToArray());
        Assert.Equal(0, kube.ReadSecretCallCount);
    }
}
