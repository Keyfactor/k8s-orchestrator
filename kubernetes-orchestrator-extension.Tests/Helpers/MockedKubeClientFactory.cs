// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using k8s;
using k8s.Autorest;
using k8s.Models;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Moq;
using Newtonsoft.Json;

namespace Keyfactor.Orchestrators.K8S.Tests.Helpers;

/// <summary>
/// Builds a <see cref="KubeCertificateManagerClient"/> whose Kubernetes API is an in-memory fake
/// (namespace list, secret list and secret read), so handler / discovery logic can be unit tested
/// without a cluster. The Moq mock of <see cref="ICoreV1Operations"/> is exposed so tests can
/// <c>Verify</c> which API calls were (not) made.
/// </summary>
public sealed class MockedKubeClient
{
    public KubeCertificateManagerClient Client { get; }
    public Mock<ICoreV1Operations> Core { get; }

    internal MockedKubeClient(KubeCertificateManagerClient client, Mock<ICoreV1Operations> core)
    {
        Client = client;
        Core = core;
    }

    /// <summary>Number of times a single secret was read by name (GET /secrets/{name}).</summary>
    public int ReadSecretCallCount => Core.Invocations.Count(i =>
        i.Method.Name == nameof(ICoreV1Operations.ReadNamespacedSecretWithHttpMessagesAsync));

    /// <summary>Number of times secrets were listed (GET /namespaces/{ns}/secrets).</summary>
    public int ListSecretsCallCount => Core.Invocations.Count(i =>
        i.Method.Name == nameof(ICoreV1Operations.ListNamespacedSecretWithHttpMessagesAsync));
}

public static class MockedKubeClientFactory
{
    public static string BuildKubeconfig() => JsonConvert.SerializeObject(new Dictionary<string, object>
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
                    { ["cluster"] = "test-cluster", ["user"] = "test-user", ["namespace"] = "default" }
            }
        }
    });

    /// <summary>Builds a secret in <paramref name="ns"/> whose data fields are the given name/value pairs.</summary>
    public static V1Secret Secret(string ns, string name, string type, IDictionary<string, byte[]> data) => new()
    {
        Metadata = new V1ObjectMeta { Name = name, NamespaceProperty = ns },
        Type = type,
        Data = data
    };

    /// <summary>
    /// Creates the client. Namespaces listed by the fake cluster are <paramref name="namespaces"/> plus every
    /// namespace that a secret lives in. Secrets are listed per namespace (items include <c>Data</c>, as the real API
    /// does) and can be read individually by name.
    /// </summary>
    /// <param name="allowSecretReads">
    /// When false, any single-secret read (GET /secrets/{name}) throws, so a test fails if the code under test
    /// makes one (e.g. discovery must rely on the list response only).
    /// </param>
    public static MockedKubeClient Create(
        IEnumerable<V1Secret> secrets, IEnumerable<string> namespaces = null, bool allowSecretReads = true)
        => Attach(new KubeCertificateManagerClient(BuildKubeconfig()), secrets, namespaces, allowSecretReads);

    /// <summary>
    /// Same as <see cref="Create"/> but rewires an EXISTING client instance in place (its Kubernetes API and secret
    /// operations are replaced by the fake). Use this when the client is constructed by the code under test (e.g. a job's
    /// <c>ProcessJob</c>) and a handler already holds a reference to it.
    /// </summary>
    public static MockedKubeClient Attach(
        KubeCertificateManagerClient client, IEnumerable<V1Secret> secrets, IEnumerable<string> namespaces = null,
        bool allowSecretReads = true)
    {
        var all = secrets.ToList();
        var nsNames = (namespaces ?? Enumerable.Empty<string>())
            .Concat(all.Select(s => s.Metadata.NamespaceProperty))
            .Distinct()
            .ToList();

        var core = new Mock<ICoreV1Operations>();

        core.Setup(c => c.ListNamespaceWithHttpMessagesAsync(
                It.IsAny<bool?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int?>(),
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool?>(), It.IsAny<int?>(), It.IsAny<bool?>(),
                It.IsAny<bool?>(), It.IsAny<IReadOnlyDictionary<string, IReadOnlyList<string>>>(),
                It.IsAny<CancellationToken>()))
            .Returns(() => Task.FromResult(new HttpOperationResponse<V1NamespaceList>
            {
                Body = new V1NamespaceList
                {
                    Items = nsNames.Select(n => new V1Namespace { Metadata = new V1ObjectMeta { Name = n } }).ToList()
                }
            }));

        core.Setup(c => c.ListNamespacedSecretWithHttpMessagesAsync(
                It.IsAny<string>(), It.IsAny<bool?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<int?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool?>(), It.IsAny<int?>(),
                It.IsAny<bool?>(), It.IsAny<bool?>(), It.IsAny<IReadOnlyDictionary<string, IReadOnlyList<string>>>(),
                It.IsAny<CancellationToken>()))
            .Returns((string ns, bool? _, string _, string _, string _, int? _, string _, string _, bool? _,
                int? _, bool? _, bool? _, IReadOnlyDictionary<string, IReadOnlyList<string>> _, CancellationToken _) =>
                Task.FromResult(new HttpOperationResponse<V1SecretList>
                {
                    Body = new V1SecretList
                    {
                        Items = all.Where(s => s.Metadata.NamespaceProperty == ns).ToList()
                    }
                }));

        core.Setup(c => c.ReadNamespacedSecretWithHttpMessagesAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool?>(),
                It.IsAny<IReadOnlyDictionary<string, IReadOnlyList<string>>>(), It.IsAny<CancellationToken>()))
            .Returns((string name, string ns, bool? _, IReadOnlyDictionary<string, IReadOnlyList<string>> _,
                CancellationToken _) =>
            {
                if (!allowSecretReads)
                    throw new System.InvalidOperationException(
                        $"Unexpected ReadNamespacedSecret({name}, {ns}): this test forbids per-secret reads.");

                var found = all.FirstOrDefault(s => s.Metadata.Name == name && s.Metadata.NamespaceProperty == ns);
                if (found == null)
                    throw new HttpOperationException("not found")
                    {
                        Response = new HttpResponseMessageWrapper(new HttpResponseMessage(HttpStatusCode.NotFound), "")
                    };
                return Task.FromResult(new HttpOperationResponse<V1Secret> { Body = found });
            });

        var k8s = new Mock<IKubernetes>();
        k8s.Setup(c => c.CoreV1).Returns(core.Object);
        k8s.Setup(c => c.BaseUri).Returns(new System.Uri("https://127.0.0.1:6443"));

        typeof(KubeCertificateManagerClient)
            .GetProperty("Client", BindingFlags.NonPublic | BindingFlags.Instance)!
            .SetValue(client, k8s.Object);
        typeof(KubeCertificateManagerClient)
            .GetField("_secretOperations", BindingFlags.NonPublic | BindingFlags.Instance)!
            .SetValue(client, new SecretOperations(k8s.Object, null));

        return new MockedKubeClient(client, core);
    }
}
