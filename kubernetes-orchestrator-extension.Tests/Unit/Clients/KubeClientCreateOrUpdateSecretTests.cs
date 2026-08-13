// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
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
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Clients;

/// <summary>
/// Regression tests for KubeCertificateManagerClient.CreateOrUpdateCertificateStoreSecret (GitHub issue #91).
/// The previous implementation blind-created the secret, routed to the update path only on a free-text
/// "Conflict" match of the exception message, and silently returned null for any other API error —
/// which the Management job then reported to Command as Success without writing anything.
/// These tests verify the read-then-branch behavior and that non-Conflict API errors propagate.
/// </summary>
public class KubeClientCreateOrUpdateSecretTests
{
    private const string SecretName = "test-secret";
    private const string Namespace = "default";

    #region Helpers

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

    /// <summary>
    /// Builds a KubeCertificateManagerClient whose private Client property and _secretOperations field
    /// are replaced (via reflection) with ones backed by the supplied IKubernetes mock, so no network I/O occurs.
    /// </summary>
    private static KubeCertificateManagerClient CreateClientWithMock(IKubernetes mockKubernetes)
    {
        var client = new KubeCertificateManagerClient(BuildKubeconfig());

        var clientProp = typeof(KubeCertificateManagerClient)
            .GetProperty("Client", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(clientProp);
        clientProp.SetValue(client, mockKubernetes);

        var secretOpsField = typeof(KubeCertificateManagerClient)
            .GetField("_secretOperations", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(secretOpsField);
        secretOpsField.SetValue(client, new SecretOperations(mockKubernetes, null));

        return client;
    }

    private static HttpOperationException MakeHttpException(HttpStatusCode status) =>
        new($"Operation returned an invalid status code '{status}'")
        {
            Response = new HttpResponseMessageWrapper(new HttpResponseMessage(status), string.Empty)
        };

    private static Task<HttpOperationResponse<V1Secret>> Response(V1Secret secret) =>
        Task.FromResult(new HttpOperationResponse<V1Secret> { Body = secret });

    private static V1Secret ExistingTlsSecret() =>
        new()
        {
            Metadata = new V1ObjectMeta
            {
                Name = SecretName,
                NamespaceProperty = Namespace,
                ResourceVersion = "12345"
            },
            Type = "kubernetes.io/tls",
            Data = new Dictionary<string, byte[]>
            {
                ["tls.crt"] = new byte[] { 1 },
                ["tls.key"] = new byte[] { 2 }
            }
        };

    private static Mock<ICoreV1Operations> SetupCoreV1(Mock<IKubernetes> k8sMock)
    {
        var core = new Mock<ICoreV1Operations>();
        k8sMock.Setup(c => c.CoreV1).Returns(core.Object);
        return core;
    }

    private static void SetupRead(Mock<ICoreV1Operations> core, params object[] resultsOrExceptions)
    {
        var seq = core.SetupSequence(c => c.ReadNamespacedSecretWithHttpMessagesAsync(
            SecretName, Namespace, It.IsAny<bool?>(),
            It.IsAny<IReadOnlyDictionary<string, IReadOnlyList<string>>>(),
            It.IsAny<CancellationToken>()));
        foreach (var item in resultsOrExceptions)
        {
            if (item is HttpOperationException ex)
                seq = seq.ThrowsAsync(ex);
            else
                seq = seq.Returns(Response((V1Secret)item));
        }
    }

    private static void SetupCreate(Mock<ICoreV1Operations> core, HttpOperationException throws = null)
    {
        var setup = core.Setup(c => c.CreateNamespacedSecretWithHttpMessagesAsync(
            It.IsAny<V1Secret>(), Namespace, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<bool?>(), It.IsAny<IReadOnlyDictionary<string, IReadOnlyList<string>>>(),
            It.IsAny<CancellationToken>()));
        if (throws != null)
            setup.ThrowsAsync(throws);
        else
            setup.Returns((V1Secret body, string ns, string dr, string fm, string fv, bool? p,
                IReadOnlyDictionary<string, IReadOnlyList<string>> h, CancellationToken ct) => Response(body));
    }

    private static void SetupReplace(Mock<ICoreV1Operations> core)
    {
        core.Setup(c => c.ReplaceNamespacedSecretWithHttpMessagesAsync(
                It.IsAny<V1Secret>(), SecretName, Namespace, It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<string>(), It.IsAny<bool?>(),
                It.IsAny<IReadOnlyDictionary<string, IReadOnlyList<string>>>(),
                It.IsAny<CancellationToken>()))
            .Returns((V1Secret body, string n, string ns, string dr, string fm, string fv, bool? p,
                IReadOnlyDictionary<string, IReadOnlyList<string>> h, CancellationToken ct) => Response(body));
    }

    private static V1Secret CallCreateOrUpdate(KubeCertificateManagerClient client) =>
        client.CreateOrUpdateCertificateStoreSecret(
            "key-pem", "cert-pem", new List<string>(),
            SecretName, Namespace, "tls");

    #endregion

    [Fact]
    public void SecretMissing_CreatesSecret()
    {
        var k8sMock = new Mock<IKubernetes>();
        var core = SetupCoreV1(k8sMock);
        SetupRead(core, MakeHttpException(HttpStatusCode.NotFound));
        SetupCreate(core);
        var client = CreateClientWithMock(k8sMock.Object);

        var result = CallCreateOrUpdate(client);

        Assert.NotNull(result);
        core.Verify(c => c.CreateNamespacedSecretWithHttpMessagesAsync(
            It.IsAny<V1Secret>(), Namespace, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<bool?>(), It.IsAny<IReadOnlyDictionary<string, IReadOnlyList<string>>>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public void SecretExists_UpdatesInsteadOfCreating()
    {
        // Pre-existing secret: must route to the update (replace) path without ever attempting a blind POST.
        var k8sMock = new Mock<IKubernetes>();
        var core = SetupCoreV1(k8sMock);
        SetupRead(core, ExistingTlsSecret(), ExistingTlsSecret()); // read-branch check + UpdateSecretStore's read
        SetupReplace(core);
        var client = CreateClientWithMock(k8sMock.Object);

        var result = CallCreateOrUpdate(client);

        Assert.NotNull(result);
        core.Verify(c => c.CreateNamespacedSecretWithHttpMessagesAsync(
            It.IsAny<V1Secret>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<bool?>(), It.IsAny<IReadOnlyDictionary<string, IReadOnlyList<string>>>(),
            It.IsAny<CancellationToken>()), Times.Never);
        core.Verify(c => c.ReplaceNamespacedSecretWithHttpMessagesAsync(
            It.IsAny<V1Secret>(), SecretName, Namespace, It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<bool?>(),
            It.IsAny<IReadOnlyDictionary<string, IReadOnlyList<string>>>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public void CreateFails_Forbidden_ThrowsInsteadOfReturningNull()
    {
        // Regression for GH #91: a 403 (or any non-Conflict API error) on create previously fell
        // through to a silent `return null`, which the Management job reported as Success.
        var k8sMock = new Mock<IKubernetes>();
        var core = SetupCoreV1(k8sMock);
        SetupRead(core, MakeHttpException(HttpStatusCode.NotFound));
        SetupCreate(core, MakeHttpException(HttpStatusCode.Forbidden));
        var client = CreateClientWithMock(k8sMock.Object);

        var ex = Assert.Throws<HttpOperationException>(() => CallCreateOrUpdate(client));
        Assert.Equal(HttpStatusCode.Forbidden, ex.Response.StatusCode);
    }

    [Fact]
    public void ReadFails_Forbidden_ThrowsInsteadOfReturningNull()
    {
        // A non-404 error on the existence check must also propagate (SecretOperations.GetSecret
        // only swallows typed 404s).
        var k8sMock = new Mock<IKubernetes>();
        var core = SetupCoreV1(k8sMock);
        SetupRead(core, MakeHttpException(HttpStatusCode.Forbidden));
        var client = CreateClientWithMock(k8sMock.Object);

        var ex = Assert.Throws<HttpOperationException>(() => CallCreateOrUpdate(client));
        Assert.Equal(HttpStatusCode.Forbidden, ex.Response.StatusCode);
    }

    [Fact]
    public void CreateConflict_RaceCondition_FallsBackToUpdate()
    {
        // Secret created concurrently between the existence check and the create call:
        // typed 409 Conflict routes to the update path.
        var k8sMock = new Mock<IKubernetes>();
        var core = SetupCoreV1(k8sMock);
        SetupRead(core, MakeHttpException(HttpStatusCode.NotFound), ExistingTlsSecret());
        SetupCreate(core, MakeHttpException(HttpStatusCode.Conflict));
        SetupReplace(core);
        var client = CreateClientWithMock(k8sMock.Object);

        var result = CallCreateOrUpdate(client);

        Assert.NotNull(result);
        core.Verify(c => c.ReplaceNamespacedSecretWithHttpMessagesAsync(
            It.IsAny<V1Secret>(), SecretName, Namespace, It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string>(), It.IsAny<bool?>(),
            It.IsAny<IReadOnlyDictionary<string, IReadOnlyList<string>>>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }
}
