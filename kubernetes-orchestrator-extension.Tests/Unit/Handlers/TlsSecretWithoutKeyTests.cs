// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Linq;
using System.Text;
using Keyfactor.Extensions.Orchestrator.K8S.Handlers;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using KeyType = Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper.KeyType;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Handlers;

/// <summary>
/// A kubernetes.io/tls secret with tls.crt but no tls.key (should not happen, but is supported): it is a valid
/// K8STLSSecr store with certificates and no private key. A missing/empty tls.crt is still not a TLS cert store.
/// </summary>
public class TlsSecretWithoutKeyTests
{
    private const string Ns = "tls-nokey";

    private static ISecretOperationContext Context(string name)
    {
        var mock = new Mock<ISecretOperationContext>();
        mock.Setup(c => c.KubeNamespace).Returns(Ns);
        mock.Setup(c => c.KubeSecretName).Returns(name);
        mock.Setup(c => c.StorePath).Returns($"{Ns}/{name}");
        mock.Setup(c => c.StorePassword).Returns(string.Empty);
        mock.Setup(c => c.PasswordSecretPath).Returns(string.Empty);
        mock.Setup(c => c.PasswordFieldName).Returns(string.Empty);
        mock.Setup(c => c.IncludeCertChain).Returns(true);
        mock.Setup(c => c.CertificateDataFieldName).Returns(string.Empty);
        return mock.Object;
    }

    private static MockedKubeClient Client()
    {
        var pem = CertificateTestHelper.ConvertCertificateToPem(
            CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "tls-nokey").Certificate);
        var data = Encoding.UTF8.GetBytes(pem);
        return MockedKubeClientFactory.Create(new[]
        {
            MockedKubeClientFactory.Secret(Ns, "cert-only", "kubernetes.io/tls",
                new Dictionary<string, byte[]> { ["tls.crt"] = data }),
            MockedKubeClientFactory.Secret(Ns, "no-crt", "kubernetes.io/tls",
                new Dictionary<string, byte[]> { ["tls.key"] = data }),
            MockedKubeClientFactory.Secret(Ns, "empty-crt", "kubernetes.io/tls",
                new Dictionary<string, byte[]> { ["tls.crt"] = new byte[0] })
        });
    }

    [Fact]
    public void Discovery_ReportsCertOnlyTlsSecret_AndSkipsMissingOrEmptyCrt()
    {
        var kube = Client();
        var handler = new TlsSecretHandler(kube.Client, new Mock<ILogger>().Object, Context("x"));

        var found = handler.DiscoverStores(null, "all");

        var single = Assert.Single(found);
        Assert.EndsWith($"/{Ns}/secrets/cert-only", single);
    }

    [Fact]
    public void SingleStoreInventory_CertOnlyTlsSecret_ReturnsCertWithoutKey()
    {
        var kube = Client();
        var handler = new TlsSecretHandler(kube.Client, new Mock<ILogger>().Object, Context("cert-only"));

        var entries = handler.GetInventoryEntries(1);

        var entry = Assert.Single(entries);
        Assert.Single(entry.Certificates);
        Assert.False(entry.HasPrivateKey);
        Assert.Single(handler.GetCertificates(1));
        Assert.False(handler.HasPrivateKey());
    }
}
