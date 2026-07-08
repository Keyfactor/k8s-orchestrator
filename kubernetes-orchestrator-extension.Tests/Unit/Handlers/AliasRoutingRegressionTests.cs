// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.IO;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Serializers.K8SJKS;
using Keyfactor.Extensions.Orchestrator.K8S.Serializers.K8SPKCS12;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using Org.BouncyCastle.Security;
using Xunit;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests.Unit.Handlers;

/// <summary>
/// Regression tests for the alias routing fix in JksSecretHandler and Pkcs12SecretHandler.
///
/// Bug: HandleAdd/HandleRemove always used <c>inventory.Keys.First()</c> as the K8S secret field
/// and passed the <b>full</b> alias string (e.g. <c>"meow.jks/default"</c>) to the serializer,
/// causing entries to be stored under a wrong alias inside the keystore file.
///
/// Fix: Parse alias at the first '/' to extract <c>fieldName</c> and <c>certAlias</c> separately:
/// <list type="bullet">
///   <item><c>fieldName</c> → selects which field in the K8S secret to read/write</item>
///   <item><c>certAlias</c> → alias used inside the JKS/PKCS12 file</item>
/// </list>
///
/// These tests use the JKS and PKCS12 serializers directly (no K8S client required) to prove the
/// building-block behaviour: the alias passed to <c>CreateOrUpdate*</c> is what gets stored, so
/// passing the full path alias would produce wrong results in inventory and remove operations.
/// </summary>
public class AliasRoutingRegressionTests
{
    // ──────────────────────────────────────────────────────────────
    // JKS alias routing
    // ──────────────────────────────────────────────────────────────

    #region JKS – certAlias is stored, full-path alias is not

    [Fact]
    public void Jks_StoreWithCertAlias_EntryFoundUnderCertAlias()
    {
        // Regression: the fix passes certAlias (e.g. "default") to the serializer,
        // not the full path (e.g. "mystore.jks/default").
        var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JKS Alias Routing Test");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(cert.Certificate, cert.KeyPair, "certpw", "mycert");

        var serializer = new JksCertificateStoreSerializer(null);
        var jksBytes = serializer.CreateOrUpdateJks(pfxBytes, "certpw", "mycert", null, "storepw",
            remove: false, includeChain: false);

        var store = new JksStore();
        using var ms = new MemoryStream(jksBytes);
        store.Load(ms, "storepw".ToCharArray());

        Assert.True(store.ContainsAlias("mycert"),
            "Entry must be stored under the short certAlias 'mycert'");
        Assert.False(store.ContainsAlias("mystore.jks/mycert"),
            "Entry must NOT be stored under the full path alias");
    }

    [Fact]
    public void Jks_StoreWithFullPathAlias_OldBehaviourWasWrong_EntryIsUnderFullPath()
    {
        // Documents why the pre-fix behaviour was incorrect:
        // Passing the full path "mystore.jks/mycert" as the keystore alias stores the
        // entry under that full string, so inventory would return
        // "keystore.jks/mystore.jks/mycert" — clearly wrong.
        var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JKS Old Alias Routing");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(cert.Certificate, cert.KeyPair, "certpw", "mycert");

        var serializer = new JksCertificateStoreSerializer(null);
        var jksBytes = serializer.CreateOrUpdateJks(pfxBytes, "certpw", "mystore.jks/mycert", null, "storepw",
            remove: false, includeChain: false);

        var store = new JksStore();
        using var ms = new MemoryStream(jksBytes);
        store.Load(ms, "storepw".ToCharArray());

        // With old behaviour the short alias is not present …
        Assert.False(store.ContainsAlias("mycert"),
            "Short alias should NOT be found when full path was mistakenly used");
        // … only the wrong full-path alias is.
        Assert.True(store.ContainsAlias("mystore.jks/mycert"),
            "The full path alias is what gets stored with old behaviour");
    }

    [Fact]
    public void Jks_RemoveWithCertAlias_RemovesCorrectEntry()
    {
        // Prove that Remove with certAlias (not full path) removes the right entry.
        var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JKS Remove Alias Test");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(cert.Certificate, cert.KeyPair, "certpw", "mycert");

        var serializer = new JksCertificateStoreSerializer(null);
        // Add
        var jksBytes = serializer.CreateOrUpdateJks(pfxBytes, "certpw", "mycert", null, "storepw",
            remove: false, includeChain: false);

        // Remove using certAlias
        var afterRemoveBytes = serializer.CreateOrUpdateJks(null, null, "mycert", jksBytes, "storepw",
            remove: true, includeChain: false);

        var store = new JksStore();
        using var ms = new MemoryStream(afterRemoveBytes);
        store.Load(ms, "storepw".ToCharArray());

        Assert.False(store.ContainsAlias("mycert"), "Entry should have been removed");
        Assert.Empty(store.Aliases.Cast<string>());
    }

    [Fact]
    public void Jks_InventoryAlias_IsFieldNameSlashCertAlias()
    {
        // Verifies the inventory alias format produced by JksSecretHandler.GetInventoryEntries:
        //   fullAlias = $"{keyName}/{alias}"
        // where keyName is the K8S secret field ("mystore.jks") and alias is the short certAlias ("mycert").
        // The final inventory alias must therefore be "mystore.jks/mycert", not "mycert" or "mystore.jks/mystore.jks/mycert".
        const string fieldName = "mystore.jks";
        const string certAlias = "mycert";

        var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "JKS Inventory Alias Test");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(cert.Certificate, cert.KeyPair, "certpw", certAlias);

        var serializer = new JksCertificateStoreSerializer(null);
        var jksBytes = serializer.CreateOrUpdateJks(pfxBytes, "certpw", certAlias, null, "storepw",
            remove: false, includeChain: false);

        // Simulate what the handler does during inventory
        var store = serializer.DeserializeRemoteCertificateStore(jksBytes, fieldName, "storepw");
        var aliases = store.Aliases.Cast<string>().ToList();

        Assert.Single(aliases);
        // The alias inside the JKS file should be the short certAlias
        Assert.Equal(certAlias, aliases[0]);
        // And the full alias the handler would return is fieldName/certAlias
        Assert.Equal($"{fieldName}/{certAlias}", $"{fieldName}/{aliases[0]}");
    }

    #endregion

    // ──────────────────────────────────────────────────────────────
    // PKCS12 alias routing
    // ──────────────────────────────────────────────────────────────

    #region PKCS12 – certAlias is stored, full-path alias is not

    [Fact]
    public void Pkcs12_StoreWithCertAlias_EntryFoundUnderCertAlias()
    {
        // Regression: the fix passes certAlias (e.g. "default") to the serializer,
        // not the full path (e.g. "mystore.p12/default").
        var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Alias Routing Test");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(cert.Certificate, cert.KeyPair, "certpw", "mycert");

        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var pkcs12Bytes = serializer.CreateOrUpdatePkcs12(pfxBytes, "certpw", "mycert", null, "storepw",
            remove: false, includeChain: false);

        var store = serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "mystore.p12", "storepw");
        var aliases = store.Aliases.Cast<string>().ToList();

        Assert.Contains("mycert", aliases);
        Assert.DoesNotContain("mystore.p12/mycert", aliases);
    }

    [Fact]
    public void Pkcs12_StoreWithFullPathAlias_OldBehaviourWasWrong_EntryIsUnderFullPath()
    {
        // Documents why the pre-fix behaviour was incorrect for PKCS12.
        var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Old Alias Routing");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(cert.Certificate, cert.KeyPair, "certpw", "mycert");

        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var pkcs12Bytes = serializer.CreateOrUpdatePkcs12(pfxBytes, "certpw", "mystore.p12/mycert", null, "storepw",
            remove: false, includeChain: false);

        var store = serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, "mystore.p12", "storepw");
        var aliases = store.Aliases.Cast<string>().ToList();

        Assert.DoesNotContain("mycert", aliases);
        Assert.Contains("mystore.p12/mycert", aliases);
    }

    [Fact]
    public void Pkcs12_RemoveWithCertAlias_RemovesCorrectEntry()
    {
        // Prove that Remove with certAlias (not full path) removes the right entry.
        var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Remove Alias Test");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(cert.Certificate, cert.KeyPair, "certpw", "mycert");

        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var pkcs12Bytes = serializer.CreateOrUpdatePkcs12(pfxBytes, "certpw", "mycert", null, "storepw",
            remove: false, includeChain: false);

        var afterRemoveBytes = serializer.CreateOrUpdatePkcs12(null, null, "mycert", pkcs12Bytes, "storepw",
            remove: true, includeChain: false);

        var store = serializer.DeserializeRemoteCertificateStore(afterRemoveBytes, "mystore.p12", "storepw");
        var aliases = store.Aliases.Cast<string>().ToList();

        Assert.Empty(aliases);
    }

    [Fact]
    public void Pkcs12_InventoryAlias_IsFieldNameSlashCertAlias()
    {
        // Verifies the inventory alias format produced by Pkcs12SecretHandler.GetInventoryEntries:
        //   fullAlias = $"{keyName}/{alias}"
        const string fieldName = "mystore.p12";
        const string certAlias = "mycert";

        var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "PKCS12 Inventory Alias Test");
        var pfxBytes = CertificateTestHelper.GeneratePkcs12(cert.Certificate, cert.KeyPair, "certpw", certAlias);

        var serializer = new Pkcs12CertificateStoreSerializer(null);
        var pkcs12Bytes = serializer.CreateOrUpdatePkcs12(pfxBytes, "certpw", certAlias, null, "storepw",
            remove: false, includeChain: false);

        var store = serializer.DeserializeRemoteCertificateStore(pkcs12Bytes, fieldName, "storepw");
        var aliases = store.Aliases.Cast<string>().ToList();

        Assert.Single(aliases);
        Assert.Equal(certAlias, aliases[0]);
        Assert.Equal($"{fieldName}/{certAlias}", $"{fieldName}/{aliases[0]}");
    }

    #endregion
}
