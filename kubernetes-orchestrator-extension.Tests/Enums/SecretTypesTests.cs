// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Xunit;

namespace Keyfactor.Orchestrators.K8S.Tests.Enums;

public class SecretTypesTests
{
    #region IsTlsType Tests

    [Theory]
    [InlineData("tls")]
    [InlineData("TLS")]
    [InlineData("tls_secret")]
    [InlineData("TLS_SECRET")]
    [InlineData("tlssecret")]
    [InlineData("TLSSECRET")]
    [InlineData("tls_secrets")]
    public void IsTlsType_ValidTlsVariants_ReturnsTrue(string type)
    {
        Assert.True(SecretTypes.IsTlsType(type));
    }

    [Theory]
    [InlineData("opaque")]
    [InlineData("secret")]
    [InlineData("pkcs12")]
    [InlineData("jks")]
    [InlineData("invalid")]
    [InlineData("")]
    [InlineData(null)]
    public void IsTlsType_NonTlsTypes_ReturnsFalse(string type)
    {
        Assert.False(SecretTypes.IsTlsType(type));
    }

    #endregion

    #region IsOpaqueType Tests

    [Theory]
    [InlineData("opaque")]
    [InlineData("OPAQUE")]
    [InlineData("secret")]
    [InlineData("SECRET")]
    [InlineData("secrets")]
    [InlineData("SECRETS")]
    public void IsOpaqueType_ValidOpaqueVariants_ReturnsTrue(string type)
    {
        Assert.True(SecretTypes.IsOpaqueType(type));
    }

    [Theory]
    [InlineData("tls")]
    [InlineData("pkcs12")]
    [InlineData("jks")]
    [InlineData("invalid")]
    [InlineData("")]
    [InlineData(null)]
    public void IsOpaqueType_NonOpaqueTypes_ReturnsFalse(string type)
    {
        Assert.False(SecretTypes.IsOpaqueType(type));
    }

    #endregion

    #region IsCsrType Tests

    [Theory]
    [InlineData("certificate")]
    [InlineData("CERTIFICATE")]
    [InlineData("cert")]
    [InlineData("csr")]
    [InlineData("CSR")]
    [InlineData("csrs")]
    [InlineData("certs")]
    [InlineData("certificates")]
    public void IsCsrType_ValidCsrVariants_ReturnsTrue(string type)
    {
        Assert.True(SecretTypes.IsCsrType(type));
    }

    [Theory]
    [InlineData("tls")]
    [InlineData("opaque")]
    [InlineData("pkcs12")]
    [InlineData("jks")]
    [InlineData("invalid")]
    [InlineData("")]
    [InlineData(null)]
    public void IsCsrType_NonCsrTypes_ReturnsFalse(string type)
    {
        Assert.False(SecretTypes.IsCsrType(type));
    }

    #endregion

    #region IsPkcs12Type Tests

    [Theory]
    [InlineData("pfx")]
    [InlineData("PFX")]
    [InlineData("pkcs12")]
    [InlineData("PKCS12")]
    [InlineData("p12")]
    [InlineData("P12")]
    public void IsPkcs12Type_ValidPkcs12Variants_ReturnsTrue(string type)
    {
        Assert.True(SecretTypes.IsPkcs12Type(type));
    }

    [Theory]
    [InlineData("tls")]
    [InlineData("opaque")]
    [InlineData("jks")]
    [InlineData("invalid")]
    [InlineData("")]
    [InlineData(null)]
    public void IsPkcs12Type_NonPkcs12Types_ReturnsFalse(string type)
    {
        Assert.False(SecretTypes.IsPkcs12Type(type));
    }

    #endregion

    #region IsJksType Tests

    [Theory]
    [InlineData("jks")]
    [InlineData("JKS")]
    [InlineData("Jks")]
    public void IsJksType_ValidJksVariants_ReturnsTrue(string type)
    {
        Assert.True(SecretTypes.IsJksType(type));
    }

    [Theory]
    [InlineData("tls")]
    [InlineData("opaque")]
    [InlineData("pkcs12")]
    [InlineData("invalid")]
    [InlineData("")]
    [InlineData(null)]
    public void IsJksType_NonJksTypes_ReturnsFalse(string type)
    {
        Assert.False(SecretTypes.IsJksType(type));
    }

    #endregion

    #region IsKeystoreType Tests

    [Theory]
    [InlineData("pkcs12")]
    [InlineData("PKCS12")]
    [InlineData("pfx")]
    [InlineData("p12")]
    [InlineData("jks")]
    [InlineData("JKS")]
    public void IsKeystoreType_ValidKeystoreVariants_ReturnsTrue(string type)
    {
        Assert.True(SecretTypes.IsKeystoreType(type));
    }

    [Theory]
    [InlineData("tls")]
    [InlineData("opaque")]
    [InlineData("secret")]
    [InlineData("certificate")]
    [InlineData("invalid")]
    [InlineData("")]
    [InlineData(null)]
    public void IsKeystoreType_NonKeystoreTypes_ReturnsFalse(string type)
    {
        Assert.False(SecretTypes.IsKeystoreType(type));
    }

    #endregion

    #region IsNamespaceType Tests

    [Theory]
    [InlineData("namespace")]
    [InlineData("NAMESPACE")]
    [InlineData("ns")]
    [InlineData("NS")]
    public void IsNamespaceType_ValidNamespaceVariants_ReturnsTrue(string type)
    {
        Assert.True(SecretTypes.IsNamespaceType(type));
    }

    [Theory]
    [InlineData("tls")]
    [InlineData("opaque")]
    [InlineData("cluster")]
    [InlineData("invalid")]
    [InlineData("")]
    [InlineData(null)]
    public void IsNamespaceType_NonNamespaceTypes_ReturnsFalse(string type)
    {
        Assert.False(SecretTypes.IsNamespaceType(type));
    }

    #endregion

    #region IsClusterType Tests

    [Theory]
    [InlineData("cluster")]
    [InlineData("CLUSTER")]
    [InlineData("k8scluster")]
    [InlineData("K8SCLUSTER")]
    public void IsClusterType_ValidClusterVariants_ReturnsTrue(string type)
    {
        Assert.True(SecretTypes.IsClusterType(type));
    }

    [Theory]
    [InlineData("tls")]
    [InlineData("opaque")]
    [InlineData("namespace")]
    [InlineData("invalid")]
    [InlineData("")]
    [InlineData(null)]
    public void IsClusterType_NonClusterTypes_ReturnsFalse(string type)
    {
        Assert.False(SecretTypes.IsClusterType(type));
    }

    #endregion

    #region IsAggregateStoreType Tests

    [Theory]
    [InlineData("namespace")]
    [InlineData("ns")]
    [InlineData("cluster")]
    [InlineData("k8scluster")]
    public void IsAggregateStoreType_ValidAggregateTypes_ReturnsTrue(string type)
    {
        Assert.True(SecretTypes.IsAggregateStoreType(type));
    }

    [Theory]
    [InlineData("tls")]
    [InlineData("opaque")]
    [InlineData("pkcs12")]
    [InlineData("jks")]
    [InlineData("invalid")]
    [InlineData("")]
    [InlineData(null)]
    public void IsAggregateStoreType_NonAggregateTypes_ReturnsFalse(string type)
    {
        Assert.False(SecretTypes.IsAggregateStoreType(type));
    }

    #endregion

    #region Normalize Tests

    [Theory]
    [InlineData("tls", "tls")]
    [InlineData("TLS", "tls")]
    [InlineData("tls_secret", "tls")]
    [InlineData("tlssecret", "tls")]
    public void Normalize_TlsVariants_ReturnsTls(string input, string expected)
    {
        Assert.Equal(expected, SecretTypes.Normalize(input));
    }

    [Theory]
    [InlineData("opaque", "secret")]
    [InlineData("OPAQUE", "secret")]
    [InlineData("secret", "secret")]
    [InlineData("secrets", "secret")]
    public void Normalize_OpaqueVariants_ReturnsSecret(string input, string expected)
    {
        Assert.Equal(expected, SecretTypes.Normalize(input));
    }

    [Theory]
    [InlineData("certificate", "certificate")]
    [InlineData("cert", "certificate")]
    [InlineData("csr", "certificate")]
    [InlineData("csrs", "certificate")]
    public void Normalize_CsrVariants_ReturnsCertificate(string input, string expected)
    {
        Assert.Equal(expected, SecretTypes.Normalize(input));
    }

    [Theory]
    [InlineData("pkcs12", "pkcs12")]
    [InlineData("PKCS12", "pkcs12")]
    [InlineData("pfx", "pkcs12")]
    [InlineData("p12", "pkcs12")]
    public void Normalize_Pkcs12Variants_ReturnsPkcs12(string input, string expected)
    {
        Assert.Equal(expected, SecretTypes.Normalize(input));
    }

    [Theory]
    [InlineData("jks", "jks")]
    [InlineData("JKS", "jks")]
    public void Normalize_JksVariants_ReturnsJks(string input, string expected)
    {
        Assert.Equal(expected, SecretTypes.Normalize(input));
    }

    [Theory]
    [InlineData("namespace", "namespace")]
    [InlineData("ns", "namespace")]
    [InlineData("NS", "namespace")]
    public void Normalize_NamespaceVariants_ReturnsNamespace(string input, string expected)
    {
        Assert.Equal(expected, SecretTypes.Normalize(input));
    }

    [Theory]
    [InlineData("cluster", "cluster")]
    [InlineData("k8scluster", "cluster")]
    [InlineData("K8SCLUSTER", "cluster")]
    public void Normalize_ClusterVariants_ReturnsCluster(string input, string expected)
    {
        Assert.Equal(expected, SecretTypes.Normalize(input));
    }

    [Theory]
    [InlineData("unknown", "unknown")]
    [InlineData("invalid", "invalid")]
    public void Normalize_UnknownTypes_ReturnsOriginal(string input, string expected)
    {
        Assert.Equal(expected, SecretTypes.Normalize(input));
    }

    [Fact]
    public void Normalize_NullInput_ReturnsNull()
    {
        Assert.Null(SecretTypes.Normalize(null));
    }

    #endregion

    #region Constants Tests

    [Fact]
    public void Constants_HaveExpectedValues()
    {
        Assert.Equal("tls", SecretTypes.Tls);
        Assert.Equal("secret", SecretTypes.Opaque);
        Assert.Equal("certificate", SecretTypes.Certificate);
        Assert.Equal("pkcs12", SecretTypes.Pkcs12);
        Assert.Equal("jks", SecretTypes.Jks);
        Assert.Equal("namespace", SecretTypes.Namespace);
        Assert.Equal("cluster", SecretTypes.Cluster);
    }

    #endregion
}
