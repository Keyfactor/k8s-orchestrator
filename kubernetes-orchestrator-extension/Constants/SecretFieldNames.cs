// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

namespace Keyfactor.Extensions.Orchestrator.K8S.Constants;

/// <summary>
/// Constants for standard Kubernetes secret data field names.
/// These field names follow Kubernetes conventions for TLS secrets and common certificate formats.
/// </summary>
public static class SecretFieldNames
{
    /// <summary>
    /// Standard TLS certificate field in kubernetes.io/tls secrets.
    /// </summary>
    public const string TlsCrt = "tls.crt";

    /// <summary>
    /// Standard TLS private key field in kubernetes.io/tls secrets.
    /// </summary>
    public const string TlsKey = "tls.key";

    /// <summary>
    /// Common CA certificate field name.
    /// </summary>
    public const string CaCrt = "ca.crt";

    /// <summary>
    /// Default field name for JKS keystore data in Opaque secrets.
    /// </summary>
    public const string DefaultJks = "jks";

    /// <summary>
    /// Default field name for PKCS12 keystore data in Opaque secrets.
    /// </summary>
    public const string DefaultPkcs12 = "pkcs12";

    /// <summary>
    /// Default field name for PFX keystore data in Opaque secrets.
    /// </summary>
    public const string DefaultPfx = "pfx";

    /// <summary>
    /// Default field name for password data in secrets.
    /// </summary>
    public const string DefaultPassword = "password";

    /// <summary>
    /// Common field name for generic certificate data.
    /// </summary>
    public const string Certificate = "certificate";

    /// <summary>
    /// Short form field name for certificate data.
    /// </summary>
    public const string Cert = "cert";

    /// <summary>
    /// Plural form field name for certificates.
    /// </summary>
    public const string Certificates = "certificates";

    /// <summary>
    /// Plural short form field name for certificates.
    /// </summary>
    public const string Certs = "certs";

    /// <summary>
    /// Common field name for CRT files.
    /// </summary>
    public const string Crt = "crt";

    /// <summary>
    /// Plural form for CRT files.
    /// </summary>
    public const string Crts = "crts";

    /// <summary>
    /// Field name for TLS certificates (plural).
    /// </summary>
    public const string TlsCrts = "tls.crts";
}

/// <summary>
/// Constants for allowed keys arrays used in secret discovery and inventory.
/// </summary>
public static class AllowedKeys
{
    /// <summary>
    /// Allowed keys for TLS secrets (kubernetes.io/tls type).
    /// </summary>
    public static readonly string[] TlsKeys = { SecretFieldNames.TlsCrt, SecretFieldNames.TlsKey, SecretFieldNames.CaCrt };

    /// <summary>
    /// Allowed keys for Opaque secrets containing certificates.
    /// </summary>
    public static readonly string[] OpaqueKeys =
    {
        SecretFieldNames.TlsCrt, SecretFieldNames.TlsCrts,
        SecretFieldNames.Cert, SecretFieldNames.Certs,
        SecretFieldNames.Certificate, SecretFieldNames.Certificates,
        SecretFieldNames.Crt, SecretFieldNames.Crts,
        SecretFieldNames.CaCrt
    };

    /// <summary>
    /// Allowed keys for Certificate Signing Request resources.
    /// </summary>
    public static readonly string[] CertKeys = { SecretFieldNames.Cert, "csr" };

    /// <summary>
    /// Allowed keys for PKCS12/PFX files in secrets.
    /// </summary>
    public static readonly string[] Pkcs12Keys = { "p12", SecretFieldNames.DefaultPkcs12, SecretFieldNames.DefaultPfx };

    /// <summary>
    /// Allowed keys for JKS files in secrets.
    /// </summary>
    public static readonly string[] JksKeys = { SecretFieldNames.DefaultJks };
}
