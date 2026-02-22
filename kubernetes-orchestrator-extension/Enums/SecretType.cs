// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

namespace Keyfactor.Extensions.Orchestrator.K8S.Enums;

/// <summary>
/// Enumeration of Kubernetes secret types and certificate formats.
/// Used internally to route operations to appropriate handlers.
/// </summary>
public enum SecretType
{
    /// <summary>
    /// Unknown or unrecognized secret type.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Kubernetes Opaque secret type.
    /// Corresponds to string values: "secret", "secrets", "opaque"
    /// </summary>
    Opaque,

    /// <summary>
    /// Kubernetes TLS secret type (kubernetes.io/tls).
    /// Corresponds to string values: "tls", "tls_secret", "tlssecret", "tls_secrets"
    /// </summary>
    Tls,

    /// <summary>
    /// Kubernetes Certificate Signing Request.
    /// Corresponds to string values: "cert", "csr", "certificate", "csrs", "certs", "certificates"
    /// </summary>
    Certificate,

    /// <summary>
    /// Java KeyStore format stored in a secret.
    /// Corresponds to string value: "jks"
    /// </summary>
    Jks,

    /// <summary>
    /// PKCS12/PFX format stored in a secret.
    /// Corresponds to string values: "pkcs12", "p12", "pfx"
    /// </summary>
    Pkcs12,

    /// <summary>
    /// Cluster-wide scope for operations.
    /// Used by K8SCluster store type.
    /// </summary>
    Cluster,

    /// <summary>
    /// Namespace-wide scope for operations.
    /// Used by K8SNS store type.
    /// </summary>
    Namespace
}
