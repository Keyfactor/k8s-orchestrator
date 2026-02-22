// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

namespace Keyfactor.Extensions.Orchestrator.K8S.Enums;

/// <summary>
/// Enumeration of supported Kubernetes certificate store types.
/// Each store type corresponds to a different Kubernetes resource or certificate format.
/// </summary>
public enum StoreType
{
    /// <summary>
    /// Unknown or unrecognized store type.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Kubernetes Certificate Signing Request (certificates.k8s.io/v1).
    /// Read-only: supports Inventory and Discovery only.
    /// </summary>
    K8SCert,

    /// <summary>
    /// Cluster-wide secret management.
    /// Manages all Opaque and TLS secrets across all namespaces.
    /// </summary>
    K8SCluster,

    /// <summary>
    /// Namespace-level secret management.
    /// Manages all Opaque and TLS secrets within a single namespace.
    /// </summary>
    K8SNS,

    /// <summary>
    /// Java KeyStore (JKS) files stored in Opaque secrets.
    /// Supports password-protected keystores.
    /// </summary>
    K8SJKS,

    /// <summary>
    /// PKCS12/PFX files stored in Opaque secrets.
    /// Supports password-protected keystores.
    /// </summary>
    K8SPKCS12,

    /// <summary>
    /// Kubernetes Opaque secrets containing PEM certificates.
    /// Standard single-secret management.
    /// </summary>
    K8SSecret,

    /// <summary>
    /// Kubernetes TLS secrets (kubernetes.io/tls type).
    /// Contains tls.crt and tls.key fields.
    /// </summary>
    K8STLSSecr
}
