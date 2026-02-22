// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Constants;

namespace Keyfactor.Extensions.Orchestrator.K8S.Models;

/// <summary>
/// Context object containing all parameters needed for secret operations.
/// Consolidates the many parameters previously passed to methods individually,
/// reducing method signature complexity and improving readability.
/// </summary>
public class SecretOperationContext
{
    /// <summary>
    /// Name of the Kubernetes secret to operate on.
    /// </summary>
    public string SecretName { get; set; } = string.Empty;

    /// <summary>
    /// Kubernetes namespace containing the secret.
    /// </summary>
    public string Namespace { get; set; } = string.Empty;

    /// <summary>
    /// Type of secret being operated on.
    /// </summary>
    public SecretType SecretType { get; set; } = SecretType.Unknown;

    /// <summary>
    /// Store type for this operation.
    /// </summary>
    public StoreType StoreType { get; set; } = StoreType.Unknown;

    /// <summary>
    /// Field name within the secret where certificate data is stored.
    /// For TLS secrets this is typically "tls.crt".
    /// </summary>
    public string CertDataFieldName { get; set; } = string.Empty;

    /// <summary>
    /// Password for the certificate store (JKS/PKCS12).
    /// </summary>
    public string StorePassword { get; set; } = string.Empty;

    /// <summary>
    /// Indicates whether the store password is stored in a separate Kubernetes secret.
    /// </summary>
    public bool PasswordIsK8SSecret { get; set; }

    /// <summary>
    /// Path to the Kubernetes secret containing the password (if PasswordIsK8SSecret is true).
    /// Format: "namespace/secret-name" or just "secret-name" for same namespace.
    /// </summary>
    public string PasswordSecretPath { get; set; } = string.Empty;

    /// <summary>
    /// Field name within the password secret where the password is stored.
    /// Defaults to "password".
    /// </summary>
    public string PasswordFieldName { get; set; } = SecretFieldNames.DefaultPassword;

    /// <summary>
    /// Whether to overwrite existing certificate data.
    /// </summary>
    public bool Overwrite { get; set; }

    /// <summary>
    /// Whether to append to existing certificate data (for multi-certificate secrets).
    /// </summary>
    public bool Append { get; set; }

    /// <summary>
    /// Whether to store the certificate chain in a separate field (e.g., ca.crt).
    /// </summary>
    public bool SeparateChain { get; set; }

    /// <summary>
    /// Whether to include the certificate chain in the output.
    /// </summary>
    public bool IncludeCertChain { get; set; } = true;

    /// <summary>
    /// The original store path from the job configuration.
    /// </summary>
    public string StorePath { get; set; } = string.Empty;

    /// <summary>
    /// The Keyfactor capability string (e.g., "CertStores.K8SJKS.Inventory").
    /// </summary>
    public string Capability { get; set; } = string.Empty;

    /// <summary>
    /// The job history ID for tracking.
    /// </summary>
    public long JobHistoryId { get; set; }

    /// <summary>
    /// The job ID.
    /// </summary>
    public Guid JobId { get; set; }

    /// <summary>
    /// Creates a shallow copy of this context.
    /// Useful when modifying context for nested operations.
    /// </summary>
    /// <returns>A new SecretOperationContext with the same values.</returns>
    public SecretOperationContext Clone()
    {
        return new SecretOperationContext
        {
            SecretName = SecretName,
            Namespace = Namespace,
            SecretType = SecretType,
            StoreType = StoreType,
            CertDataFieldName = CertDataFieldName,
            StorePassword = StorePassword,
            PasswordIsK8SSecret = PasswordIsK8SSecret,
            PasswordSecretPath = PasswordSecretPath,
            PasswordFieldName = PasswordFieldName,
            Overwrite = Overwrite,
            Append = Append,
            SeparateChain = SeparateChain,
            IncludeCertChain = IncludeCertChain,
            StorePath = StorePath,
            Capability = Capability,
            JobHistoryId = JobHistoryId,
            JobId = JobId
        };
    }
}
