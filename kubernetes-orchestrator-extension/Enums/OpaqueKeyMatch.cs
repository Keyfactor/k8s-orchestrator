// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

namespace Keyfactor.Extensions.Orchestrator.K8S.Enums;

/// <summary>
/// How <c>KubeCertificateManagerClient.DiscoverSecrets</c> decides whether an Opaque secret is reported.
/// </summary>
public enum OpaqueKeyMatch
{
    /// <summary>
    /// Report the secret if it has a data key equal to an allowed key, or ending with <c>.&lt;allowed&gt;</c>
    /// (case-insensitive). Used by K8SJKS / K8SPKCS12, whose inventory matches keystore fields by extension.
    /// A null/empty allowed-key list matches nothing.
    /// </summary>
    Suffix = 0,

    /// <summary>
    /// Report the secret only if it has a data key exactly equal (case-sensitive) to an allowed key. Used by K8SSecret
    /// so discovery reports exactly what inventory reads. A null/empty allowed-key list matches nothing.
    /// </summary>
    Exact = 1,

    /// <summary>
    /// No data-key filtering: every Opaque secret is reported. Must be requested explicitly (K8SCluster / K8SNS
    /// inventory); it is never implied by a null or empty allowed-key list.
    /// </summary>
    AllSecrets = 2
}
