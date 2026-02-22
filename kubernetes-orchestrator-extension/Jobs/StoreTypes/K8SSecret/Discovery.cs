// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Extensions.Orchestrator.K8S.Constants;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;
using Keyfactor.Orchestrators.Extensions.Interfaces;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SSecret;

/// <summary>
/// Discovery job for Kubernetes Opaque secrets containing certificates.
/// Finds Opaque secrets in specified namespaces.
/// </summary>
public class Discovery : DiscoveryBase
{
    /// <summary>
    /// Creates a new Opaque secret discovery job with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    public Discovery(IPAMSecretResolver resolver) : base(resolver)
    {
    }

    /// <inheritdoc />
    protected override SecretType GetSecretType() => SecretType.Opaque;

    /// <inheritdoc />
    protected override StoreType GetStoreType() => StoreType.K8SSecret;

    /// <inheritdoc />
    protected override string[] GetDefaultAllowedKeys() => AllowedKeys.OpaqueKeys;

    /// <inheritdoc />
    protected override string GetSecretTypeFilter() => "Opaque";
}
