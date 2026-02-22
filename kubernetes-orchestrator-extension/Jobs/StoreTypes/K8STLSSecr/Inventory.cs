// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;
using Keyfactor.Orchestrators.Extensions.Interfaces;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8STLSSecr;

/// <summary>
/// Inventory job for Kubernetes TLS secrets (kubernetes.io/tls type).
/// Discovers certificates stored in tls.crt and tls.key fields.
/// </summary>
public class Inventory : InventoryBase
{
    /// <summary>
    /// Creates a new TLS secret inventory job with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    public Inventory(IPAMSecretResolver resolver) : base(resolver)
    {
    }

    /// <inheritdoc />
    protected override SecretType GetSecretType() => SecretType.Tls;

    /// <inheritdoc />
    protected override StoreType GetStoreType() => StoreType.K8STLSSecr;
}
