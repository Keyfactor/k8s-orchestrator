// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Linq;
using Keyfactor.Extensions.Orchestrator.K8S.Constants;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs.Base;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs.StoreTypes.K8SPKCS12;

/// <summary>
/// Discovery job for PKCS12/PFX files in Kubernetes Opaque secrets.
/// Finds secrets containing PKCS12 data in specified namespaces.
/// </summary>
public class Discovery : DiscoveryBase
{
    /// <summary>
    /// Creates a new PKCS12 discovery job with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    public Discovery(IPAMSecretResolver resolver) : base(resolver)
    {
    }

    /// <inheritdoc />
    protected override SecretType GetSecretType() => SecretType.Pkcs12;

    /// <inheritdoc />
    protected override StoreType GetStoreType() => StoreType.K8SPKCS12;

    /// <inheritdoc />
    protected override string[] GetDefaultAllowedKeys() => AllowedKeys.Pkcs12Keys;

    /// <inheritdoc />
    protected override string GetSecretTypeFilter() => "pkcs12";

    /// <inheritdoc />
    protected override string[] GetAllowedKeys(DiscoveryJobConfiguration config)
    {
        // PKCS12 discovery also checks "extensions" and "patterns" properties
        var extensionsKeys = Array.Empty<string>();
        var patternsKeys = Array.Empty<string>();

        if (config.JobProperties != null)
        {
            if (config.JobProperties.TryGetValue("extensions", out var extensionsValue) && extensionsValue != null)
            {
                extensionsKeys = extensionsValue.ToString()?.Split(',') ?? Array.Empty<string>();
            }
            if (config.JobProperties.TryGetValue("patterns", out var patternsValue) && patternsValue != null)
            {
                patternsKeys = patternsValue.ToString()?.Split(',') ?? Array.Empty<string>();
            }
        }

        return extensionsKeys
            .Concat(patternsKeys)
            .Concat(GetDefaultAllowedKeys())
            .Distinct()
            .ToArray();
    }
}
