// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

internal class PAMUtilities
{
    internal static string ResolvePAMField(IPAMSecretResolver resolver, ILogger logger, string name, string key)
    {
        logger.LogDebug("Attempting to resolve PAM eligible field '{Name}'", name);
        logger.LogTrace("Resolver is null: {IsNull}", resolver == null);
        logger.LogTrace("Key is null: {IsNull}", key == null);

        if (string.IsNullOrEmpty(key))
        {
            logger.LogWarning("PAM field is empty, skipping PAM resolution");
            return key;
        }

        // test if field is JSON string
        if (key.StartsWith("{") && key.EndsWith("}"))
        {
            try
            {
                logger.LogTrace("Calling resolver.Resolve() for field '{Name}'", name);
                var resolved = resolver.Resolve(key);
                logger.LogTrace("Resolver returned: {HasValue}", !string.IsNullOrEmpty(resolved));
                if (string.IsNullOrEmpty(resolved)) logger.LogWarning("Failed to resolve PAM field {Name}", name);
                return resolved;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "PAM resolution failed for field '{Name}': {Message}", name, ex.Message);
            }
        }

        logger.LogDebug("Field '{Name}' is not a JSON string, skipping PAM resolution", name);
        return key;
    }
}