// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using Unity.Injection;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

class PAMUtilities
{
    internal static string ResolvePAMField(IPAMSecretResolver resolver, ILogger logger, string name, string key)
    {
        logger.LogDebug("Attempting to resolve PAM eligible field '{Name}'", name);
        if (string.IsNullOrEmpty(key))
        {
            logger.LogWarning("PAM field is empty, skipping PAM resolution");
            return key;
        }
        
        // test if field is JSON string
        if (key.StartsWith("{") && key.EndsWith("}"))
        {
            var resolved =  resolver.Resolve(key);
            if (string.IsNullOrEmpty(resolved))
            {
                logger.LogWarning("Failed to resolve PAM field {Name}", name);
            }
            return resolved;
        }
        
        logger.LogDebug("Field '{Name}' is not a JSON string, skipping PAM resolution", name);
        return key;
    }
}
