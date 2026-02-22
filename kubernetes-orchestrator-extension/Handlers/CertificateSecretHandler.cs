// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using k8s.Autorest;
using Keyfactor.Extensions.Orchestrator.K8S.Clients;
using Keyfactor.Extensions.Orchestrator.K8S.Enums;
using Keyfactor.Extensions.Orchestrator.K8S.Jobs;
using Keyfactor.Extensions.Orchestrator.K8S.Models;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.K8S.Handlers;

/// <summary>
/// Handler for Kubernetes Certificate Signing Requests (CSRs).
/// This is a read-only handler that only supports inventory operations.
/// </summary>
public class CertificateSecretHandler : BaseSecretHandler
{
    /// <summary>
    /// Creates a new CertificateSecretHandler.
    /// </summary>
    /// <param name="logger">Optional logger instance.</param>
    public CertificateSecretHandler(ILogger logger = null) : base(logger)
    {
    }

    /// <inheritdoc />
    public override SecretType SupportedSecretType => SecretType.Certificate;

    /// <inheritdoc />
    public override InventoryResult ProcessInventory(SecretOperationContext context, KubeCertificateManagerClient client)
    {
        LogOperationStart("Inventory", context);

        try
        {
            Logger.LogDebug("Fetching CSR {SecretName}", context.SecretName);
            var certificates = client.GetCertificateSigningRequestStatus(context.SecretName);

            var certsList = certificates?.ToList() ?? new List<string>();
            Logger.LogDebug("CSR inventory returned {Count} certificates", certsList.Count);

            LogOperationComplete("Inventory", context, true);
            return InventoryResult.SuccessWithCertificates(certsList, false);
        }
        catch (HttpOperationException ex) when (ex.Response?.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            Logger.LogWarning("CSR not found: {SecretName}", context.SecretName);
            return InventoryResult.Warning($"CSR '{context.SecretName}' not found");
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error during CSR inventory: {Message}", ex.Message);
            return InventoryResult.Failure($"Error querying Kubernetes CSR API: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public override JobResult ProcessAdd(SecretOperationContext context, K8SJobCertificate certificate, KubeCertificateManagerClient client)
    {
        // CSRs are read-only - cannot add certificates
        const string errorMessage = "ADD operation not supported by Kubernetes CSR type. Use k8s-csr-signer for CSR provisioning.";
        Logger.LogError(errorMessage);
        return FailJob(errorMessage, context.JobHistoryId);
    }

    /// <inheritdoc />
    public override JobResult ProcessRemove(SecretOperationContext context, string alias, KubeCertificateManagerClient client)
    {
        // CSRs are read-only - cannot remove certificates
        const string errorMessage = "REMOVE operation not supported by Kubernetes CSR type.";
        Logger.LogError(errorMessage);
        return FailJob(errorMessage, context.JobHistoryId);
    }
}
