// Copyright 2024 Keyfactor                                                   
// Licensed under the Apache License, Version 2.0 (the "License"); you may    
// not use this file except in compliance with the License.  You may obtain a 
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless 
// required by applicable law or agreed to in writing, software distributed   
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   
// OR CONDITIONS OF ANY KIND, either express or implied. See the License for  
// the specific language governing permissions and limitations under the       
// License.

using System;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.Orchestrator.K8S.Jobs;

/// <summary>
/// Re-enrollment job implementation for Kubernetes certificate stores.
/// This job type is intended to:
/// 1) Generate a new public/private keypair locally
/// 2) Generate a CSR from the keypair
/// 3) Submit the CSR to Keyfactor Command to enroll the certificate
/// 4) Deploy the newly re-enrolled certificate to a certificate store
/// </summary>
/// <remarks>
/// NOTE: Re-enrollment is not currently implemented for Kubernetes stores.
/// This class provides a placeholder that returns a failure indicating
/// the operation is not supported.
/// </remarks>
[Obsolete("Use store-type-specific reenrollment classes in Jobs.StoreTypes.* namespace instead. This class will be removed in a future version.")]
public class Reenrollment : JobBase, IReenrollmentJobExtension
{
    /// <summary>
    /// Initializes a new instance of the Reenrollment job with the specified PAM resolver.
    /// </summary>
    /// <param name="resolver">PAM secret resolver for credential retrieval.</param>
    public Reenrollment(IPAMSecretResolver resolver)
    {
        _resolver = resolver;
    }

    /// <summary>
    /// Main entry point for the reenrollment job.
    /// Currently not implemented - returns a failure result.
    /// </summary>
    /// <param name="config">Reenrollment job configuration.</param>
    /// <param name="submitReenrollment">Callback delegate to submit CSR for enrollment.</param>
    /// <returns>JobResult indicating failure (not implemented).</returns>
    /// <remarks>
    /// Future implementation should:
    /// 1. Generate keypair using BouncyCastle
    /// 2. Create CSR with appropriate subject and extensions
    /// 3. Submit CSR via submitReenrollment callback
    /// 4. Receive enrolled certificate and deploy to store
    /// </remarks>
    public JobResult ProcessJob(ReenrollmentJobConfiguration config, SubmitReenrollmentCSR submitReenrollment)
    {
        Logger = LogHandler.GetClassLogger(GetType());
        Logger.MethodEntry(MsLogLevel.Debug);
        Logger.LogDebug("Processing reenrollment job {JobId} for capability {Capability}", config.JobId, config.Capability);

        Logger.LogTrace("Server: {Server}", config.CertificateStoreDetails.ClientMachine);
        Logger.LogTrace("Store Path: {StorePath}", config.CertificateStoreDetails.StorePath);

        // Re-enrollment is not implemented for Kubernetes stores
        Logger.LogWarning("Re-enrollment not implemented for {Capability}", config.Capability);
        Logger.MethodExit(MsLogLevel.Debug);
        return FailJob($"Re-enrollment not implemented for {config.Capability}", config.JobHistoryId);
    }
}

//var kpGenerator = new RsaKeyPairGenerator();
//kpGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
//var kp = kpGenerator.GenerateKeyPair();

//var key = kp;

//Dictionary<DerObjectIdentifier, string> values = CreateSubjectValues("myname");

//var subject = new X509Name(values.Keys.Reverse().ToList(), values);

//GeneralName name = new GeneralName(GeneralName.DnsName, "a1.example.ca");
//X509ExtensionsGenerator extGen = new X509ExtensionsGenerator();

//extGen.AddExtension(X509Extensions.SubjectAlternativeName, false, name);
//extGen.Generate()

// Potential solution with bouncycastle - non functional due to lack of BC csr builder in c#.
//var attributes = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, converted);
//attributes.

//var pkcs10Csr = new Pkcs10CertificationRequest(
//"SHA512withRSA",
//subject,
//key.Public,
//converted,
//key.Private);

//byte[] derEncoded = pkcs10Csr.GetDerEncoded();

//RSA rsa = RSA.Create(2048);
//var csr = new CertificateRequest(
//  new X500DistinguishedName("CN=myname"),
//rsa,
//HashAlgorithmName.SHA256,
//RSASignaturePadding.Pkcs1).CreateSigningRequest();
