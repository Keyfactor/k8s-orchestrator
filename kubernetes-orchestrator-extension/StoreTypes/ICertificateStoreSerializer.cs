// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace Keyfactor.Extensions.Orchestrator.K8S.StoreTypes
{
    public abstract class CertificateStoreSerializer
    {
        protected CertificateStoreSerializer(byte[] storeContent, string storePassword, string storePath = null)
        {
            Logger = LogHandler.GetClassLogger(GetType());
            Logger.MethodEntry();
            StoreContent = storeContent;
            StorePassword = storePassword;
            StorePath = storePath;
            Logger.MethodExit();
        }

        protected readonly ILogger Logger;
        public string StorePath { get; set; }
        public byte[] StoreContent { get; }
        public string StorePassword { get; }

        public abstract T Deserialize<T>(byte[] storeContents = null, string storePassword = null)
            where T : CertificateStoreSerializer;

        public abstract byte[] Serialize();
        public abstract void Create();
        public abstract void Update();
        public abstract void Delete();
    }
}