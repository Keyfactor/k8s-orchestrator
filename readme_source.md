## Overview
This is a sample orchestrator extension with a sample key store type.
The main purpose is to provide an easy to install and use orchestrator extension for educational
and testing purposes. The current version supports discovery, inventory, management and reenrollment for the 
custom cert store store type. 

## Installation and Usage
The compiled binaries can be deployed to the extensions folder at the location of the Universal Orchestrator 
installation. However, to get the most use out of this extension, it is recommended to use the Visual Studio project.
You should either install Visual Studio on the machine you run the orchestrator or link the debugger remotely. 
In case you setup Visual Studio locally, you could use a symlink to link the Visual studio output directory to 
the extensions folder, specifically making a subfolder named "SOS". Once this is done and the code is compiled, 
you can attach the Visual Studio debugger to the Universal Orchestrator process for efficient debugging and variable inspection.
The Sample Key Store certificate store type also needs to be added to Keyfactor. The exact settings are available in the install folder
in this repository. This extension is configured to automatically log all incoming data it receives from the Universal Orchestrator.
The log level needs to be set to at least Debug in the Universal Orchestrator settings for this information to appear in the logs.
This data appears as follows"
```
{
	"LastInventory":[],
	"CertificateStoreDetails":
		{
			"ClientMachine":"XXXX","StorePath":"C:\\...\\SampleKeyStore.json","StorePassword":"",
			"Properties":"{\"storeparameter1\":\"SampleKeyStore.json\"}","Type":102
		},
	"JobCancelled":false,
	"ServerError":null,
	"JobHistoryId":423,
	"RequestStatus":1,
	"ServerUsername":null,
	"ServerPassword":null,
	"UseSSL":false,
	"JobProperties":null,
	"JobTypeId":"000",
	"JobId":"0000",
	"Capability":"CertStores.SOS.Inventory"
}

```

## Sample Key Store 
The sample key store exists as a .json file that should be placed locally on the machine where the Universal Orchestrator 
is running. The specific location should not matter, as long as both the extension and the Orchestrator have access permissions to it.
It is not password protected or encrypted for simplicity of use. 
The Sample Key Store has the following structure:
```
{
"storeparameter1": "SampleKeyStore.json",  
	"certs": 
		[    
			{      
				"alias": "abc",      
				"certdata": "def",
        			"privatekey": "ghi",
        			"sampleentryparameter1": "TestParamCert1",      
				"sampleentryparameter2": "TestParam2Cert1"    
			}
    		] 
}
```
Storeparameter1 is currently used to store the store filename. The alias is the cert thumbprint, certdata is a base64 encoded copy of the certificate,
privatekey is the base64 encoded private key string. Sampleentryparameter1 is used to store a list of SANs, which are required for reenrollment in Keyfactor Command.

