# Sample Orchestrator Extension

A sample orchestrator with a sample certificate store type for testing and education.

#### Integration status: Pilot - Ready for use in test environments. Not for use in production.

## About the Keyfactor Universal Orchestrator Capability

This repository contains a Universal Orchestrator Capability which is a plugin to the Keyfactor Universal Orchestrator. Within the Keyfactor Platform, Orchestrators are used to manage “certificate stores” &mdash; collections of certificates and roots of trust that are found within and used by various applications.

The Universal Orchestrator is part of the Keyfactor software distribution and is available via the Keyfactor customer portal. For general instructions on installing Capabilities, see the “Keyfactor Command Orchestrator Installation and Configuration Guide” section of the Keyfactor documentation. For configuration details of this specific Capability, see below in this readme.

The Universal Orchestrator is the successor to the Windows Orchestrator. This Capability plugin only works with the Universal Orchestrator and does not work with the Windows Orchestrator.



## Support for Sample Orchestrator Extension

Sample Orchestrator Extension is open source and there is **no SLA** for this tool/library/client. Keyfactor will address issues as resources become available. Keyfactor customers may request escalation by opening up a support ticket through their Keyfactor representative.

###### To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.
___



---




---


## Overview


## Installation and Usage

## Sample Key Store 

## kfutil Commands
For more information on `kfutil` and a full list of commands, see the [kfctl](https://github.com/Keyfactor/kfutil/blob/main/docs/kfutil.md) docs, or type `kfutil --help` after you've installed it.

## kfutil quick install
This will install the latest version of kfutil and add it to your PATH.

### Linux
```bash
curl -s https://raw.githubusercontent.com/Keyfactor/kfutil/main/install.sh | bash
```

### Powershell
```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Keyfactor/kfutil/main/install.ps1'))
```
### Create store types

```bash
kfutil store-types create \
  --name=K8STLSecrt \
  --name=K8SSecret \
  --name=K8SCert
```


