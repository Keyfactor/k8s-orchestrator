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

