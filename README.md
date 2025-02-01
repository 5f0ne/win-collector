# Description

Collects basic system information on a Windows host with Powershell enabled and saves each information into a file. 

# Usage

`.\win-collector-ng.ps1 -ErrorActionPreference [STRING] -Output [STRING] -EnumPath [STRING] -EnumerateADS [BOOL] -EnumerateFiles [BOOL]`

| Option | Type | Default | Description |
|---|---|---|---|
| $ErrorActionPreference | String | SilentlyContinue | Powershell variable to defined what happens, when an error occur. |
| $Output | String | .\win-collector-ng | Path to write win-collector output |
| $EnumPath | String | $env:USERPROFILE| Path to apply following enumeration tasks |
| $EnumerateADS | Boolean | $false | If true, searches for alternate data streams in all files in $EnumPath |
| $EnumerateFiles | Boolean | $false | If true, enumerates all files to provide a list of file paths in $EnumPath |

# Example

Open Powershell, preferably with admin rights and use:

`.\win-collector-ng.ps1`

Each run of the script create a folder in the directory `win-collector-ng` where the script is located. The folder name consists of:

`[computer name].[datetime]`

Example:

`Laptop1.01-01-1970_10-10-10`

Within the folder, all data are available as `csv` files for the powershell commands. If we need to extract actual content, this content is saved into a `txt` file. For the old commands the output is written to a `txt` file. There is a SHA256 and MD5 hash generated for each file in this folder an saved into a separate file for verification purposes. Additionally all errors from `$error` and information on the execution time is also saved into a `txt` file.

# Data

The following data is collected:

- **Process Information**
  - Get-CimInstance
  - Get-Process -IncludeUserName
  - Get-Process -FileVersionInfo
  - tasklist
- **Network Configuration and Connections**
  - Get-NetTCPConnection
  - Get-NetUDPEndpoint
  - Get-DnsClientCache
  - Get-NetRoute
  - Get-NetAdapter
  - netstat
  - arp -a
  - ipconfig /all
  - route print
  - ipconfig /displaydns
- **Services**
  - Get-CimInstance
- **Local Users**
  - Get-LocalUser
- **Local Groups**
  - Get-LocalGroup
- **Members per Group**
  - Get-LocalGroup
  - Get-LocalGroupMember
- **ScheduledTasks**
  - Get-ScheduledTask
  - Get-ScheduledTaskInfo
  - Export-ScheduledTask
- **WMI**
  - Get-WMIObject
- **Alternate Data Steams**
  - Get-ChildItem
  - Get-Item
  - Get-Content
- **Firewall**
  - Get-NetFirewallProfile
  - Get-NetFirewallRule
- **SMB**
  - Get-SmbMapping
  - Get-SmbSession
  - Get-SmbShare
  - Get-SmbShareAccess
- **Installed Programs**
  - Get-ItemProperty
- **HotFixes**
  - Get-HotFix
- **Files in Home Dir**
  - Get-ChildItem
- **Registry - Run Keys**
  - Get-ItemProperty
- **System Variables**
  - cmd.exe /c set
- **System Information**
  - systeminfo

# License 

MIT