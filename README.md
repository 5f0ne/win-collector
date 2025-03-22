# Description

Collects basic system information on a Windows host with Powershell enabled and saves each information into a file. 

# Usage

`.\win-collector-ng.ps1 -ErrorActionPreference [STRING] -Output [STRING] -AdsEnumPath [STRING] -FileEnumPath [STRING] -LnkEnumPath [STRING] -FileEnumFilters [STRING] -EnumerateADS [BOOL] -EnumerateFiles [BOOL] -EnumerateShortcuts [BOOL] -EnumerateFileAssociation [BOOL] -Compress [BOOL]`

| Option | Type | Default | Description |
|---|---|---|---|
| -ErrorActionPreference | String | SilentlyContinue | Powershell variable to defined what happens, when an error occur. |
| -Output | String | .\win-collector-ng | Path to write win-collector output |
| -AdsEnumPath | String | $env:USERPROFILE | Path for alternate data stream enumeration |
| -FileEnumPath | String | $env:USERPROFILE | Path for directory / file enumeration |
| -LnkEnumPath | String | $env:USERPROFILE | Path for shortcut enumeration |
| -FileEnumFilters | String | "" | Enumerates only files with the given file extension in $FileEnumPath. Example: -FileEnumFilters "pdf, docx, png". If no filters are given (default value), all files in $FileEnumPath are going to be enumerated |
| -EnumerateADS | Boolean | $false | If true, searches for alternate data streams in all files located in $AdsEnumPath |
| -EnumerateFiles | Boolean | $false | If true, enumerates all files to provide a list of file paths located in $FileEnumPath |
| -EnumerateShortcuts | Boolean | $false | If true, enumerates all shortcuts to provide a list of the shortcut`s target property located in $LnkEnumPath |
| -EnumerateFileAssociation | Boolean | $false | If true, enumerate file association in the registry and their associated programm to open it |
| -Compress | Boolean | $false | If true, an archive of the files is created and hashed |

# Example

Open Powershell, preferably with admin rights and use:

`.\win-collector-ng.ps1`

Each run of the script create a folder in the directory `win-collector-ng` where the script is located. The folder name consists of:

`[computer name].[datetime in UTC]`

Example:

`Laptop1.01-01-1970_10-10-10Z`

Within the folder, all data are available as `csv` files for the powershell commands. If we need to extract actual content, this content is saved into a `txt` file. For the old commands the output is written to a `txt` file. There is a SHA256 and MD5 hash generated for each file in this folder an saved into a separate file for verification purposes. Additionally all errors from `$error` and information on the execution time is also saved into a `txt` file. 

For timezone management please have a look at `win-collector-ng\Laptop1.01-01-1970_10-10-10Z\ps\Laptop1.01-01-1970_10-10-10Z.time-zone.csv` or `win-collector-ng\Laptop1.01-01-1970_10-10-10Z\cmd\Laptop1.01-01-1970_10-10-10Z.systeminfo.txt` where the systems time zone is described. The timestamps in the other files are
in this timezone if not specifically described as UTC timestamps.

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
- **Time Zone**
  - Get-TimeZone
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
- **ScheduledTask Actions**
  - Get-Content
- **Powershell History**
  - Get-ChildItem
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
- **Event Log: Available Log Files**
  - Get-WinEvent
- **Installed Programs**
  - Get-ItemProperty
- **HotFixes**
  - Get-HotFix
- **File Enumeration**
  - Get-ChildItem
- **Shortcut Enumeration**
  - Get-ChildItem
- **Registry: Keys of Interest**
  - Get-ItemProperty
- **Registry: File Association**
  - Get-ChildItem
  - Get-ItemProperty
- **Autostart Folder**
  - Get-ChildItem
- **System Variables**
  - cmd.exe /c set
- **System Information**
  - systeminfo
- **Cached Kerberos Tickets**
  - klist
- **User Account Information**
  - whoami /all

# License 

MIT