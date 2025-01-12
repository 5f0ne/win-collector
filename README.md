# Description

Collects basic system information on a Windows host with Powershell enabled and saves each information into a file. The following information is collected:

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
- **Firewall**
  - Get-NetFirewallProfile
  - Get-NetFirewallRule
- **Services**
  - Get-CimInstance
- **ScheduledTasks**
  - Get-ScheduledTask
  - Get-ScheduledTaskInfo
  - Export-ScheduledTask
- **System Variables**
  - cmd.exe /c set
- **Local Users**
  - Get-LocalUser
- **Local Groups**
  - Get-LocalGroup
- **Members per Group**
  - Get-LocalGroup
  - Get-LocalGroupMember
- **Network Shares**
  - Get-WmiObject
- **System Information**
  - systeminfo
- **Installed Programs**
  - Get-ItemProperty
- **HotFixes**
  - Get-HotFix

# Usage

Open Powershell, preferably with admin rights and use:

`.\win-collector-ng.ps1 -Output win-collector`

Each run of the script create a folder in the directory `win-collector` where the script is located. The folder name consists of:

`[computer name].[datetime]`

Example:

`Laptop1.01-01-1970_10-10-10`

Within the folder, all generated system information are available as `csv` files for the powershell commands. For the old
commands the output is written to a `txt` file.

There is a SHA256 and MD5 hash generated for each file in this folder an saved into a separate file for verification purposes.

# License 

MIT