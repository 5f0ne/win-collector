# Description

Collects basic system information on a Windows host with Powershell enabled and saves each information into a file. The following information is collected:

- Process Information
- Network Connections
- ARP Table
- Network Configuration
- Routing Table
- DNS Info
- System Variables
- Local Users
- Network Shares
- System Information
- Installed Programs

# Usage

Open Powershell, preferably with admin rights and fire:

`.\win-collector.ps1`

Each run of the script create a folder in the directory where the script is located. The folder name consists of:

`[computer name].[datetime]`

Example:

`Laptop1.01-01-1970_10-10-10`

Within the folder, all generated system information files are available.
There is a SHA256 and MD5 hash generated for each file in this folder an saved into a separate file for verification purposes.

# License 

MIT