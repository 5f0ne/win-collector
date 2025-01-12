# Microsoft Basic System Information Collector NG
#
# Author: 5f-0
#
# Version: 1.0.0
#
# Usage: .\win-collector-ng.ps1 -Output output-dir
# 

param($Output = ".\win-collector-ng")

# ---------------------------------------------------------------------------------------------------------

# Functions

function New-OutputFolder {
    param (
        $OutputPath
    )
    
    if (-not (Test-Path -LiteralPath $OutputPath)) {
    
        try {
            New-Item -Path $OutputPath -ItemType Directory -ErrorAction Stop | Out-Null #-Force
        }
        catch {
            Write-Error -Message "Unable to create directory '$OutputPath'. Error was: $_" -ErrorAction Stop
        }
        "Successfully created directory '$OutputPath'."
    }
    else {
        "Directory already existed"
    }
}

function Get-FilePath {
    param($Path, $FileName)
    return $Path + "\" + $basicInfo + "." + $FileName
}

# ----------------------------------------------------------------------------------------------------------

# Create Directories

$dateTime = Get-Date -Format "dd-MM-yyyy_HH-mm-ss"
$machineName = $env:computername
$basicInfo = $machineName + "." + $dateTime

$currentPath = $Output + "\" + $basicInfo

$currentPathPsDir = $currentPath + "\ps"
$currentPathCmdDir = $currentPath + "\cmd"

New-OutputFolder -OutputPath $currentPath
New-OutputFolder -OutputPath $currentPathPsDir
New-OutputFolder -OutputPath $currentPathCmdDir


# ----------------------------------------------------------------------------------------------------------

# ---> POWERSHELL <---

# ----------------------------------------------------------------------------------------------------------

# Processes 

$p = Get-FilePath -Path $currentPathPsDir -FileName "processes.csv"
Get-CimInstance -Class Win32_Process | Select-Object ProcessName, CreationDate, CSName, ProcessId, ParentProcessId, CommandLine | Export-Csv $p -NoTypeInformation

# Processes with usernames

$p = Get-FilePath -Path $currentPathPsDir -FileName "processes-with-usernames.txt"
Get-Process -IncludeUserName | Format-Table -AutoSize | Out-File $p

# File Version for processes
$p = Get-FilePath -Path $currentPathPsDir -FileName "processes-with-fileversion.csv"
Get-Process -FileVersionInfo | Select-Object FileName, FileVersion, CompanyName | Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Network Usage

$p = Get-FilePath -Path $currentPathPsDir -FileName "tcp.csv"
Get-NetTCPConnection | Select-Object State, CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Export-Csv $p -NoTypeInformation

$p = Get-FilePath -Path $currentPathPsDir -FileName "udp.csv"
Get-NetUDPEndpoint | Select-Object CreationTime, EnabledDefault, RequestedState, TransitioningToState, LocalAddress, LocalPort, OwningProcess | Export-Csv $p -NoTypeInformation

$p = Get-FilePath -Path $currentPathPsDir -FileName "dns-cache.csv"
Get-DnsClientCache | Select-Object Status, Type, Entry, Name, DataLength, Data, TimeToLive | Export-Csv $p -NoTypeInformation

$p = Get-FilePath -Path $currentPathPsDir -FileName "dns-cache-table.txt"
Get-DnsClientCache | Format-Table -AutoSize | Out-File $p

$p = Get-FilePath -Path $currentPathPsDir -FileName "net-route.csv"
Get-NetRoute | Select-Object AddressFamily, State, TypeOfRoute, InterfaceAlias, ifIndex, DestinationPrefix, NextHop, RouteMetric, ifMetric | Export-Csv $p -NoTypeInformation

$p = Get-FilePath -Path $currentPathPsDir -FileName "net-route-table.txt"
Get-NetRoute | Format-Table -AutoSize | Out-File $p

$p = Get-FilePath -Path $currentPathPsDir -FileName "net-adapter.csv"
Get-NetAdapter | Select-Object * | Export-Csv $p -NoTypeInformation

$p = Get-FilePath -Path $currentPathPsDir -FileName "net-adapter-table.txt"
Get-NetAdapter | Format-Table -AutoSize | Out-File $p


# ----------------------------------------------------------------------------------------------------------

# Services

$p = Get-FilePath -Path $currentPathPsDir -FileName "services.csv"
Get-CimInstance -Class Win32_Service | Select-Object Started, State, ProcessId, Name, StartName, Status, PathName, StartMode, ExitCode, Caption, Description | Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Local Users

$p = Get-FilePath -Path $currentPathPsDir -FileName "local-users.csv"
Get-LocalUser | Select-Object Enabled, SID, PrincipalSource, FullName, UserMayChangePassword, PasswordRequired, Name,  LastLogon, PasswordChageableDate, PasswordExpires, PasswordLastSet, Description | Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Local Groups
$p = Get-FilePath -Path $currentPathPsDir -FileName "local-groups.csv"
Get-LocalGroup | Select-Object PrincipalSource, SID, Name, Description | Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Get Members for each group
$groupMembersList = @()

# Get all local groups
Get-LocalGroup | Select-Object Name | ForEach-Object { 
    # Get the name of each local group to request group members
    $members = Get-LocalGroupMember $_.Name 

    # $memberString is the string in which all member names get appended for the specific group
    $memberStr = ""
    $members | ForEach-Object{ $memberStr += $_.Name + " | " }

    # The final object with the group name / member mapping is created
    $obj = New-Object -TypeName PSObject -Property @{     
        'GroupName' = $_.Name
        'Members' = $memberStr
    }
    $groupMembersList += $obj 
}


$p = Get-FilePath -Path $currentPathPsDir -FileName "local-group-members.csv"
$groupMembersList | Select-Object GroupName, Members  | Export-Csv $p -NoTypeInformation


# ----------------------------------------------------------------------------------------------------------

# Scheduled Tasks

$p = Get-FilePath -Path $currentPathPsDir -FileName "scheduled-tasks.csv"
Get-ScheduledTask | Select-Object State, Author, Date, TaskName, TaskPath, URI, Description | Export-Csv $p -NoTypeInformation


$p = Get-FilePath -Path $currentPathPsDir -FileName "scheduled-tasks-info.csv"
Get-ScheduledTask | Get-ScheduledTaskInfo | Select-Object TaskName, TaskPath, LastTaskResult, LastRunTime, NextRunTime | Export-Csv $p -NoTypeInformation

# Create ScheduledTask exports

$stp = $currentPathPsDir + "\scheduled-tasks-export"
New-OutputFolder -OutputPath $stp

$tasks = Get-ScheduledTask 

foreach ($task in $tasks){
 
    $result =  Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath

    if($null -ne $result){
        # to have consistent file names, tasknames with spaces are replaced with underscores.
        $taskName = $task.TaskName.Replace(" ","_")
        $result | Out-File -FilePath ($stp + "\" + $basicInfo + "." + $taskName + ".xml")
    }
}


# ----------------------------------------------------------------------------------------------------------

# Get firewall profiles and rules


$p = Get-FilePath -Path $currentPathPsDir -FileName "firewall-profiles.csv"
Get-NetFirewallProfile | Select-Object * | Export-Csv $p -NoTypeInformation


$p = Get-FilePath -Path $currentPathPsDir -FileName "firewall-rules.csv"
Get-NetFirewallRule -All | Select-Object Enabled, Direction, Action, Name, Id, DisplayName, Group, Profile, RuleGroup, StatusCode, Description  | Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Network Shares
$p = Get-FilePath -Path $currentPathPsDir -FileName "network-shares.csv"
Get-WmiObject -query "SELECT * FROM Win32_Share"  | Select-Object Name, Path, Description  | Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Installed Programms
$p = Get-FilePath -Path $currentPathPsDir -FileName "installed-programms.csv"
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Installed Hotfixes
$p = Get-FilePath -Path $currentPathPsDir -FileName "hotfixes.csv"
Get-HotFix | Select-Object CSName, Description, HotFixID, InstalledBy, InstalledOn | Export-Csv $p -NoTypeInformation


# ----------------------------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------

# ---> CMD <---

# ----------------------------------------------------------------------------------------------------------

# tasklist - Get loaded dlls for processes
$p = Get-FilePath -Path $currentPathCmdDir -FileName "tasklist.txt"
$result =  tasklist /m
$result | Out-File -FilePath $p

# ----------------------------------------------------------------------------------------------------------

# network usage - netstat / arp / ipconfig / route / dns

$p = Get-FilePath -Path $currentPathCmdDir -FileName "netstat.txt"
$result = netstat -nao 
$result += " "
$result += netstat -ab 
$result | Out-File -FilePath $p

$p = Get-FilePath -Path $currentPathCmdDir -FileName "arp.txt"
$result = arp -a
$result | Out-File -FilePath $p

$p = Get-FilePath -Path $currentPathCmdDir -FileName "ipconfig.txt"
$result = ipconfig /all 
$result | Out-File -FilePath $p

$p = Get-FilePath -Path $currentPathCmdDir -FileName "route.txt"
$result = route print 
$result | Out-File -FilePath $p

$p = Get-FilePath -Path $currentPathCmdDir -FileName "dns.txt"
$result = ipconfig /displaydns 
$result | Out-File -FilePath $p


# ----------------------------------------------------------------------------------------------------------

# System Variables

$p = Get-FilePath -Path $currentPathCmdDir -FileName "system-variables.txt"
$result = cmd.exe /c set 
$result | Out-File -FilePath $p

# ----------------------------------------------------------------------------------------------------------

# System Info

$p = Get-FilePath -Path $currentPathCmdDir -FileName "system-info.txt"
$result = systeminfo
$result | Out-File -FilePath $p


# ----------------------------------------------------------------------------------------------------------

# Hash all the files

$files = Get-ChildItem -Recurse $currentPath

$hash_array = @()
foreach ($f in $files){
    $md5 = Get-FileHash -Algorithm MD5 -LiteralPath $f.FullName | Select-Object Hash
    $sha256 = Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName | Select-Object Hash
    $obj = New-Object -TypeName PSObject -Property @{
        "FullName" = $f.FullName
        "MD5" = $md5.Hash
        "SHA256" = $sha256.Hash
    }
    $hash_array += $obj
}

$p = Get-FilePath -Path $currentPath -FileName "hashes.csv"
$hash_array | Select-Object FullName, MD5, SHA256 | Export-Csv $p -NoTypeInformation