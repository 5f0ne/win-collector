# Microsoft Basic System Information Collector NG
#
# Author: 5f-0
#

param($ErrorActionPreference="SilentlyContinue", 
      # Path to write win collector output
      $Output=".\win-collector-ng", 
      # Path for alternate data stream enumeration
      $AdsEnumPath=$env:USERPROFILE,
      # Path for directory / file enumeration
      $FileEnumPath=$env:USERPROFILE,
      # Path for shortcut enumeration
      $LnkEnumPath=$env:USERPROFILE,
      # Enumerates only files with the given file extension in $FileEnumPath. Example: -FileEnumFilters "pdf, docx, png" 
      # If no filters are given (default value), all files in $FileEnumPath are going to be enumerated
      $FileEnumFilters="", 
      # If true, searches for alternate data streams in all files located in $AdsEnumPath
      $EnumerateADS=$false, 
      # If true, enumerates all files to provide a list of file paths located in $FileEnumPath
      $EnumerateFiles=$false,
      # If true, enumerates all shortcuts to provide a list of the shortcut`s target property located in $LnkEnumPath
      $EnumerateShortcuts=$false,
      # If true, enumerate file association in the registry and their associated programm to open it 
      $EnumerateFileAssociation=$false,
      # If true, zip the result files
      $Compress=$false
)

# ---------------------------------------------------------------------------------------------------------

# Functions
function New-OutputFolder {
    param ($OutputPath)
    
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        try {
            New-Item -Path $OutputPath -ItemType Directory -ErrorAction Stop | Out-Null #-Force
        }
        catch {
            Write-Error -Message "Unable to create directory " + $OutputPath + ". Error was: $_" -ErrorAction Stop
        }
        "Successfully created directory " + $OutputPath + "."
    }
    else {
        "Directory already existed"
    }
}

function Get-FilePath {
    param($Path, $FileName)
    return $Path + "\" + $basicInfo + "." + $FileName
}

function Get-Hashes {
    param($Path)
    $Md5 = Get-FileHash -Algorithm MD5 -LiteralPath $Path | Select-Object Hash
    $Sha256 = Get-FileHash -Algorithm SHA256 -LiteralPath $Path  | Select-Object Hash
    $HashValues = New-Object -TypeName PSObject -Property @{
        "FullName" = $Path
        "MD5" = $Md5.Hash
        "SHA256" = $Sha256.Hash
    }
    return $HashValues
}

function Get-RegistryValues {
    param($Path, $KeyName="")
    $result = "No value found!"
    if($KeyName -eq ""){
        $result = Get-ItemProperty $Path
    } else {
        $result = Get-ItemProperty $Path -Name $KeyName
    }
    return $result
}

# ----------------------------------------------------------------------------------------------------------

# Variables
$startDateTime = (Get-Date).ToUniversalTime()
$startDateTimeFormatStr = $startDateTime.ToString("dd-MM-yyyy_HH-mm-ssZ")
$machineName = $env:computername.Replace(" ","_")
$basicInfo = $machineName + "." + $startDateTimeFormatStr

$currentPath = $Output + "\" + $basicInfo

$currentPathPsDir = $currentPath + "\ps"
$currentPathCmdDir = $currentPath + "\cmd"

# ----------------------------------------------------------------------------------------------------------

# Create Directories
New-OutputFolder -OutputPath $currentPath
New-OutputFolder -OutputPath $currentPathPsDir
New-OutputFolder -OutputPath $currentPathCmdDir

# ----------------------------------------------------------------------------------------------------------

# ---> POWERSHELL <---

# ----------------------------------------------------------------------------------------------------------

# Processes 
$p = Get-FilePath -Path $currentPathPsDir -FileName "processes.csv"
Get-CimInstance -Class Win32_Process | Select-Object CreationDate, CSName, ProcessId, ParentProcessId, ProcessName, CommandLine, ExecutablePath | 
    Sort-Object ProcessId | 
    Export-Csv $p -NoTypeInformation

# Processes with usernames
$p = Get-FilePath -Path $currentPathPsDir -FileName "processes-with-usernames.txt"
Get-Process -IncludeUserName | Format-Table -AutoSize | Out-File $p

# File Version for processes
$p = Get-FilePath -Path $currentPathPsDir -FileName "processes-with-fileversion.csv"
Get-Process -FileVersionInfo | Select-Object FileName, FileVersion, CompanyName | Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Network Usage
$p = Get-FilePath -Path $currentPathPsDir -FileName "tcp.csv"
Get-NetTCPConnection | Select-Object State, CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | 
    Export-Csv $p -NoTypeInformation

$p = Get-FilePath -Path $currentPathPsDir -FileName "udp.csv"
Get-NetUDPEndpoint | Select-Object CreationTime, EnabledDefault, RequestedState, TransitioningToState, LocalAddress, LocalPort, OwningProcess | 
    Export-Csv $p -NoTypeInformation

$p = Get-FilePath -Path $currentPathPsDir -FileName "dns-cache.csv"
Get-DnsClientCache | Select-Object Status, Type, Entry, Name, DataLength, Data, TimeToLive | Export-Csv $p -NoTypeInformation

$p = Get-FilePath -Path $currentPathPsDir -FileName "dns-cache-table.txt"
Get-DnsClientCache | Format-Table -AutoSize | Out-File $p

$p = Get-FilePath -Path $currentPathPsDir -FileName "net-route.csv"
Get-NetRoute | Select-Object AddressFamily, State, TypeOfRoute, InterfaceAlias, ifIndex, DestinationPrefix, NextHop, RouteMetric, ifMetric | 
    Export-Csv $p -NoTypeInformation

$p = Get-FilePath -Path $currentPathPsDir -FileName "net-route-table.txt"
Get-NetRoute | Format-Table -AutoSize | Out-File $p

$p = Get-FilePath -Path $currentPathPsDir -FileName "net-adapter.csv"
Get-NetAdapter | Select-Object * | Export-Csv $p -NoTypeInformation

$p = Get-FilePath -Path $currentPathPsDir -FileName "net-adapter-table.txt"
Get-NetAdapter | Format-Table -AutoSize | Out-File $p

# ----------------------------------------------------------------------------------------------------------

# Services
$p = Get-FilePath -Path $currentPathPsDir -FileName "services.csv"
Get-CimInstance -Class Win32_Service | Select-Object Started, State, ProcessId, Name, StartName, Status, PathName, StartMode, ExitCode, Caption, Description | 
    Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Time Zone
$p = Get-FilePath -Path $currentPathPsDir -FileName "time-zone.csv"
Get-TimeZone | Select-Object * | Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Local Users
$p = Get-FilePath -Path $currentPathPsDir -FileName "local-users.csv"
Get-LocalUser | Select-Object Enabled, SID, PrincipalSource, FullName, UserMayChangePassword, PasswordRequired, Name, LastLogon, PasswordChageableDate, PasswordExpires, PasswordLastSet, Description |
     Export-Csv $p -NoTypeInformation

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
        "GroupName" = $_.Name
        "Members" = $memberStr
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

# Get ScheduledTasks Actions from XML Exports
$files = Get-ChildItem -Path $stp -Include *.xml -Recurse

$resultExec = @()
$resultCH = @()
$resultSendMail = @()
$resultShowMsg = @()

ForEach ($file in $files) {
    $xml = [xml](Get-Content $file)
    if ($xml.Task.Actions.Exec) {
        $xml.Task.Actions.Exec | ForEach-Object {
            $obj = New-Object -TypeName PSObject -Property @{     
                "URI"         = $xml.Task.RegistrationInfo.URI
                "Date"        = $xml.Task.RegistrationInfo.Date
                "Author"      = $xml.Task.RegistrationInfo.Author
                "Command"     = $_.Command
                "Arguments"   = $_.Arguments
                "Description" = $xml.Task.RegistrationInfo.Description
            }
            $resultExec += $obj 
        } 
    } 
    if ($xml.Task.Actions.ComHandler) {
        $xml.Task.Actions.ComHandler | ForEach-Object {
            $obj = New-Object -TypeName PSObject -Property @{     
                "URI"         = $xml.Task.RegistrationInfo.URI
                "Date"        = $xml.Task.RegistrationInfo.Date
                "Author"      = $xml.Task.RegistrationInfo.Author
                "ClassId"     = $_.ClassId
                "Data"        = $_.Data
                "Description" = $xml.Task.RegistrationInfo.Description
            }
            $resultCH += $obj 
        } 
    } 
    if ($xml.Task.Actions.SendEmail) {
        $xml.Task.Actions.SendEmail | ForEach-Object {
            $obj = New-Object -TypeName PSObject -Property @{     
                "URI"          = $xml.Task.RegistrationInfo.URI
                "Date"         = $xml.Task.RegistrationInfo.Date
                "Author"       = $xml.Task.RegistrationInfo.Author
                "Server"       = $_.Server
                "Subject"      = $_.Subject
                "To"           = $_.To
                "Cc"           = $_.Cc
                "Bcc"          = $_.Bcc
                "ReplyTo"      = $_.ReplyTo
                "From"         = $_.From
                "HeaderFields" = $_.HeaderFields
                "Body"         = $_.Body
                "Attachments"  = $_.Attachments
                "Description"  = $xml.Task.RegistrationInfo.Description
            }
            $resultSendMail += $obj 
        } 
    } 
    if ($xml.Task.Actions.ShowMessage) {
        $xml.Task.Actions.ShowMessage | ForEach-Object {
            $obj = New-Object -TypeName PSObject -Property @{     
                "URI"          = $xml.Task.RegistrationInfo.URI
                "Date"         = $xml.Task.RegistrationInfo.Date
                "Author"       = $xml.Task.RegistrationInfo.Author
                "Title"       = $_.Title
                "Body"      = $_.Body
                "Description"  = $xml.Task.RegistrationInfo.Description
            }
            $resultShowMsg += $obj 
        } 
    }   
}

if ($resultExec.Length -gt 0) {
    $p = Get-FilePath -Path $currentPathPsDir -FileName "scheduled-tasks-action-exec.csv"
    $resultExec | Select-Object Date, URI, Command, Arguments, Author, Description | Export-Csv $p -NoTypeInformation
}

if ($resultCH.Length -gt 0) {
    $p = Get-FilePath -Path $currentPathPsDir -FileName "scheduled-tasks-action-comhandler.csv"
    $resultCH | Select-Object Date, URI, ClassId, Data, Author, Description | Export-Csv $p -NoTypeInformation
}

if ($resultSendMail.Length -gt 0) {
    $p = Get-FilePath -Path $currentPathPsDir -FileName "scheduled-tasks-action-sendmail.csv"
    $resultSendMail | Select-Object Date, URI, Server, Subject, To, Cc, Bcc, ReplyTo, From, HeaderFields, Body, Author, Description | Export-Csv $p -NoTypeInformation
}

if ($resultShowMsg.Length -gt 0) {
    $p = Get-FilePath -Path $currentPathPsDir -FileName "scheduled-tasks-action-showmsg.csv"
    $resultShowMsg | Select-Object Date, URI, Title, Body, Author, Description | Export-Csv $p -NoTypeInformation
}


# ----------------------------------------------------------------------------------------------------------

# Powershell History
# Finds all powershell files in powershell history standard path
$psHistoryPath = $env:APPDATA + "\Microsoft\Windows\Powershell\PSReadLine"
Get-ChildItem -Path $psHistoryPath -Force | ForEach-Object {
    # if the file name contains spaces they are replaced with underscores
    $fileName = "powershell-history-" + $_.Name.Replace(" ","_")
    $p = Get-FilePath -Path $currentPathPsDir -FileName $fileName
    Get-Content -LiteralPath $_.FullName | Out-File -FilePath $p
}

# ----------------------------------------------------------------------------------------------------------

# WMI Event Filter and Consumer
$p = Get-FilePath -Path $currentPathPsDir -FileName "wmi-event-filter.csv"
Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Select-Object __NAMESPACE, Name, EventNamespace, Query, QueryLanguage  | Export-Csv $p -NoTypeInformation
Get-WMIObject -Namespace root\Default -Class __EventFilter | Select-Object __NAMESPACE, Name, EventNamespace, Query, QueryLanguage  | Export-Csv -Append $p

$p = Get-FilePath -Path $currentPathPsDir -FileName "wmi-event-consumer.csv"
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | 
    Select-Object __NAMESPACE, Name, SourceName, CommandLineTemplate, ExecutablePath, ScriptFilename, ScriptingEngine, ScriptText | Export-Csv $p -NoTypeInformation
Get-WMIObject -Namespace root\Default -Class __EventConsumer | 
    Select-Object __NAMESPACE, Name, SourceName, CommandLineTemplate, ExecutablePath, ScriptFilename, ScriptingEngine, ScriptText | Export-Csv -Append $p

$p = Get-FilePath -Path $currentPathPsDir -FileName "wmi-event-filter-consumer-binding.csv"
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Select-Object __NAMESPACE, Filter, Consumer | Export-Csv $p -NoTypeInformation
Get-WMIObject -Namespace root\Default -Class __FilterToConsumerBinding | Select-Object __NAMESPACE, Filter, Consumer | Export-Csv -Append $p

# ----------------------------------------------------------------------------------------------------------

# Alternate Data Streams (ADS)
if($EnumerateADS){
    $p = Get-FilePath -Path $currentPathPsDir -FileName "alternate-data-streams.csv"
    $ads_content= Get-FilePath -Path $currentPathPsDir -FileName "alternate-data-streams-content.txt"
    $ads_array = @()
    # Iterate over path and get all files with an alternate data stream
    Get-ChildItem -Path $AdsEnumPath -Recurse -Force | Get-Item -Stream * | Where-Object {$_.Stream -ne ":`$DATA"} | ForEach-Object {
        # Extract the content of the alternate data stream and write it to a file as a hexdump
        $filenameAndStream = "`n`n$($_.FileName):$($_.Stream)" 
        $filenameAndStream | Out-File -Append -FilePath $ads_content
        Get-Content -LiteralPath $_.FileName -Stream $_.Stream -Raw | Format-Hex | Out-File -Append -FilePath $ads_content
        $line = "----------------------------------------------------------------------------------------------------------"
        $line | Out-File -Append -FilePath $ads_content
        # Get the filename, stream name and length of the ads
        $obj = New-Object -TypeName PSObject -Property @{
            "FileName" = $_.FileName
            "Stream" = $_.Stream
            "Length" = $_.Length
        }
        $ads_array += $obj
    }
    # Save ADS properties into csv file
    $ads_array | Select-Object Length, FileName, Stream | Export-Csv $p -NoTypeInformation
}

# ----------------------------------------------------------------------------------------------------------

# Get firewall profiles and rules
$p = Get-FilePath -Path $currentPathPsDir -FileName "firewall-profiles.csv"
Get-NetFirewallProfile | Select-Object * | Export-Csv $p -NoTypeInformation

$p = Get-FilePath -Path $currentPathPsDir -FileName "firewall-rules.csv"
Get-NetFirewallRule -All | Select-Object Enabled, Direction, Action, Name, Id, DisplayName, Group, Profile, RuleGroup, StatusCode, Description | Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Out SMB Mappings
$p = Get-FilePath -Path $currentPathPsDir -FileName "smb-mappings.csv"
Get-SmbMapping | Select-Object LocalPath, Status, RemotePath | Export-Csv $p -NoTypeInformation

# SMB Sessions
$p = Get-FilePath -Path $currentPathPsDir -FileName "smb-sessions.csv"
Get-SmbSession -ErrorAction SilentlyContinue | Select-Object * | Export-Csv $p -NoTypeInformation

# SMB Shares
$p = Get-FilePath -Path $currentPathPsDir -FileName "smb-shares.csv"
Get-SmbShare | Select-Object ShareState, ShareType, CurrentUsers, Name, Path, Description, ScopeName | Export-Csv $p -NoTypeInformation

# SMB Share AcLs
$ssa = $currentPathPsDir + "\smb-share-acl"
New-OutputFolder -OutputPath $ssa

$shares = Get-SmbShare 

foreach ($share in $shares){
 
    $result = Get-SmbShareAccess -Name $share.Name

    if($null -ne $result){
        # to have consistent file names, tasknames with spaces are replaced with underscores.
        $taskName = $share.Name.Replace(" ","_")
        $p = Get-FilePath -Path $ssa -FileName ($taskName + ".csv")
        $result | Select-Object AccessCOntrolType, AccessRight, AccountName, Name, ScopeName | Export-Csv $p -NoTypeInformation
    }
}

# ----------------------------------------------------------------------------------------------------------

# Printers
$p = Get-FilePath -Path $currentPathPsDir -FileName "printers.csv"
Get-Printer | Select-Object Name, ComputerName, Type, DriverName, PortName, Shared, Published, DeviceType | Export-Csv $p -NoTypeInformation
    
# ----------------------------------------------------------------------------------------------------------

# Prefetch Files (Requires Admin Privileges)
$p = Get-FilePath -Path $currentPathPsDir -FileName "prefetch-files.csv"
Get-ChildItem "C:\Windows\Prefetch\" -Force -Filter "*.pf" | Select-Object CreationTimeUtc,LastAccessTimeUtc,LastWriteTimeUtc,Length,FullName | 
    Sort-Object -Property CreationTimeUtc -Descending | 
    Export-Csv $p -NoTypeInformation
   
# ----------------------------------------------------------------------------------------------------------

# Event Log: Available Log Files
$p = Get-FilePath -Path $currentPathPsDir -FileName "available-event-logs.csv"
Get-WinEvent -ListLog * -ComputerName localhost | Where-Object { $_.RecordCount } | 
    Select-Object LogMode, RecordCount, LogName, FileSize, LastAccessTime, LastWriteTime, LogFilePath | 
    Sort-Object -Descending -Property RecordCount |
    Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Installed Programms
$p = Get-FilePath -Path $currentPathPsDir -FileName "installed-programms.csv"
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
    Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Installed Hotfixes
$p = Get-FilePath -Path $currentPathPsDir -FileName "hotfixes.csv"
Get-HotFix | Select-Object CSName, Description, HotFixID, InstalledBy, InstalledOn | Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# File Enumeration 
if($EnumerateFiles){
    $p = Get-FilePath -Path $currentPathPsDir -FileName "file-enumeration.csv"
    if($FileEnumFilters -eq "") {
        # Enumerates all files in the fiven path
        Get-ChildItem -Path $FileEnumPath -Recurse -Force | Select-Object -Property Extension, Length, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, FullName | 
        Export-Csv $p -NoTypeInformation
    } else {
        # Enumerates only the files described by the given file extensions
        $filters_ready = @()
        $result = @()
        $filters = $FileEnumFilters.Split(",").trim()
        foreach($f in $filters){
          $filters_ready += "*." + $f
        }
        Get-ChildItem -Path $FileEnumPath -Recurse -Force | Select-Object -Property Extension, Length, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, FullName | ForEach-Object {
            foreach($v in $filters_ready){
                if($_.FullName -Like $v) {
                    $result += $_
                }
            }
        }
        $result | Export-Csv $p -NoTypeInformation
    }    
}

# ----------------------------------------------------------------------------------------------------------

# Shortcut Enumeration 
if($EnumerateShortcuts) {
  $p = Get-FilePath -Path $currentPathPsDir -FileName "shortcut-target-enumeration.csv"
  $result_array = @() 
  Get-ChildItem -Path $LnkEnumPath -Filter *.lnk -Recurse | Get-ItemProperty | ForEach-Object {
      $sh = New-Object -ComObject WScript.Shell
      $target = $sh.CreateShortcut($_.FullName).TargetPath
      $arguments = $sh.CreateShortcut($_.FullName).Arguments
      $obj = New-Object -TypeName PSObject -Property @{
          "Name" = $_.FullName
          "Target" = $target
          "Arguments" = $arguments
      }
      $result_array += $obj
      [Runtime.InteropServices.Marshal]::ReleaseComObject($sh) | Out-Null
  }
  $result_array | Select-Object Name, Target, Arguments | Export-Csv $p -NoTypeInformation
}

# ----------------------------------------------------------------------------------------------------------

# Registry: Keys of Interest
$p = Get-FilePath -Path $currentPathPsDir -FileName "reg-keys-of-interest.txt"

$regKeys = @(@{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
               KeyName = "" },
             @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
               KeyName = "" },
             @{Path = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run"
               KeyName = "" },
             @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
               KeyName = "" },
             @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
               KeyName = "" },
             @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
               KeyName = "" },
             @{Path = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
               KeyName = "" },
             @{Path = "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
               KeyName = "" }
            # -------------------------------------------------------------    
             @{Path = "HKCU:\Environment"
               KeyName = "UserInitMprLogonScript" },
             @{Path = "HKCU:\Control Panel\Desktop"
               KeyName = "SCRNSAVE.EXE" },
            # -------------------------------------------------------------
             @{Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
               KeyName = "" },
             @{Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
               KeyName = "" },
             @{Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
               KeyName = "" },
             @{Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\Services"
               KeyName = "" },
             @{Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\Services\Once"
               KeyName = "" },
             @{Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
               KeyName = "" },
             @{Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
               KeyName = "" },
             @{Path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
               KeyName = "" },
             @{Path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\IniFileMapping\system.ini\boot"
               KeyName = "" },
             @{Path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"
               KeyName = "" },
             @{Path = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
               KeyName = "" }
            # -------------------------------------------------------------
             @{Path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
               KeyName = "AppInit_DLLs" },
             @{Path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
               KeyName = "Userinit" },
             @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
               KeyName = "BootExecute" },
             @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
               KeyName = "KnownDLLs" })

$regKeys | ForEach-Object {
    $result = Get-RegistryValues -Path $_.Path -KeyName $_.KeyName
    $path = $_.Path
    $key = $_.KeyName
    $heading = "`n--> $path $key `n---`n"
    $heading | Out-File -Append -FilePath $p
    $result | Out-File -Append -FilePath $p
    $line = "----------------------------------------------------------------------------------------------------------"
    $line | Out-File -Append -FilePath $p
}

# ----------------------------------------------------------------------------------------------------------

# Registry: File Association

if($EnumerateFileAssociation) {
  $p = Get-FilePath -Path $currentPathPsDir -FileName "file-association-enumeration.csv"
  $command_array = @()

  Get-ChildItem "Registry::HKEY_CLASSES_ROOT\" -Recurse -Force | ForEach-Object {
      if($_.Name.toLower().Contains("shell\open\command")) {
          $path = "Registry::" + $_.Name
          $cmd = (Get-ItemProperty -LiteralPath $path).'(default)'
          $obj = New-Object -TypeName PSObject -Property @{
              "KeyName" = $_.Name
              "Command" = $cmd
          }
          $command_array += $obj
      }
  }
  $command_array | Select-Object KeyName, Command | Export-Csv $p -NoTypeInformation
}

# ----------------------------------------------------------------------------------------------------------

# Autostart Folder
$currentUserAutoStart = $env:APPDATA + "\Microsoft\Windows\Start Menu\Programs\Startup"
$systemAutoStart = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

$p = Get-FilePath -Path $currentPathPsDir -FileName "autostart-folder-current-user.csv"
Get-ChildItem -Path $currentUserAutoStart -Recurse -Force | Select-Object Extension, Length, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, FullName | 
    Export-Csv $p -NoTypeInformation
$p = Get-FilePath -Path $currentPathPsDir -FileName "autostart-folder-system.csv"
Get-ChildItem -Path $systemAutoStart -Recurse -Force | Select-Object Extension, Length, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, FullName | 
    Export-Csv $p -NoTypeInformation

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

# Cached Kerberos Tickets
$p = Get-FilePath -Path $currentPathCmdDir -FileName "cached-kerberos-tickets.txt"
$result = klist
$result | Out-File -FilePath $p

# ----------------------------------------------------------------------------------------------------------

# User  Account Information
$p = Get-FilePath -Path $currentPathCmdDir -FileName "user-account-information.txt"
$result = whoami /all
$result | Out-File -FilePath $p

# ----------------------------------------------------------------------------------------------------------

# Write Execution Time
$endDateTime = (Get-Date).ToUniversalTime()
$endDateTimeFormatStr = $endDateTime.ToString("dd-MM-yyyy_HH-mm-ssZ")

$elapsedTime = $endDateTime - $startDateTime

$p = Get-FilePath -Path $currentPath -FileName "execution-time.txt"

$obj = New-Object -TypeName PSObject -Property @{
    "Duration" = $elapsedTime
    "End" = $endDateTimeFormatStr
    "Start" = $startDateTimeFormatStr
}

$obj | Format-List | Out-File -FilePath $p

# ----------------------------------------------------------------------------------------------------------

# Save error array
$p = Get-FilePath -Path $currentPath -FileName "errors.txt"
$error | Out-File -FilePath $p

# ----------------------------------------------------------------------------------------------------------

# Hash all the files
$files = Get-ChildItem -Recurse $currentPath

$hash_array = @()
foreach ($f in $files){
    $hash_array += Get-Hashes -Path $f.FullName
}

$p = Get-FilePath -Path $currentPath -FileName "hashes.csv"
$hash_array | Select-Object FullName, MD5, SHA256 | Export-Csv $p -NoTypeInformation

# ----------------------------------------------------------------------------------------------------------

# Create an archive
# -> *.compressed.zip is the intermediate zip file which includes 
if($Compress){
    Start-Sleep(5)
    $IntermediateArchive = $Output +  "\" + $basicInfo + ".compressed.zip"
    $currentPathWithoutRoot = $currentPath + "\*"
    Compress-Archive -Path $currentPathWithoutRoot -DestinationPath $IntermediateArchive -Force
    # Hash the intermediate archive
    $hashes = Get-Hashes -Path $IntermediateArchive
    $hash_array = @($hashes)
    $p = Get-FilePath -Path $Output -FileName "hashes.compressed.csv"
    $hash_array | Select-Object FullName, MD5, SHA256 | Export-Csv $p -NoTypeInformation
    # Create final archive
    $finalArchive = $Output +  "\" + $basicInfo + ".compressed.final.zip"
    $archiveConfig = @{
        LiteralPath= $IntermediateArchive, $p
        CompressionLevel = "Optimal"
        DestinationPath = $finalArchive
    }
    Compress-Archive @archiveConfig
    # Hash final archive
    $hashes = Get-Hashes -Path $finalArchive
    $hash_array = @($hashes)
    $p = Get-FilePath -Path $Output -FileName "hashes.compressed.final.csv"
    $hash_array | Select-Object FullName, MD5, SHA256 | Export-Csv $p -NoTypeInformation 
} 