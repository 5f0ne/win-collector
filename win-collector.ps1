# Microsoft Basic System Information Collector
#
# Author: 5f-0
#
# Usage: .\win-collector.ps1
# 

# Functions

# Creates the folder containing all generated
# system information documents
# $dir = the path for the directory to be created
function Create-Folder {
    param($dir)
    if (-not (Test-Path -LiteralPath $dir)) {    
        New-Item -Path $dir -ItemType Directory 
    }
}

# Creates the actual file in which the specific system
# information will be stored
# $path = the path + filename of the file to be created
function Create-File {
    param($path)
    if (-not (Test-Path -Path $path)) {    
        New-Item $path 
    }
}

# Writes the fileheader into the specific file
# $path = The path of the file in which the header shall be written
# $headline = The headline of the Header
function Create-FileHeader {
    param($path, $headline)
    "###############################################################################" >> $path
    "# Host: " + $machineName                                                         >> $path
    "# Timestamp: " + (Get-Date -Format "dddd, dd.MM.yyy HH:mm:ss")                   >> $path
    "# "                                                                              >> $path
    "# Topic: " + $headline                                                           >> $path
    "# "                                                                              >> $path
    "###############################################################################" >> $path
}

# Writes a result into a file
# $path = the path to the file
# $text = the text which shall be written
function Format-Output {
    param($path, $text)
   # Add-Content -Path $path -value " " # Newline Workaround
    $text >> $path
}

# Creates the final document for a system information topic
function Create-Document{
    param($dir, $path, $headline, $result)

    Create-Folder -dir $dir

    Create-File -path $path

    Create-FileHeader -path $path -headline $headline

    Format-Output -path $path -text $result
}

# Instructions

# 1. Setup of basic variables

$dateTime = Get-Date -Format "dd-MM-yyyy_HH-mm-ss"
$machineName = $env:computername
$basicInfo = $machineName + "." + $dateTime
$dir = ".\" + $basicInfo


# 2. Get current processes with the user who started the process

$headline = "ProcessInformation"
$path = $dir + "\" + $basicInfo + "_" + $headline + ".txt"

$result += get-process -IncludeUserName
$result += tasklist
$result += tasklist /m
$result += tasklist /svc

Create-Document -dir $dir -path $path -headline $headline -result $result

 
# 3. Get current network connections with the owner

$headline = "NetworkConnections"
$path = $dir + "\" + $basicInfo + "_" + $headline + ".txt"

$result = ""
$result = netstat -nao 
$result += netstat -ab 

Create-Document -dir $dir -path $path -headline $headline -result $result

# 4. Get arp table

$headline = "ARPTable"
$path = $dir + "\" + $basicInfo + "_" + $headline + ".txt"

$result = arp -a 

Create-Document -dir $dir -path $path -headline $headline -result $result

# 5. Get network configuration

$headline = "NetworkConfiguration"
$path = $dir + "\" + $basicInfo + "_" + $headline + ".txt"

$result = ipconfig /all

Create-Document -dir $dir -path $path -headline $headline -result $result

# 6. Get routing table

$headline = "RoutingTable"
$path = $dir + "\" + $basicInfo + "_" + $headline + ".txt"

$result = route print

Create-Document -dir $dir -path $path -headline $headline -result $result

# 7. Get dns info

$headline = "DNSInfo"
$path = $dir + "\" + $basicInfo + "_" + $headline + ".txt"

$result = ipconfig /displaydns

Create-Document -dir $dir -path $path -headline $headline -result $result

# 8. Get system variables

$headline = "SystemVariables"
$path = $dir + "\" + $basicInfo + "_" + $headline + ".txt"

$result = cmd.exe /c set

Create-Document -dir $dir -path $path -headline $headline -result $result

# 9. Get local users

$headline = "LocalUsers"
$path = $dir + "\" + $basicInfo + "_" + $headline + ".txt"

$result = get-localuser | select *

Create-Document -dir $dir -path $path -headline $headline -result $result

# 10. Get network shares

$headline = "NetworkShares"
$path = $dir + "\" + $basicInfo + "_" + $headline + ".txt"

$result = ""
$result = get-wmiobject -query "SELECT * FROM Win32_Share"
$result = net share 

Create-Document -dir $dir -path $path -headline $headline -result $result

# 11. Get systeminfo

$headline = "SystemInfo"
$path = $dir + "\" + $basicInfo + "_" + $headline + ".txt"

$result = systeminfo

Create-Document -dir $dir -path $path -headline $headline -result $result

# 12. Get installed programms

$headline = "InstalledPrograms"
$path = $dir + "\" + $basicInfo + "_" + $headline + ".txt"

$result = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize

Create-Document -dir $dir -path $path -headline $headline -result $result

# Create File Hash Document

$headline = "FileHashes"
$path = $dir + "\" + $basicInfo + "_" + $headline +".txt"

$result = Get-FileHash -Algorithm MD5 -LiteralPath (Get-ChildItem -Path $dir).fullname | Format-List
$result += Get-FileHash -Algorithm SHA256 -LiteralPath (Get-ChildItem -Path $dir).fullname | Format-List

Create-Document -dir $dir -path $path -headline $headline -result $result