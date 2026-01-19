### Windows Server ###
### Aeven Windows Server Audit Policies
### Author: RRII
### Approver: TBKL
### Date: 2025.06.04
### Version: 1.3
### MET-072

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2018.11.13, OTDU, New Document
### 1.1, 2022.01.13, RRII, Added Windows 2022
### 1.2, 2023.04.18, RRII, Corrected error for pre windows 2022
### 1.3, 2025.06.04, RRII, Added Windows 2025


### Get OS Info
$OS = Get-CimInstance Win32_OperatingSystem | Select Name

### Set Audit Policies for 2022 & 2025
If($OS -like "*2022*" -or $OS -like "*2025*")
{
$Audits= @(
# System
("""Security System Extension"" /success:enable /failure:enable")
("""System Integrity"" /success:enable /failure:enable")
("""IPsec Driver"" /success:enable /failure:enable")
("""Other System Events"" /success:enable /failure:enable")
("""Security State Change"" /success:enable")
# Logon / Logoff
("""Logon"" /success:enable /failure:enable")
("""Logoff"" /success:enable")
("""Account Lockout"" /success:enable /failure:enable")
("""Special Logon"" /success:enable")
("""Other Logon/Logoff Events"" /success:enable /failure:enable")
("""Network Policy Server"" /success:enable /failure:enable")
("""Group Membership"" /success:enable")
# Object Access
("""File System"" /success:enable /failure:enable")
("""Registry"" /success:enable /failure:enable")
("""Kernel Object"" /success:enable /failure:enable")
("""Certification Services"" /success:enable /failure:enable")
("""Application Generated"" /success:enable /failure:enable")
("""File Share"" /success:enable /failure:enable")
("""Detailed File Share"" /success:enable /failure:enable")
("""Other Object Access Events"" /success:enable /failure:enable")
("""Filtering Platform Packet Drop"" /success:enable /failure:enable")
("""Filtering Platform Connection"" /success:enable /failure:enable")
("""Removable Storage"" /success:enable /failure:enable")
# Privilege Use
("""Sensitive Privilege Use"" /success:enable /failure:enable")
# Detailed Tracking
("""Process Creation"" /success:enable")
("""Plug and Play Events"" /success:enable")
# Policy Change
("""Audit Policy Change"" /success:enable /failure:enable")
("""Authentication Policy Change"" /success:enable")
("""Authorization Policy Change"" /success:enable")
("""MPSSVC Rule-Level Policy Change"" /success:enable /failure:enable")
("""Other Policy Change Events"" /failure:enable")
# Account Management
("""Computer Account Management"" /success:enable /failure:enable")
("""Security Group Management"" /success:enable /failure:enable")
("""Application Group Management"" /success:enable /failure:enable")
("""Other Account Management Events"" /success:enable /failure:enable")
("""User Account Management"" /success:enable /failure:enable")
# DS Access
("""Directory Service Access"" /success:enable")
# Account Logon
("""Kerberos Service Ticket Operations"" /success:enable")
("""Kerberos Authentication Service"" /success:enable")
("""Credential Validation"" /success:enable /failure:enable")

)

foreach($Audit in $Audits)
{
#$Audit
$ArgList = "/set /subcategory:" + $Audit
#$ArgList
Start-Process -Wait -FilePath auditpol.exe -Argumentlist $Arglist
}
}

### Set Audit Policies for pre Windows 2022
	Else
	{
$Audits= @(
# System
("""Security System Extension"" /success:enable /failure:enable")
("""System Integrity"" /success:enable /failure:enable")
("""IPsec Driver"" /success:enable /failure:enable")
("""Other System Events"" /success:enable /failure:enable")
("""Security State Change"" /success:enable")
# Logon / Logoff
("""Logon"" /success:enable /failure:enable")
("""Logoff"" /success:enable")
("""Account Lockout"" /success:enable /failure:enable")
("""Special Logon"" /success:enable")
("""Other Logon/Logoff Events"" /success:enable /failure:enable")
("""Network Policy Server"" /success:enable /failure:enable")
("""Group Membership"" /success:enable")
# Object Access
("""File System"" /success:enable /failure:enable")
("""Registry"" /success:enable /failure:enable")
("""Kernel Object"" /success:enable /failure:enable")
("""Certification Services"" /success:enable /failure:enable")
("""Application Generated"" /success:enable /failure:enable")
("""File Share"" /success:enable /failure:enable")
("""Filtering Platform Packet Drop"" /success:disable /failure:disable")
("""Filtering Platform Connection "" /success:disable /failure:disable")
("""Removable Storage"" /success:enable /failure:enable")
# Privilege Use
("""Sensitive Privilege Use"" /success:enable /failure:enable")
# Detailed Tracking
("""Process Creation"" /success:enable")
("""Plug and Play Events"" /success:enable")
# Policy Change
("""Audit Policy Change"" /success:enable /failure:enable")
("""Authentication Policy Change"" /success:enable")
("""Authorization Policy Change"" /success:enable")
# Account Management
("""Computer Account Management"" /success:enable /failure:enable")
("""Security Group Management"" /success:enable /failure:enable")
("""Application Group Management"" /success:enable /failure:enable")
("""Other Account Management Events"" /success:enable /failure:enable")
("""User Account Management"" /success:enable /failure:enable")
# DS Access
("""Directory Service Access"" /success:enable")
# Account Logon
("""Kerberos Service Ticket Operations"" /success:enable")
("""Kerberos Authentication Service"" /success:enable")
("""Credential Validation"" /success:enable /failure:enable")

)

foreach($Audit in $Audits)
{
#$Audit
$ArgList = "/set /subcategory:" + $Audit
#$ArgList
Start-Process -Wait -FilePath auditpol.exe -Argumentlist $Arglist
}
	}
