########################################################################################################################
########################################################################################################################
### NNIT_Windows_Server_Audit ###
### Audit-Script
### Author: RRII
### Approver: MLSJ
### Date: 2022.03.10
### Version: 1.3.1
### PRD-089

param ([bool]$AntiVirus=$true,$Backup=$true,$Monitoring=$true,$FireWall=$true,$HPUD=$True,$HPSA=$True,$License=$True,$Policies=$True)

### Changelog ###
### Version, Date, Initials, Change Description, Approver
### 1.0, 2019.05.24, OTDU, New Script, CRR Approver TBKL
### 1.1, 2020.09.01, TBKL, Added possibility for exceptions in checks ###
### 1.2, 2020.11.27, TBKL, Codereview ITINC0009975444 ###
### 1.3, 2022.02.28, RRII, Added Windows 2022, CodeReview ITINC0012296142 ###
$ChangeLog = "### 1.3.1, 2022.03.10, RRII, Minor - Add pylibs3 directory check of HP-SA ###"


########################################################################################################################
########################################################################################################################
### Module Start ###
### Prepare Audit Report ###
### Audit-Script
### Author: OTDU
### Approver: TBKL
### Date: 2019.06.21
### Version: 1.1
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module
### 1.1, 2019.06.21, OTDU, Removed duplicated array initilization

###
### Audit Summary
###

### Set ExitCode for failed
$Exitcode = 1


### Prepare results
$AuditResults = [System.Collections.ArrayList]@()
$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()
$sysinfo = Get-Ciminstance -Class Win32_ComputerSystem
$OSInfo = Get-Ciminstance -Class Win32_OperatingSystem | Select-Object Caption, Version, InstallDate | Format-List
$DomainJoined = $sysinfo.PartOfDomain
$Date = Get-Date | Select-Object DateTime

### Prepare the Audit report info ###
$path = "C:\temp"
If(!(test-path $path))
{
      New-Item -ItemType Directory -Force -Path $path
}
$computerName = (Get-Ciminstance -Class Win32_ComputerSystem -Property DNSHostName).DNSHostName + "." + $sysinfo.Domain
$fDate = (Get-Date).tostring("yyy-MM-dd")
$fileName = $computerName + "-" + $fDate + "-Audit-Report.log"
$fileNameInfo = $computerName + "-" + $fDate + "-Audit-Info.log"
$AuditReport = "C:\Temp\" + $fileName
$AuditReportInfo = "C:\Temp\" + $fileNameInfo

### Prepare text for Audit Report ###

$textForReport.Add("############################################################") | Out-Null
$textForReport.Add("### Windows Server Default deployment settings Audit #######") | Out-Null
$textForReport.Add("############################################################") | Out-Null
$textForReport.Add("### Report Result ##########################################") | Out-Null
$textForReport.Add("############################################################") | Out-Null
$textForReport.Add("### Validation script version and last changelog ###########") | Out-Null
$textForReport.Add("############################################################") | Out-Null
$textForReport.Add($Changelog) | Out-Null
$textForReport.Add("############################################################") | Out-Null
$textForReport.Add("Server name: "+ $computerName) | Out-Null
$textForReport.Add($Date) | Out-Null
$textForReport.Add($OSInfo) | Out-Null
$textForReport.Add("############################################################") | Out-Null
$textForReport.Add("### Audit summary ##########################################") | Out-Null
$textForReport.Add("############################################################") | Out-Null
$textForReport.Add("") | Out-Null

$textForReport | out-file $AuditReport

$textForReportInfo.Add("############################################################") | Out-Null
$textForReportInfo.Add("### Windows Server Default deployment settings Audit #######") | Out-Null
$textForReportInfo.Add("############################################################") | Out-Null
$textForReportInfo.Add("### Report Info ############################################") | Out-Null
$textForReportInfo.Add("############################################################") | Out-Null
$textForReportInfo.Add("### Validation script version and last changelog ###########") | Out-Null
$textForReportInfo.Add("############################################################") | Out-Null
$textForReportInfo.Add($Changelog) | Out-Null
$textForReportInfo.Add("############################################################") | Out-Null
$textForReportInfo.Add("Server name: "+ $computerName) | Out-Null
$textForReportInfo.Add($Date) | Out-Null
$textForReportInfo.Add($OSInfo) | Out-Null
$textForReportInfo.Add("############################################################") | Out-Null
$textForReportInfo.Add("### Audit Info #############################################") | Out-Null
$textForReportInfo.Add("############################################################") | Out-Null
$textForReportInfo.Add("") | Out-Null

$textForReportInfo | out-file $AuditReportInfo

if(Test-Path $AuditReport)
{
    $AuditReport + " Created successfully"
}
else
{
    "Failed: " + $AuditReport + " was not created"
}

if(Test-Path $AuditReportInfo)
{
    $AuditReportInfo + " Created successfully"
}
else
{
    "Failed: " + $AuditReportInfo + " was not created"
}

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### Windows Server Installed After New Deployment settings ###
### Audit-Script
### Author: OTDU
### Approver: TBKL
### Date: 2019.05.24
### Version: 1.0
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module

$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()

$textForReportInfo.Add("## Starting Windows Server Installed After New Deployment settings ##") | Out-Null

If(Test-Path -Path HKLM:\Software\NNIT\Deployed_with\NNIT_Deployment_Settings_for_Windows_Servers)
{
	$resultDeploymentSettings = "## OK ## This Server is deployed using[NNIT_Deployment_Settings_for_Windows_Servers]"
	$textForReportInfo.Add("## OK ## This Server is deployed using the Software Policy [NNIT_Deployment_Settings_for_Windows_Servers]") | Out-Null
	$textForReport.Add("## OK ## This Server is deployed using the Software Policy [NNIT_Deployment_Settings_for_Windows_Servers]") | Out-Null
}

Else
{
	$resultDeploymentSettings = "## OK Info ## This Server is not deployed using[NNIT_Deployment_Settings_for_Windows_Servers]"
	$textForReport.Add("## OK Info ## This Server is not deployed using the Software Policy [NNIT_Deployment_Settings_for_Windows_Servers]") | Out-Null
	$textForReportInfo.Add("## OK Info ## This Server is not deployed using the Software Policy [NNIT_Deployment_Settings_for_Windows_Servers]") | Out-Null
}

$textForReportInfo.Add("") | Out-Null
$textForReport | out-file $AuditReport -Append
$textForReportInfo | out-file $AuditReportInfo -Append

$AuditResults.Add($resultDeploymentSettings) | Out-Null

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### System Info and Updated History ###
### Audit Module
### Author: OTDU
### Approver: TBKL
### Date: 2019.05.24
### Version: 1.0
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module

$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()

### Collect system info ###
function Get-SystemInfo
{
  param($ComputerName = $env:ComputerName)

      $header = 'Hostname','OSName','OSVersion','OSManufacturer','OSConfig','Buildtype', 'RegisteredOwner','RegisteredOrganization','ProductID','InstallDate', 'StartTime','Manufacturer','Model','Type','Processor','BIOSVersion', 'WindowsFolder' ,'SystemFolder','StartDevice','Culture', 'UICulture', 'TimeZone','PhysicalMemory', 'AvailablePhysicalMemory' , 'MaxVirtualMemory', 'AvailableVirtualMemory','UsedVirtualMemory','PagingFile','Domain' ,'LogonServer','Hotfix','NetworkAdapter'
      systeminfo.exe /FO CSV /S $ComputerName |
      Select-Object -Skip 1 |
      ConvertFrom-CSV -Header $header
}

$SystemInfo = Get-SystemInfo

### Collect Update History ###
$UpdateHistory = get-ciminstance -class win32_quickfixengineering | format-table -AutoSize

### Get Disk info ###
$DiskInfo = Get-Disk | format-list

### Get Extended Disk info ###
$ExtendedDiskInfo = Get-Disk |Select-Object "FriendlyName", "Manufacturer", "DiskNumber", "HealthStatus", "BusType", "FirmwareVersion", "PhysicalSectorSize", "LogicalSectorSize", "Model", "NumberOfPartitions", "OperationalStatus", "PartitionStyle", "Location", "Path", "ProvisioningType", "SerialNumber", "Is*"

$textForReportInfo.Add("###########################") | Out-Null
$textForReportInfo.Add("System Information") | Out-Null
$textForReportInfo.Add($SystemInfo) | Out-Null
$textForReportInfo.Add("###########################") | Out-Null
$textForReportInfo.Add("Update History") | Out-Null
$textForReportInfo.Add($UpdateHistory) | Out-Null
$textForReportInfo.Add("###########################") | Out-Null
$textForReportInfo.Add("Disk Information") | Out-Null
$textForReportInfo.Add($DiskInfo) | Out-Null
$textForReportInfo.Add("###########################") | Out-Null
$textForReportInfo.Add("Extended Disk Information") | Out-Null
$textForReportInfo.Add($ExtendedDiskInfo) | Out-Null
$textForReportInfo.Add("###########################") | Out-Null
$textForReportInfo.Add("") | Out-Null

$textForReportInfo | out-file $AuditReportInfo -Append

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### Firewalls Enabled ###
### Audit Module
### Author: OTDU
### Approver: TBKL
### Date: 2020.07.04
### Version: 1.1
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module
### 1.1. 2020.07.04, TBKL, Add option to accept failure of check


$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()

$textForReportInfo.Add("## Starting Firewall Enabled ##") | Out-Null

### Check firewall status ###

$firewallStateTrue = Get-NetFirewallProfile | Select-Object Enabled, Name | where-object Enabled -EQ True
$firewallStateFalse = Get-NetFirewallProfile | Select-Object Enabled, Name | where-object Enabled -EQ False

if($firewallStateTrue -Match "True" -and $firewallStateFalse -notcontains "False")
{
    $resultFirewallEnabled = "## OK ## Firewalls are all enabled"
    $textForReport.Add("## OK ## Firewalls are all enabled") | Out-Null
    $textForReportInfo.Add("## Firewalls Enabled Info ##") | Out-Null
    $textForReportInfo.Add($firewallStateTrue) | Out-Null
}
if($firewallStateFalse -Match "False" -and -not $Firewall)
{
    $resultFirewallEnabled = "## OK ## all Firewalls are not enabled. Not required."
    $textForReport.Add("## Failed ## all Firewalls are not enabled. Not required.") | Out-Null
    $textForReportInfo.Add("## Firewall Enabled Info ##") | Out-Null
    $textForReportInfo.Add($firewallStateFalse) | Out-Null
}
elseif($firewallStateFalse -Match "False")
{
    $resultFirewallEnabled = "## Failed ## all Firewalls are not enabled"
    $textForReport.Add("## Failed ## all Firewalls are not enabled") | Out-Null
    $textForReportInfo.Add("## Firewall Enabled Info ##") | Out-Null
    $textForReportInfo.Add($firewallStateFalse) | Out-Null
}

$textForReportInfo.Add("") | Out-Null
$textForReport | out-file $AuditReport -Append
$textForReportInfo | out-file $AuditReportInfo -Append

$AuditResults.Add($resultFirewallEnabled) | Out-Null

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### Firewalls Disabled ###
### Audit Module
### Author: RRII
### Approver: TBKL
### Date: 2022.02.02
### Version: 1.2
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module
### 1.1. 2020.07.04, TBKL, Add option to accept failure of check
### 1.2. 2022.02.02, RRII, Server 2022 aware

$OS = Get-CimInstance Win32_OperatingSystem

$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()

$textForReportInfo.Add("## Starting Firewall Disabled ##") | Out-Null

### Firewall Rules disabled in MSR for Windows 2022
If($OS -like "*2022*")
{
$EnabledFirewallRules = [System.Collections.ArrayList]@()
$EnabledFirewallRules += Get-NetFirewallRule -DisplayName "Cast to Device functionality*" | where-object -Property "Enabled" -eq -value "True" | Select-Object DisplayName, Enabled
$EnabledFirewallRules += Get-NetFirewallRule -Group "@{Microsoft Edge*" | where-object -Property "Enabled" -eq -value "True" | Select-Object DisplayName, Enabled
$EnabledFirewallRules += Get-NetFirewallRule -DisplayName "Alljoyn Router*" | where-object -Property "Enabled" -eq -value "True" | Select-Object DisplayName, Enabled
$EnabledFirewallRules += Get-NetFirewallRule -Group "DiagTrack*" | where-object -Property "Enabled" -eq -value "True" | Select-Object DisplayName, Enabled
}
### Firewall Rules disabled in MSR for pre Windows 2022
    Else
    {
$EnabledFirewallRules = [System.Collections.ArrayList]@()
$EnabledFirewallRules += Get-NetFirewallRule -DisplayName "Cast to Device functionality*" | where-object -Property "Enabled" -eq -value "True" | Select-Object DisplayName, Enabled
$EnabledFirewallRules += Get-NetFirewallRule -Group "@{Microsoft.Windows.Cortana*" | where-object -Property "Enabled" -eq -value "True" | Select-Object DisplayName, Enabled
$EnabledFirewallRules += Get-NetFirewallRule -DisplayName "Alljoyn Router*" | where-object -Property "Enabled" -eq -value "True" | Select-Object DisplayName, Enabled
$EnabledFirewallRules += Get-NetFirewallRule -Group "DiagTrack*" | where-object -Property "Enabled" -eq -value "True" | Select-Object DisplayName, Enabled
$EnabledFirewallRules += Get-NetFirewallRule -Group "@{Microsoft.XboxGame*" | where-object -Property "Enabled" -eq -value "True" | Select-Object DisplayName, Enabled
    }

If([string]::IsNullOrEmpty($EnabledFirewallRules))
{
    $resultFirewallRules = "## OK ## Firewall Rules are disabled"
    $textForReport.Add("## OK ## Firewall Rules are disabled") | Out-Null
    $textForReportInfo.Add("## OK ## Firewall Rules are disabled") | Out-Null
}
Elseif (-not $firewall)
{
    $resultFirewallRules = "## OK ## Not all Firewall Rules are disabled. Not required."
    $textForReport.Add("## OK ## Not all Firewall Rules are disabled. Not required.") | Out-Null
    $textForReportInfo.Add($EnabledFirewallRules) | Out-Null
}

Else
{
    $resultFirewallRules = "## Failed ## Not all Firewall Rules are disabled, Check Audit-Info.log for more information"
    $textForReport.Add("## Failed ## Not all Firewall Rules are disabled, Check Audit-Info.log for more information") | Out-Null
    $textForReportInfo.Add($EnabledFirewallRules) | Out-Null
}

$textForReportInfo.Add("") | Out-Null
$textForReport | out-file $AuditReport -Append
$textForReportInfo | out-file $AuditReportInfo -Append

$AuditResults.Add($resultFirewallRules) | Out-Null

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### Services Startup status ###
### Audit Module
### Author: RRII
### Approver: TBKL
### Date: 2022.02.02
### Version: 1.2
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module
### 1.1, 2019.07.04, OTDU, Server 2019 aware
### 1.2, 2022.02.02, RRII, Server 2022 aware


$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()

$OS = Get-CimInstance Win32_OperatingSystem

### Load List of Services for Server 2022
$Services2022= @(
"Spooler"
"DiagTrack"
"dmwappushservice"
"PcaSvc"
"WiaRpc"
"QWAVE"
"lfsvc"
"bthserv"
"AJRouter"
"RmSvc"
"SCardSvr"
"ScDeviceEnum"
"SCPolicySvc"
"Themes"
"TabletInputService"
"WalletService"
"Audiosrv"
"AudioEndpointBuilder"
"WbioSrvc"
"FrameServer"
"FrameServerMonitor"
"stisvc"
"wisvc"
"TapiSrv"
"WerSvc"
"RemoteRegistry"
"LicenseManager"
"wercplsupport"
"RasAuto"
"RasMan"
"SharedAccess"
"MapsBroker"
"McpManagementService"
)

### Load List of Services for Server 2019
$Services2019= @(
"Spooler"
"DiagTrack"
"dmwappushservice"
"PcaSvc"
"WiaRpc"
"QWAVE"
"lfsvc"
"bthserv"
"AJRouter"
"RmSvc"
"SCardSvr"
"ScDeviceEnum"
"SCPolicySvc"
"Themes"
"TabletInputService"
"WalletService"
"Audiosrv"
"AudioEndpointBuilder"
"WbioSrvc"
"FrameServer"
"stisvc"
"wisvc"
"TapiSrv"
"icssvc"
"WerSvc"
"RemoteRegistry"
"LicenseManager"
"wercplsupport"
"RasAuto"
"RasMan"
"PhoneSvc"
"SharedAccess"
"MapsBroker"
)

### Load List of Services for Server 2016
$Services2016= @(
"Spooler"
"DiagTrack"
"dmwappushservice"
"PcaSvc"
"WiaRpc"
"QWAVE"
"lfsvc"
"bthserv"
"AJRouter"
"RmSvc"
"SCardSvr"
"ScDeviceEnum"
"SCPolicySvc"
"Themes"
"TabletInputService"
"WalletService"
"Audiosrv"
"AudioEndpointBuilder"
"WbioSrvc"
"FrameServer"
"stisvc"
"wisvc"
"XblAuthManager"
"XblGameSave"
"TapiSrv"
"icssvc"
"WerSvc"
"RemoteRegistry"
"LicenseManager"
"wercplsupport"
"RasAuto"
"RasMan"
"PhoneSvc"
"SharedAccess"
"MapsBroker"
)

### Load List of Services for Server 2012
$Services2012= @(
"Spooler"
"SCardSvr"
"Themes"
"Audiosrv"
"AudioEndpointBuilder"
"TapiSrv"
"WerSvc"
"wercplsupport"
"RasAuto"
"RasMan"
"SharedAccess"
)

### Create arrays
$ServiceStateOk = @()
$ServiceStateNotOk = @()

### Go through all services disabled in MSR, add services where Startup State is Disabled to $ServiceStateOK and if not add to $ServiceStateNotOk

if($OS -like "*2012*")
{
	foreach($Service in $Services2012)
	{
		$ServiceState = sc.exe qc $Service

		if($ServiceState -like "*DISABLED*")
		{
        		$ServiceStateOk += $Service
    		}
    		Else
    		{
        		$ServiceStateNotOk += $Service
    		}
	}
}

if($OS -like "*2016*")
{
	foreach($Service in $Services2016)
	{
		$ServiceState = Get-Service $Service | Select-Object StartType -ExpandProperty StartType

		if($ServiceState -eq "Disabled")
		{
        		$ServiceStateOk += $Service
		}
		Else
		{
        		$ServiceStateNotOk += $Service
		}
	}

}

if($OS -like "*2019*")
{
	foreach($Service in $Services2019)
	{
		$ServiceState = Get-Service $Service | Select-Object StartType -ExpandProperty StartType

		if($ServiceState -eq "Disabled")
		{
        		$ServiceStateOk += $Service
		}
		Else
		{
        		$ServiceStateNotOk += $Service
		}
	}

}

if($OS -like "*2022*")
{
	foreach($Service in $Services2022)
	{
		$ServiceState = Get-Service $Service | Select-Object StartType -ExpandProperty StartType

		if($ServiceState -eq "Disabled")
		{
        		$ServiceStateOk += $Service
		}
		Else
		{
        		$ServiceStateNotOk += $Service
		}
	}

}


If([string]::IsNullOrEmpty($ServiceStateNotOk))
{
    $textForReport = "## OK ## Service Startup State: OK"
}
Else
{
    $textForReport = "## OK Info ## Service Startup State: Not disabled on all services, Check Audit-Info.log for more information"
}

$textForReportInfo.Add("") | Out-Null
$textForReportInfo.Add("Services State Ok") | Out-Null
$textForReportInfo.Add($ServiceStateOk) | Out-Null
$textForReportInfo.Add("Services State NOT Ok") | Out-Null
$textForReportInfo.Add($ServiceStateNotOk) | Out-Null
$textForReport | out-file $AuditReport -Append
$textForReportInfo | out-file $AuditReportInfo -Append

$AuditResults.Add($textForReport) | Out-Null

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### Licens Status ###
### Audit Module
### Author: OTDU
### Approver: TBKL
### Date: 2019.05.24
### Version: 1.0
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module
### 1.1. 2020.07.04, TBKL, Add option to accept failure of check

$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()

$textForReportInfo.Add("## Starting Licens Status ##") | Out-Null

$licenseStatusValue = Get-CimInstance -ClassName SoftwareLicensingProduct | where-object {$_.PartialProductKey} | Select-Object Description, LicenseStatus
$licenseStatus = $licenseStatusValue | Where-Object { $_.licenseStatus -match "1" -and $_.Description -match "Windows"}

if($licenseStatus -match "Windows")
{
    $resultLicense = "## OK ## Server is licensed"
    $textForReport.Add("## OK ## Server is licensed") | Out-Null
    $textForReportInfo.Add($licenseStatus) | Out-Null
}
elseif (-not $License)
{
    $resultLicense = "## OK ## no licenses found. Not required."
    $textForReport.Add("## OK ## no licenses found. Not required.") | Out-Null
    $textForReportInfo.Add($licenseStatusValue) | Out-Null
}
else
{
    $resultLicense = "## Failed ## no licenses found"
    $textForReport.Add("## Failed ## no licenses found") | Out-Null
    $textForReportInfo.Add($licenseStatusValue) | Out-Null
}

$textForReportInfo.Add("") | Out-Null
$textForReport | out-file $AuditReport -Append
$textForReportInfo | out-file $AuditReportInfo -Append

$AuditResults.Add($resultLicense) | Out-Null

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### Get Installed Software ###
### Audit Module
### Author: OTDU
### Approver: TBKL
### Date: 2019.05.24
### Version: 1.0
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module

$InstalledSoftware = [System.Collections.ArrayList]@()
$SoftwareWow6462 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion
$Software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion

foreach($Line in $Software)
{
    $InstalledSoftware.Add($line) | Out-Null
}
foreach($Line in $SoftwareWow6462)
{
    $InstalledSoftware.Add($line) | Out-Null
}

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### HP SA Agent ###
### Audit Module
### Author: RRII
### Approver: CLIR
### Date: 2022.03.10
### Version: 1.2
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module
### 1.1. 2020.07.04, TBKL, Add option to accept failure of check
### 1.2. 2022.03.10, RRII, Add pylibs3 directory check

$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()

$textForReportInfo.Add("## Starting HP SA Agent ##") | Out-Null

$installedHPSA = $InstalledSoftware | where-object DisplayName -Like "*SA Agent*"

if($installedHPSA -match "SA agent" -and (Test-Path -Path "HKLM:\software\Opsware\agent"))
{
    $checkInstallDirValue = Get-ItemProperty -Path "HKLM:\software\Opsware\agent" -Name "InstallDir"
    $installDir = $checkInstallDirValue.InstallDir

    $HPSAexeDir = $installDir + "\pylibs\cog"
    if(Test-Path $HPSAexeDir)
    {
        set-location $HPSAexeDir
        $HPSAstatus = Invoke-command {.\bs_min_hardware.bat}
    }
	else
	{
		$HPSAexeDir = $installDir + "\pylibs3\cog"
    if(Test-Path $HPSAexeDir)
		{
        set-location $HPSAexeDir
        $HPSAstatus = Invoke-command {.\bs_min_hardware.bat}
		}
	}

    if($HPSAstatus -match "Opsware machine ID :")
    {
        $textForReport.Add("## OK ## HPSA Agent Installed") | Out-Null
        $textForReportInfo.Add($installedHPSA) | Out-Null
        $resultHPSA = "## OK ## Installed and Connected to HPSA"
        $textForReport.Add("## OK ## Connected to HPSA") | Out-Null
        $textForReportInfo.Add($HPSAstatus) | Out-Null
    }
    else
    {
    $textForReport = "## Failed ## HPSA Agent installed but not connected to HPSA Infrastructure, Check Audit-Info.log for more information"
    $resultHPSA = "## Failed ## HPSA Agent installed but not connected to HPSA Infrastructure"
    $textForReportInfo.Add($installedHPSA) | Out-Null
    $textForReportInfo.Add($HPSAstatus) | Out-Null
    }

}
elseif (-not $HPSA)
{
    $resultHPSA = "## OK ## HP SA is NOT Installed. Not required."
    $textForReport = "## Failed ## HP SA is not Installed. Not required."
}
else
{
    $resultHPSA = "## Failed ## HP SA is NOT Installed"
    $textForReport = "## Failed ## HP SA is not Installed"
}

$textForReportInfo.Add("") | Out-Null
$textForReport | out-file $AuditReport -Append
$textForReportInfo | out-file $AuditReportInfo -Append

$AuditResults.Add($resultHPSA) | Out-Null

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### HP UD Agent ###
### Audit Module
### Author: OTDU
### Approver: TBKL
### Date: 2019.05.24
### Version: 1.0
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module
### 1.1. 2020.07.04, TBKL, Add option to accept failure of check

$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()

$textForReportInfo.Add("## Starting HP UD Agent ##") | Out-Null

$installedHPUD = $InstalledSoftware | where-object DisplayName -Like "*Universal Discovery*"

$serviceRunning = Get-Service -Name "*DiscAgent*" | Out-String

if($installedHPUD -match "Universal Discovery")
{
    if($serviceRunning -match "Running")
    {
        $textForReport.Add("## OK ## HPUD Agent Installed") | Out-Null
        $textForReportInfo.Add($installedHPUD) | Out-Null
        $resultHPUD = "## OK ## HPUD Agent Installed and Service is running"
        $textForReport.Add("## OK ## HPUD Service is running") | Out-Null
        $textForReportInfo.Add($serviceRunning) | Out-Null
    }
    else
    {
        $textForReport.Add("## Failed ## HPUD Agent installed but the service is not running, Check Audit-Info.log for more information") | Out-Null
        $textForReportInfo.Add($installedHPUD) | Out-Null
    }
}
elseif (-not $HPUD)
{
    	$resultHPUD = "## OK ## HP UD NOT Installed. Not required."
    	$textForReport.Add("## OK ## HP UD NOT Installed. Not required.") | Out-Null
	$textForReportInfo.Add("## OK ## HP UD NOT Installed. Not required.") | Out-Null
}
else
{
    	$resultHPUD = "## Failed ## HP UD NOT Installed"
    	$textForReport.Add("## Failed ## HP UD NOT Installed") | Out-Null
	$textForReportInfo.Add("## Failed ## HP UD NOT Installed") | Out-Null
}

$textForReportInfo.Add("") | Out-Null
$textForReport | out-file $AuditReport -Append
$textForReportInfo | out-file $AuditReportInfo -Append

$AuditResults.Add($resultHPUD) | Out-Null

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### Monitoring Agent ###
### Audit Module
### Author: OTDU
### Approver: TBKL
### Date: 2019.05.24
### Version: 1.1
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module
### 1.1, 2019.06.19, OTDU, Support for Microsoft SCOM added
### 1.2, 2020.07.04, TBKL, Add option to accept failure of check
### 1.3, 2021.03.26, TBKL, Correction to policy check from CLVE
### 1.4, 2021.04.12, TBKL, Correction to policy check from CLIR

$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()

$textForReportInfo.Add("## Starting Monitoring Agent ##") | Out-Null

$installedHPOM = $InstalledSoftware | where-object DisplayName -Like "*Operations-agent*"

if($installedHPOM -match "Operations-agent" -and (Test-Path -Path "HKLM:\software\Hewlett-Packard\HP Openview"))
{
    $HPOMexeDirMsga = "C:\Program Files\HP\HP BTO Software\lbin\eaagt"
    $HPOMexeDirOv = "C:\Program Files\HP\HP BTO Software\bin\win64"
    if(Test-Path $HPOMexeDirMsga)
    {
        set-location  $HPOMexeDirMsga
        $HPOMstatus = Invoke-command {.\opcmsga.exe -status}
        $HPOMinstalled = "True"
    }

    if(Test-Path $HPOMexeDirOv)
    {
        set-location  $HPOMexeDirOv
        # Get the OM manager for the current host
        $HPOMmanager = Invoke-command {.\ovconfget.exe sec.core.auth MANAGER}
      #  $HPOMPolicy = Invoke-command {.\ovpolicy.exe -l}
      #  $NoOfPolicies = ($HPOMPolicy | where-object {$_.Contains( "enabled")}|measure-object).Count
    }
    #If manager is set check if we can talk to the manager from the client.
    if($HPOMmanager -match "ad.nss.nnit.com" -or $HPOMmanager -match "nnithosting.com")
    {
        #Run bbcutil -ping to check communication to manager
        set-location  $HPOMexeDirOv
        $bbcutil =Invoke-command {.\bbcutil -ping $HPOMmanager}
        if($bbcutil -match "eServiceOK") {
	        $HPOMinstalled = "True"
        	$textForReport.Add("## OK ## HPOM Installed and Connected to OM manager $HPOMmanager") | Out-Null
            	$resultMonOMCon = "## OK ## HPOM Installed and Connected to OM manager $HPOMmanager"
            	$textForReportInfo.Add("HPOM Installed and Connected to HPOM") | Out-Null
	        $textForReportInfo.Add($installedHPOM) | Out-Null
        }
        else
        {
            $textForReport.Add("## Failed ## Not connected to OM manager $HPOMmanager, Check Audit-Info.log for more information") | Out-Null
            $resultMonOM = "## Failed ## Not connected to OM manager $HPOMmanager, Check Audit-Info.log for more information"
            $textForReportInfo.Add($HPOMstatus) | Out-Null
           # $textForReportInfo.Add($HPOMPolicy) | Out-Null
        }
    }
    else
    {
        $textForReport.Add("## Failed ## Not connected to OM manager not set, Check Audit-Info.log for more information") | Out-Null
        $resultMonOM = "## Failed ## Not connected to OM manager not set, Check Audit-Info.log for more information"
        $textForReportInfo.Add($HPOMstatus) | Out-Null
       # $textForReportInfo.Add($HPOMPolicy) | Out-Null
    }

}

$installedSCOM = $InstalledSoftware | where-object DisplayName -Like "*Microsoft Monitoring Agent*"
#$serviceSCOM = Get-Service -DisplayName "Microsoft Monitoring Agent" | where-object Status -eq "Running"
if($installedSCOM -match "Monitoring Agent" -and  $null -ne (Get-Service -DisplayName "Microsoft Monitoring Agent" | where-object Status -eq "Running") )
{
	$lastTimeWritten = [System.Collections.ArrayList]@()
	$WrittenDate = Get-EventLog -LogName "Operations Manager" -Newest 1 -InstanceId 6022 | Select-Object TimeWritten | format-table -HideTableHeaders | Out-String
	$lastTimeWritten.add($WrittenDate) | Out-String

	foreach($line in $lastTimeWritten)
	{
	    if($null -ne $line ){$RealLastWritten = $line }
	}

	if($RealLastWritten -match $cDate)
	{
		$SCOMinstalled = "True"
		$textForReportInfo.Add("## OK ## SCOM installed and status OK") | Out-Null
		$textForReportInfo.Add("## SCOM installed: " + $installedSCOM + " and status OK" + $RealLastWritten) | Out-Null
		$resultMonSCOM = "## OK ## SCOM installed and status OK"
	}
	else
	{
		$textForReport.Add("## SCOM installed: " + $installedSCOM + " and status NOT OK") | Out-Null
		$resultMonSCOM = "SCOM installed: " + $installedSCOM + " and status NOT OK"
		$textForReportInfo.Add("## Last status: " + $RealLastWritten) | Out-Null
		$resultMonSCOM = "Last status: " + $RealLastWritten
	}
}
if($HPOMinstalled -notmatch "True" -and $SCOMinstalled -notmatch "True" -and -not $monitoring)
{
	$resultMon = "## OK ## No monitoring Installed. Not required."
	$textForReport.Add("## OK ## Monitoring NOT Installed. Not required.") | Out-Null
	$textForReportInfo.Add("## OK ## Monitoring NOT InstalledNot required.") | Out-Null
}
elseif($HPOMinstalled -notmatch "True" -and $SCOMinstalled -notmatch "True")
{
	$resultMon = "## Failed ## No monitoring Installed"
	$textForReport.Add("## Failed ## Monitoring NOT Installed, Check Audit-Info.log for more information") | Out-Null
	$textForReportInfo.Add("## Failed ## Monitoring NOT Installed, Check Audit-Info.log for more information") | Out-Null
}

If($HPOMinstalled -like "True"){$resultMon = $ResultMonOMCon + "`r`n" + $ResultMonOMPol + $ResultMonOM}
If($SCOMinstalled -like "True"){$resultMon = $ResultMonSCOM}
$textForReportInfo.Add("") | Out-Null
$textForReport | out-file $AuditReport -Append
$textForReportInfo | out-file $AuditReportInfo -Append

$AuditResults.Add($resultMon) | Out-Null

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### VMware Tools ###
### Audit Module
### Author: OTDU
### Approver: TBKL
### Date: 2019.05.24
### Version: 1.0
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module
### 1.1, 2019.10.03, TBKL, Machine type changed from "Virtual" to "VMWare Virtual" to avoid failed check for other virtual platforms

$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()

$textForReportInfo.Add("## Starting VMware Tools ##") | Out-Null

Function Get-MachineType
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # ComputerName
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string[]]$ComputerName=$env:COMPUTERNAME
    )

    Begin
    {
    }
    Process
    {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Checking $Computer"
            try {
                $ComputerSystemInfo = Get-CIMInstance -Class Win32_ComputerSystem  -ErrorAction Stop
                switch ($ComputerSystemInfo.Model) {

                    # Check for Hyper-V Machine Type
                    "Virtual Machine" {
                        $MachineType="VM"
                        }

                    # Check for VMware Machine Type
                    "VMware Virtual Platform" {
                        $MachineType="VM"
                        }

                    # Check for Oracle VM Machine Type
                    "VirtualBox" {
                        $MachineType="VM"
                        }

                    # Check for Xen
                    # I need the values for the Model for which to check.

                    # Check for KVM
                    # I need the values for the Model for which to check.

                    # Otherwise it is a physical Box
                    default {
                        $MachineType="Physical"
                        }
                    }

                # Building MachineTypeInfo Object
                $MachineTypeInfo = New-Object -TypeName PSObject -Property ([ordered]@{
                    ComputerName=$ComputerSystemInfo.PSComputername
                    Type=$MachineType
                    Manufacturer=$ComputerSystemInfo.Manufacturer
                    Model=$ComputerSystemInfo.Model
                    })
                $MachineTypeInfo
                }
            catch [Exception] {
                Write-Output "$Computer`: $($_.Exception.Message)"
                }
            }
    }
    End
    {

    }
}

$machineType = Get-MachineType

if($machineType -match "Physical")
{
	$textForReport.Add("## OK ## Machine is Physical, hardware found ##") | Out-Null
	$textForReportInfo.Add($machineType) | Out-Null
	$resultVmtools = "## OK ## Machine is Physical, hardware found ##"
}

if($machineType -match "VMWare Virtual")
{
	$installedVMtools = $InstalledSoftware | where-object DisplayName -Like "*vmware tools*" | format-table -HideTableHeaders | Out-String

	if($installedVMtools -match "vmware tools")
	{
    		$resultVmtools = "## OK ## Machine is virtual, VMware Tools installed ##"
        	$textForReport.Add("## OK ## Machine is virtual, VMware Tools installed ##") | Out-Null
        	$textForReportInfo.Add($installedVMtools) | Out-Null
	}
	else
	{
		$resultVmtools = "## Failed ## Machine is a VMware Vm but, No VMware Tools found"
	    	$textForReport.Add("## Failed ## Machine is a VMware Vm but, No VMware Tools found") | Out-Null
		$textForReportInfo.Add("## Failed ## Machine is a VMware Vm but, No VMware Tools found") | Out-Null
	}
}

$textForReportInfo.Add("") | Out-Null
$textForReport | out-file $AuditReport -Append
$textForReportInfo | out-file $AuditReportInfo -Append

$AuditResults.Add($resultVmtools) | Out-Null

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### AV installeret ###
### Audit Module
### Author: OTDU
### Approver: TBKL
### Date: 2019.06.21
### Version: 1.0
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module
### 1.1, 2019.06.21, OTDU, Support added for Mcafee Agent(Newest version of Mcafee Enterprise)
### 1.2, 2019.10.04, TBKL, Support added for Trend Micro
### 1.3, 2019.11.06, TBKL, Section for Trend Micro corrected to account for different date formats
### 1.4. 2020.07.04, TBKL, Add option to accept failure of check
### 1.5. 2020.11.26, TBKL, Check for ePO server configuration added
### 1.6, 2021.20.09, TBKL, Cisco check modified to support latest version

$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()

$textForReportInfo.Add("## Starting AV Installed script ##") | Out-Null

$installedAV = $InstalledSoftware | Where-Object { $_.DisplayName -like "*Enterprise*" -or $_.DisplayName -like "*Endpoint*" -or $_.DisplayName -like "*Cisco AMP*"  -or $_.DisplayName -like "*Traps*" -or $_.DisplayName -like "*McAfee Agent*" -or $_.DisplayName -like "*Trend Micro*" } | format-table -HideTableHeaders | Out-String

if (-not $InstalledAV)
{
    $found = (get-service -name WinDefend -ErrorAction Ignore | where {$_.Status -eq "Running"}| Measure-Object).Count
    if ($found -eq 1)
    {
        $InstalledAV = "Microsoft Defender"
    }
}

if($installedAV -match "Traps" -and (Test-Path -Path "HKLM:\SOFTWARE\Palo Alto Networks\Traps"))
{
	$hostname=$(hostname)
    $filepath = Get-ChildItem -Path "C:\ProgramData\Cyvera\Logs\Service_$hostname.log"
	$file = Get-Content $filepath.FullName
	#$contains = $file | %{$_ -match "Is content up to date: True "}
    $contains = $file | ForEach-Object{$_ -match "Is content up to date: True "}

	If($contains -contains $true)
	{
	    $textForReport.Add("## OK ## Antivirus in active mode") | Out-Null
		$resultAV = "## OK ## Cyvera Installed and connected to server"
	}
	Else
	{
		$textForReport.Add("## Failed ## Antivirus not connected") | Out-Null
		$resultAV = "## Failed(Info) ## Cyvera Installed but not connected"
		$textForReportInfo = "## Failed(Info) ## Cyvera Installed but not connected"
	}


}

if($installedAV -match "Enterprise" -and (Test-Path -Path HKLM:\SOFTWARE\Wow6432Node\McAfee\AVEngine))
{
    $mcafeeEnterpriseInstalled = $installedAV
    $checkValue = Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\McAfee\AVEngine -Name "AVDatDate"
    $avDatDate = $checkValue.AVDatDate

    $avDatDate = $avDatDate.Replace("/", "-")
    $checkDate = (get-date).AddDays(-2).ToString("yyy/MM/dd") | Out-Null

    if ($avDatDate -ge $checkDate)
    {
        $resultAV = "## OK ## Mcafee Enterprise Installed and updated."
        $textForReport.Add("## OK ## Mcafee Enterprise Installed and updated.") | Out-Null
        $textForReportInfo.Add($mcafeeEnterpriseInstalled + "last updated " + $avDatDate) | Out-Null
    }
    else
    {
	    $resultAV = "## OK(Info) ## Installed but not updated within the last 2 days, last updated."
        $textForReport.Add("## OK(Info) ## Installed but not updated within the last 2 days, last updated " + $avavDatDate ) | Out-Null
        $textForReportInfo.Add($mcafeeEnterpriseInstalled + "Installed but not updated within the last 2 days, last updated " + $avavDatDate ) | Out-Null
    }
}

if($installedAV -match "Endpoint" -and (Test-Path -Path HKLM:\SOFTWARE\McAfee\AVSolution\DS\DS))
{
    $mcafeeEndpointinstalled = $installedAV
    $checkValue = Get-ItemProperty -Path HKLM:\SOFTWARE\McAfee\AVSolution\DS\DS -Name "szContentCreationDate"
    $avCreationDate = $checkValue.szContentCreationDate

    $checkDate = (get-date).AddDays(-2).ToString("yyy/MM/dd") | Out-Null

    if ($avCreationDate -ge $checkDate)
    {
        $resultAV = "## OK ## Mcafee Endpoint Installed and updated. ePO configuration" + $ePOServer
        $textForReport.Add("## OK ## Mcafee Endpoint Installed and updated. ePO configuration - " + $ePOServer) | Out-Null
        $textForReportInfo.Add($mcafeeEndpointinstalled + "last updated " + $avCreationDate + ". ePO configuration - " + $ePOServer) | Out-Null
    }

    else
    {
        $resultAV = "## OK(Info) ## Installed but not updated within the last 2 days, last updated "
	    $textForReport.Add("## OK(Info) ## Installed but not updated within the last 2 days, last updated") | Out-Null
        $textForReportInfo.Add($mcafeeEndpointinstalled + "Installed but not updated within the last 2 days, last updated " + $avCreationDate) | Out-Null
    }

}

if($installedAV -match "McAfee Agent" -and (Test-Path -Path "C:\ProgramData\McAfee\Common Framework\UpdateHistory.ini"))
{
    $mcafeeAgentinstalled = $installedAV
    $checkValue = Get-Content -Path "C:\ProgramData\McAfee\Common Framework\UpdateHistory.ini" | Where-Object{$_ -match "LastUpdateCatalogVersion"} | Out-String
    $checkValue = $checkValue.Split("=")
    $checkValue = $checkValue[1]
    $avCreationDate = $checkValue.Substring(0,$checkValue.Length-8)

    $checkDate = (get-date).AddDays(-2).ToString("yyyMMdd")

    if ($avCreationDate -ge $checkDate)
    {

        $resultAV = "## OK ## Mcafee Agent installed and updated"
        $textForReport.Add("## OK ## Mcafee Agent Installed and updated") | Out-Null
        $textForReportInfo.Add($mcafeeAgentinstalled + "last updated " + $avCreationDate) | Out-Null
    }

    else
    {
        $resultAV = "## OK(Info) ## Mcafee Agent installed but not updated within the last 2 days, last updated "
	$textForReport.Add("## OK(Info) ## Mcafee Agent installed but not updated within the last 2 days, last updated") | Out-Null
        $textForReportInfo.Add($mcafeeAgentinstalled + "Installed but not updated within the last 2 days, last updated " + $avCreationDate) | Out-Null
    }

}

if(($installedAV -match "Cisco AMP" -or $installedAV -match "Cisco Secure Endpoint") -and (Test-Path -Path "C:\Program Files\Cisco\AMP\policy.xml"))
{
	$CiscoAMPinstalled = $installedAV

	$filepath = Get-ChildItem -Path "C:\Program Files\Cisco\AMP\policy.xml"
	$file = Get-Content $filepath.FullName

	$containsProtect = $file | foreach-object{$_ -match "Protect"}
	$containsAudit = $file | foreach-object{$_ -match "Audit"}
	If($containsProtect -contains $true)
	{
	    	$textForReport.Add("## OK ## Antivirus in active [Protect] mode") | Out-Null
	}
	ElseIf($containsAudit -contains $true)
	{
		$textForReport.Add("## Failed ## Antivirus is installed but in inactive [Audit] mode") | Out-Null
	}

	### Get Current date and AV defenition date ###
	$virusDef = Get-ChildItem -Path "C:\Program Files\Cisco\AMP\tetra\versions.dat.*" | Where-object {$_.LastWriteTime -gt (Get-Date).AddDays(-3)}
	$virusDefDate = Get-ChildItem -Path "C:\Program Files\Cisco\AMP\tetra\versions.dat.*" | Select-Object "LastWriteTime"
	If($null -ne $virusDef )
	{
		$resultAV = "## OK ## Cisco AMP Installed and updated, last updated " + $virusDefDate
		$CiscoAMPInfo
		$textForReport.Add("## OK ## Cisco AMP Installed and updated") | Out-Null
		$CiscoAMPInfo = $CiscoAMPinstalled + "last updated " + $virusDefDate
		$textForReportInfo.add( $CiscoAMPInfo) | Out-Null
	}
	Else
	{
	        $resultAV = "## Failed(Info) ## Cisco AMP Installed but not updated within the last 3 days, last updated "
		$textForReport.Add("## OK(Info) ## Cisco AMP Installed but not updated within the last 3 days, last updated") | Out-Null
		$textForReportInfo.Add($CiscoAMPinstalled + "Installed but not updated within the last 3 days, last updated " + $virusDef) | Out-Null
	}
}

if($installedAV -match "Trend" )
{
	$TrendMicroinstalled = $installedAV






	### Get Current date and AV defenition date ###

	$virusDefDate =  Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc. -Name "PatternDate"
    $DateStr = $virusDefDate.PatternDate
    $virusDefYearString =  $DateStr.Substring( 0,4)
    $virusDefMonthString = $DateStr.Substring( 4,2)
    $virusDefDayString = $DateStr.Substring( 6,2)
    $virusDefDate=  get-date -Year $virusDefYearString -Month $virusDefMonthString -Day $virusDefDayString -hour 0 -Minute 0 -Second 0
    $Age =  (get-date) - $virusDefDate

	If($Age.Days -lt 3)
	{
		$resultAV = "## OK ## Trend Micro Installed and updated, last updated " + $DateStr

		$textForReport.Add("## OK ## Trend Micro Installed and updated") | Out-Null
		$TrendMicroInfo = $TrendMicroinstalled + "last updated " + $DateStr
		$textForReportInfo.add($TrendMicroInfo) | Out-Null
	}
	Else
	{
	    $resultAV = "## Failed(Info) ## Trend Micro Installed but not updated within the last 3 days, last updated " +$DateStr
		$textForReport.Add("## OK(Info) ## Trend Micros Installed but not updated within the last 3 days, last updated " + $DateStr) | Out-Null
		$textForReportInfo.Add($TrendMicroinstalled + "Installed but not updated within the last 3 days, last updated " + $DateStr) | Out-Null
	}
}

if($installedAV -match "Defender")
{
    $Defenderinstalled = $installedAV






	### Get Current date and AV defenition date ###

	$virusDates =  Get-MpComputerStatus  | select  AntispywareSignatureLastUpdated,  AntivirusSignatureLastUpdated 
    $DateStr = $virusDates.AntivirusSignatureLastUpdated
    $virusDefYearString =  $DateStr.Year
    $virusDefMonthString = $DateStr.Month
    $virusDefDayString = $DateStr.Day
    $virusDefDate=  get-date -Year $virusDefYearString -Month $virusDefMonthString -Day $virusDefDayString -hour 0 -Minute 0 -Second 0
    $Age =  (get-date) - $virusDefDate

	If($Age.Days -lt 3)
	{
		$resultAV = "## OK ## Microsoft Defender Installed and updated, last updated " + $DateStr

		$textForReport.Add("## OK ## Microsoft Defender Installed and updated") | Out-Null
		$DefenderInfo = $Defenderinstalled + " last updated " + $DateStr
		$textForReportInfo.add($DefenderInfo) | Out-Null
	}
	Else
	{
	    $resultAV = "## Failed(Info) ## Microsoft Defender Installed but not updated within the last 3 days, last updated " +$DateStr
		$textForReport.Add("## OK(Info) ## Microsoft Defender Installed but not updated within the last 3 days, last updated " + $DateStr) | Out-Null
		$textForReportInfo.Add($Defenderinstalled + " Installed but not updated within the last 3 days, last updated " + $DateStr) | Out-Null
	}
}
Elseif (-not $Antivirus)
{

    	$textForReport.Add("## OK ## No AV installation found. Not required.") | Out-Null
    	$textForReportInfo.Add("## OK ## No AV installation found. Not required.") | Out-Null
	$resultAV = "## OK ## No AV installation found. Not required."
}
else
{
    	$textForReport.Add("## Failed ## No AV installation found") | Out-Null
    	$textForReportInfo.Add("## Failed ## No AV installation found") | Out-Null
	$resultAV = "## Failed ## No AV installation found"
}

$textForReportInfo.Add("") | Out-Null
$textForReport | out-file $AuditReport -Append
$textForReportInfo | out-file $AuditReportInfo -Append

$AuditResults.Add($resultAV) | Out-Null

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### Backup installeret ###
### Audit Module
### Author: OTDU
### Approver: TBKL
### Date: 2019.05.24
### Version: 1.0
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module
### 1.1, 2019.08.29, OTDU, Added Commvault install check
### 1.2, 2019.10.03, TBKL, Added support for Azure Backup
### 1.3, 2020.07.04, TBKL, Add option to accept failure of check
### 1.4, 2020.04.12, TBKL, Correction to option to accept failure of check

$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()

$textForReportInfo.Add("## Starting Backup Installed ##") | Out-Null

$installedBackup = $InstalledSoftware | Where-Object { $_.DisplayName -like "*Symantec Netbackup*" -or $_.DisplayName -like "*Commvault*" -or $_.DisplayName -like "*Azure Recovery*" -or $_.DisplayName -like "*Veritas Netbackup*" } | format-table -HideTableHeaders | Out-String

if($installedBackup -match "Symantec Netbackup" -or $installedBackup -match "Veritas Netbackup" )
{
    $checkValue = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Veritas\Netbackup\CurrentVersion -Name "INSTALLDIR"
    $installDir = $checkValue.INSTALLDIR
    $backupImageList = $installDir + "netbackup\bin\bpclimagelist.exe"
    if(Test-Path $backupImageList)
        {
        	$lastBackup = & $backupImageList
        	if (-not ([string]::IsNullOrEmpty($lastBackup)))
        	{
		        $checkDate = (get-date).AddDays(-7).ToString("MMddyyy") | Out-Null
	        	$lastBackupDate = $lastBackup |  Select-String -Pattern "Full" |  Select-Object -First 1 | Out-String
        		$lastBackupDateCheck = $lastBackupDate.Substring(0,12)
	        	$lastBackupDateCheck = [int]$lastBackupDateCheck.Replace("/", "")

			if($lastBackupDateCheck -ge $checkDate)
		    	{
                	$resultBackup = "## OK ## Backup Installed and full backup within the last 7 days"
                	$textForReport.Add("## OK ## Backup Installed and full backup within the last 7 days") | Out-Null
                	$textForReportInfo.Add($installedBackup) | Out-Null
                	$textForReportInfo.Add($lastBackupDate) | Out-Null
			}
            }
            else
            {
                $resultBackup = "## Failed ## Symantec Netbackup installed but no Full backup within the last 7 days"
                $textForReport.Add("## Failed ## Symantec Netbackup installed but no Full backup within the last 7 days") | Out-Null
                $textForReportInfo.Add($installedBackup) | Out-Null
                $textForReportInfo.Add($lastBackupDate) | Out-Null
            }
	}

}

if($installedBackup -match "Commvault")
{
	$resultBackup = "## OK ## Commvault Backup Installed"
        $textForReport.Add("## OK ## Commvault Backup Installed") | Out-Null
        $textForReportInfo.Add($installedBackup) | Out-Null
}

if($installedBackup -match "Azure Recovery")
{
	$resultBackup = "## OK ## Azure Backup Installed"
        $textForReport.Add("## OK ## Azure Backup Installed") | Out-Null
        $textForReportInfo.Add($installedBackup) | Out-Null
}

if($Backup)
{}
Elseif (-not $Backup)
{
	$resultBackup = "## OK ## No Backup software found. Not required."
    	$textForReport.Add("## OK ## No Backup software found. Not required.") | Out-Null
    	$textForReportInfo.Add("## OK ## No Backup software found. Not required.") | Out-Null
}

else
{
	$resultBackup = "## Failed ## No Backup software found"
    	$textForReport.Add("## Failed ## No Backup software found") | Out-Null
    	$textForReportInfo.Add("## Failed ## No Backup software found") | Out-Null
}

$textForReportInfo.Add("") | Out-Null
$textForReport | out-file $AuditReport -Append
$textForReportInfo | out-file $AuditReportInfo -Append

$AuditResults.Add($resultBackup) | Out-Null

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### Audit Policies ###
### Audit Module
### Author: RRII
### Approver: TBKL
### Date: 2020.02.22
### Version: 1.2
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module
### 1.1, 2020.07.04, TBKL, Add option to accept failure of check
### 1.2. 2022.02.02, RRII, Server 2022 aware

$OS = Get-CimInstance Win32_OperatingSystem

$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()
$textForReportInfoOK = [System.Collections.ArrayList]@()
$textForReportInfoFails = [System.Collections.ArrayList]@()

$textForReportInfo.Add("## Starting Audit Policies ##") | Out-Null

$auditFails = [System.Collections.ArrayList]@()
$auditOk = [System.Collections.ArrayList]@()
$auditPolicies = [System.Collections.ArrayList]@()
$auditPolicy = [System.Collections.ArrayList]@()
$auditPolicies = auditpol /get /category:* /r | Out-String
$auditPolicies = $auditPolicies -split "`n"

### Audit Check for Windows 2022
If($OS -like "*2022*")
{
### Policy "System,Security System Extension" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Security System Extension"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Security System Extension - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,System Integrity" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,System Integrity"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,System Integrity - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,IPsec Driver" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,IPsec Driver"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,IPsec Driver - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Other System Events" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other System Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Other System Events - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Security State Change" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Security State Change"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Security State Change - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Logon" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Logon"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Logon - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Logoff" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Logoff"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Logoff - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Account Lockout" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Account Lockout"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Account Lockout - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,IPsec Main Mode" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,IPsec Main Mode"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,IPsec Main Mode - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,IPsec Quick Mode" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,IPsec Quick Mode"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,IPsec Quick Mode - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,IPsec Extended Mode" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,IPsec Extended Mode"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,IPsec Extended Mode - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Special Logon" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Special Logon"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Special Logon - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Other Logon/Logoff Events" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other Logon/Logoff Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Other Logon/Logoff Events - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,User / Device Claims" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,User / Device Claims"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,User / Device Claims - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Group Membership" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Group Membership"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Group Membership - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,File System" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,File System"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,File System - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Registry" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Registry"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Registry - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Kernel Object" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Kernel Object"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Kernel Object - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,SAM" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,SAM"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,SAM - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Certification Services" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Certification Services"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Certification Services - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: Success and Failure: " + $auditPolicy) | Out-Null
}

### Policy "System,Application Generated" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Application Generated"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Application Generated - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Handle Manipulation" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Handle Manipulation"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Handle Manipulation - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,File Share" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,File Share"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,File Share - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Filtering Platform Packet Drop" Expected Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Filtering Platform Packet Drop"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Filtering Platform Packet Drop - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: Success and Failure: " + $auditPolicy) | Out-Null
}

### Policy "System,Filtering Platform Connection" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Filtering Platform Connection"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Filtering Platform Connection - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: Success and Failure: " + $auditPolicy) | Out-Null
}

### Policy "System,Other Object Access Events" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other Object Access Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Other Object Access Events - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: Success and Failure: " + $auditPolicy) | Out-Null
}

### Policy "System,Detailed File Share" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Detailed File Share"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Detailed File Share - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: Success and Failure: " + $auditPolicy) | Out-Null
}

### Policy "System,Removable Storage" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Removable Storage"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Removable Storage - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure: " + $auditPolicy) | Out-Null
}

### Policy "System,Central Policy Staging" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Central Policy Staging"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Central Policy Staging - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Non Sensitive Privilege Use" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Non Sensitive Privilege Use"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Non Sensitive Privilege Use - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Other Privilege Use Events" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other Privilege Use Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Other Privilege Use Events - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Sensitive Privilege Use" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Sensitive Privilege Use"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Sensitive Privilege Use - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Process Creation" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Process Creation"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Process Creation - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Process Termination" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Process Termination"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Process Termination - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,DPAPI Activity" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,DPAPI Activity"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,DPAPI Activity - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,RPC Events" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,RPC Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,RPC Events - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Plug and Play Events" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Plug and Play Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Plug and Play Events - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Token Right Adjusted Events" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Token Right Adjusted Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Token Right Adjusted Events - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Audit Policy Change" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Audit Policy Change"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Audit Policy Change - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Authentication Policy Change" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Authentication Policy Change"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Authentication Policy Change - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Authorization Policy Change" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Authorization Policy Change"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Authorization Policy Change - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,MPSSVC Rule-Level Policy Change" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,MPSSVC Rule-Level Policy Change"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,MPSSVC Rule-Level Policy Change - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure: " + $auditPolicy) | Out-Null
}

### Policy "System,Filtering Platform Policy Change" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Filtering Platform Policy Change"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Filtering Platform Policy Change - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Other Policy Change Events" Expected results Success Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other Policy Change Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Failure,")
{
$auditOk.Add("OK: System,Other Policy Change Events - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: Failure: " + $auditPolicy) | Out-Null
}

### Policy "System,Computer Account Management" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Computer Account Management"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Computer Account Management - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Security Group Management" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Security Group Management"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Security Group Management - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Distribution Group Management" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Distribution Group Management"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Distribution Group Management - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Application Group Management" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Application Group Management"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Application Group Management - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Other Account Management Events" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other Account Management Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Other Account Management Events - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,User Account Management" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,User Account Management"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,User Account Management - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " +$auditPolicy) | Out-Null
}

### Policy "System,Directory Service Access" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Directory Service Access"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Directory Service Access - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Directory Service Changes" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Directory Service Changes"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Directory Service Changes - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Directory Service Replication" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Directory Service Replication"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Directory Service Replication - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Detailed Directory Service Replication" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Detailed Directory Service Replication"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
    $auditOk.Add("OK: System,Detailed Directory Service Replication - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Kerberos Service Ticket Operations" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Kerberos Service Ticket Operations"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
    $auditOk.Add("OK: System,Kerberos Service Ticket Operations - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Other Account Logon Events" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other Account Logon Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
    $auditOk.Add("OK: System,Other Account Logon Events - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Kerberos Authentication Service" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Kerberos Authentication Service"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
    $auditOk.Add("OK: System,Kerberos Authentication Service - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Credential Validation" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Credential Validation"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
    $auditOk.Add("OK: System,Credential Validation - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}
}
### Audit check for pre Windows 2022
    Else
    {
### Policy "System,Security System Extension" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Security System Extension"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Security System Extension - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,System Integrity" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,System Integrity"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,System Integrity - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,IPsec Driver" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,IPsec Driver"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,IPsec Driver - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Other System Events" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other System Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Other System Events - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Security State Change" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Security State Change"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Security State Change - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Logon" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Logon"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Logon - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Logoff" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Logoff"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Logoff - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Account Lockout" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Account Lockout"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Account Lockout - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,IPsec Main Mode" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,IPsec Main Mode"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,IPsec Main Mode - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,IPsec Quick Mode" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,IPsec Quick Mode"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,IPsec Quick Mode - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,IPsec Extended Mode" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,IPsec Extended Mode"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,IPsec Extended Mode - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Special Logon" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Special Logon"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Special Logon - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Other Logon/Logoff Events" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other Logon/Logoff Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Other Logon/Logoff Events - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,User / Device Claims" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,User / Device Claims"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,User / Device Claims - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Group Membership" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Group Membership"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Group Membership - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,File System" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,File System"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,File System - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Registry" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Registry"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Registry - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Kernel Object" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Kernel Object"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Kernel Object - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,SAM" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,SAM"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,SAM - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Certification Services" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Certification Services"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Certification Services - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Application Generated" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Application Generated"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Application Generated - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Handle Manipulation" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Handle Manipulation"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Handle Manipulation - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,File Share" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,File Share"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,File Share - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Filtering Platform Packet Drop" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Filtering Platform Packet Drop"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Filtering Platform Packet Drop - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Filtering Platform Connection" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Filtering Platform Connection"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Filtering Platform Connection - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Other Object Access Events" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other Object Access Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Other Object Access Events - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Detailed File Share" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Detailed File Share"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Detailed File Share - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Removable Storage" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Removable Storage"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Removable Storage - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Central Policy Staging" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Central Policy Staging"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Central Policy Staging - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Non Sensitive Privilege Use" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Non Sensitive Privilege Use"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Non Sensitive Privilege Use - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Other Privilege Use Events" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other Privilege Use Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Other Privilege Use Events - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Sensitive Privilege Use" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Sensitive Privilege Use"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Sensitive Privilege Use - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Process Creation" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Process Creation"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Process Creation - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Process Termination" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Process Termination"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Process Termination - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,DPAPI Activity" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,DPAPI Activity"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,DPAPI Activity - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,RPC Events" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,RPC Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,RPC Events - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Plug and Play Events" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Plug and Play Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Plug and Play Events - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Token Right Adjusted Events" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Token Right Adjusted Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Token Right Adjusted Events - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Audit Policy Change" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Audit Policy Change"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Audit Policy Change - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Authentication Policy Change" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Authentication Policy Change"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Authentication Policy Change - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Authorization Policy Change" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Authorization Policy Change"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Authorization Policy Change - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,MPSSVC Rule-Level Policy Change" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,MPSSVC Rule-Level Policy Change"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,MPSSVC Rule-Level Policy Change - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Filtering Platform Policy Change" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Filtering Platform Policy Change"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Filtering Platform Policy Change - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Other Policy Change Events" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other Policy Change Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Other Policy Change Events - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Computer Account Management" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Computer Account Management"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Computer Account Management - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Security Group Management" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Security Group Management"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Security Group Management - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Distribution Group Management" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Distribution Group Management"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Distribution Group Management - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Application Group Management" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Application Group Management"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Application Group Management - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,Other Account Management Events" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other Account Management Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,Other Account Management Events - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}

### Policy "System,User Account Management" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,User Account Management"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
$auditOk.Add("OK: System,User Account Management - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " +$auditPolicy) | Out-Null
}

### Policy "System,Directory Service Access" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Directory Service Access"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
$auditOk.Add("OK: System,Directory Service Access - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Directory Service Changes" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Directory Service Changes"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Directory Service Changes - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Directory Service Replication" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Directory Service Replication"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
$auditOk.Add("OK: System,Directory Service Replication - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Detailed Directory Service Replication" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Detailed Directory Service Replication"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
    $auditOk.Add("OK: System,Detailed Directory Service Replication - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Kerberos Service Ticket Operations" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Kerberos Service Ticket Operations"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
    $auditOk.Add("OK: System,Kerberos Service Ticket Operations - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Other Account Logon Events" Expected results No Auditing ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Other Account Logon Events"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",No Auditing," -or ",Success and Failure," -or ",Success")
{
    $auditOk.Add("OK: System,Other Account Logon Events - " + $auditPolicy) | Out-Null
}
else
{
     $auditFails.Add("Found but not configured correctly, Should be: No Auditing: " + $auditPolicy) | Out-Null
}

### Policy "System,Kerberos Authentication Service" Expected results Success ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Kerberos Authentication Service"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success" -or ",Success and Failure,")
{
    $auditOk.Add("OK: System,Kerberos Authentication Service - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success " + $auditPolicy) | Out-Null
}

### Policy "System,Credential Validation" Expected results Success and Failure ###
$auditPolicy = $auditPolicies | Select-String -Pattern "System,Credential Validation"
if($auditPolicy -notlike $null -and $auditPolicy -Match ",Success and Failure,")
{
    $auditOk.Add("OK: System,Credential Validation - " + $auditPolicy) | Out-Null
}
else
{
    $auditFails.Add("Found but not configured correctly, Should be: Success and Failure " + $auditPolicy) | Out-Null
}
    }

If($DomainJoined -eq $False)
{
	If($auditFails -Match "not configured correctly" -and -not $Policies)
	{
	    $resultAudit = "## OK ## Audit Policies found but not configured correctly. Not required."
	    $textForReport.Add("## OK  ## Audit Policies found but not configured correctly. Not required.") | Out-Null
	}
    elseIf($auditFails -Match "not configured correctly")
	{
	    $resultAudit = "## Failed ## Audit Policies found but not configured correctly"
	    $textForReport.Add("## Failed ## Audit Policies Found but not configured correctly") | Out-Null
	}
    	Else
	{
	    $resultAudit = "## OK ## Audit Policies Found and configured correctly"
	    $textForReport.Add("## OK ## Audit Policies Found and configured correctly") | Out-Null
	}
}

If($DomainJoined -eq $True)
{
	$resultAudit = "## OK Info ## Audit Policies Found and configured by Domain GPO"
	$textForReport.Add($resultAudit) | Out-Null
}

$textForReportInfo.Add("Audit Policies Found and configured correctly") | Out-Null
$textForReportInfo.Add($auditOk) | Out-Null
$textForReportInfo.Add("Audit Policies Found but not configured correctly") | Out-Null
$textForReportInfo.Add($auditFails) | Out-Null

$AuditResults.Add($resultAudit) | Out-Null

$textForReportInfo.Add("") | Out-Null
$textForReport | out-file $AuditReport -Append
$textForReportInfo | out-file $AuditReportInfo -Append
$textForReportInfoOK | out-file $AuditReportInfo -Append
$textForReportInfoFails | out-file $AuditReportInfo -Append

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### Local Policies ###
### Audit Module
### Author: OTDU
### Approver: TBKL
### Date: 2019.06.21
### Version: 1.1
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module
### 1.1, 2019.06.21, OTDU, Fixed false posetive( -like changed to -match ), Added domain awareness so it will be “OK Info” if the server is joined to a domain

$textForReport = [System.Collections.ArrayList]@()
$textForReportInfo = [System.Collections.ArrayList]@()
$textForReportInfoOk = [System.Collections.ArrayList]@()

$textForReportInfo.Add("## Starting Starting Local Policies ##") | Out-Null

### Export local security settings ###
Secedit /export /cfg C:\Temp\SecExport.csv
$secInfo = Import-Csv -Path C:\Temp\SecExport.csv
$option = [System.StringSplitOptions]::RemoveEmptyEntries
$separator = " = ", "}", "\n", "@{[Unicode]="
$compliant = [System.Collections.ArrayList]@()
$Noncompliant = [System.Collections.ArrayList]@()

### PasswordHistorySize ###
$secTemp = $secInfo | Select-String "PasswordHistorySize " | Out-String
$secTemp = $secTemp.split($separator, 4, $option)

$policyName = $secTemp[1]
[int]$policyValue = $secTemp[2]

if($policyValue -ge "24"){$compliant.Add($policyName + ":" + $policyValue) | Out-Null }
else{$Noncompliant.Add("Failed: " + $policyName + ":" + $policyValue)  | Out-Null }

###############################

### MaximumPasswordAge ###
$secTemp = $secInfo | Select-String "MaximumPasswordAge " | Out-String
$secTemp = $secTemp.split($separator, 4, $option)

$policyName = $secTemp[1]
[int]$policyValue = $secTemp[2]

if($policyValue -le "60"){$compliant.Add($policyName + ":" + $policyValue) | Out-Null }
else{$Noncompliant.Add("Failed: " + $policyName + ":" + $policyValue) | Out-Null }

###############################

### MinimumPasswordAge ###
$secTemp = $secInfo | Select-String "MinimumPasswordAge " | Out-String
$secTemp = $secTemp.split($separator, 4, $option)

$policyName = $secTemp[1]
[int]$policyValue = $secTemp[2]

if($policyValue -ge "1"){$compliant.Add($policyName + ":" + $policyValue) | Out-Null }
else{$Noncompliant.Add("Failed: " + $policyName + ":" + $policyValue) | Out-Null }

###############################

### MinimumPasswordLength ###
$secTemp = $secInfo | Select-String "MinimumPasswordLength " | Out-String
$secTemp = $secTemp.split($separator, 4, $option)

$policyName = $secTemp[1]
[int]$policyValue = $secTemp[2]

if($policyValue -ge "14"){$compliant.Add($policyName + ":" + $policyValue) | Out-Null }
else{$Noncompliant.Add("Failed: " + $policyName + ":" + $policyValue) | Out-Null }

###############################

### PasswordComplexity ###
$secTemp = $secInfo | Select-String "PasswordComplexity " | Out-String
$secTemp = $secTemp.split($separator, 4, $option)

$policyName = $secTemp[1]
[int]$policyValue = $secTemp[2]

if($policyValue -eq "1"){$compliant.Add($policyName + ":" + $policyValue) | Out-Null }
else{$Noncompliant.Add("Failed: " + $policyName + ":" + $policyValue) | Out-Null }

###############################

### LockoutDuration ###
$secTemp = $secInfo | Select-String "LockoutDuration " | Out-String
$secTemp = $secTemp.split($separator, 4, $option)

$policyName = $secTemp[1]
[int]$policyValue = $secTemp[2]

if($policyValue -ge "15"){$compliant.Add($policyName + ":" + $policyValue) | Out-Null }
else{$Noncompliant.Add("Failed: " + $policyName + ":" + $policyValue) | Out-Null }

###############################

### LockThreshold ###
$secTemp = $secInfo | Select-String "LockoutBadCount " | Out-String
$secTemp = $secTemp.split($separator, 4, $option)

$policyName = $secTemp[1]
[int]$policyValue = $secTemp[2]

if($policyValue -le "10"){$compliant.Add($policyName + ":" + $policyValue) | Out-Null }
else{$Noncompliant.Add("Failed: " + $policyName + ":" + $policyValue) | Out-Null }

###############################

### ResetLockoutCount ###
$secTemp = $secInfo | Select-String "ResetLockoutCount " | Out-String
$secTemp = $secTemp.split($separator, 4, $option)

$policyName = $secTemp[1]
[int]$policyValue = $secTemp[2]

if($policyValue -ge "15"){$compliant.Add($policyName + ":" + $policyValue) | Out-Null }
else{$Noncompliant.Add("Failed: " + $policyName + ":" + $policyValue) | Out-Null }

###############################

### EnableGuestAccount ###
$secTemp = $secInfo | Select-String "EnableGuestAccount " | Out-String
$secTemp = $secTemp.split($separator, 4, $option)

$policyName = $secTemp[1]
[int]$policyValue = $secTemp[2]

if($policyValue -eq "0"){$compliant.Add($policyName + ":" + $policyValue) | Out-Null }
else{$Noncompliant.Add("Failed: " + $policyName + ":" + $policyValue) | Out-Null }

###############################

### ClearTextPassword ###
$secTemp = $secInfo | Select-String "ClearTextPassword " | Out-String
$secTemp = $secTemp.split($separator, 4, $option)

$policyName = $secTemp[1]
[int]$policyValue = $secTemp[2]

if($policyValue -eq "0"){$compliant.Add($policyName + ":" + $policyValue) | Out-Null }
else{$Noncompliant.Add("Failed: " + $policyName + ":" + $policyValue) | Out-Null }

###############################

### RequireLogonToChangePassword ###
$secTemp = $secInfo | Select-String "RequireLogonToChangePassword " | Out-String
$secTemp = $secTemp.split($separator, 4, $option)

$policyName = $secTemp[1]
[int]$policyValue = $secTemp[2]

if($policyValue -eq "1"){$compliant.Add($policyName + ":" + $policyValue) | Out-Null }
else{$Noncompliant.Add("Failed: " + $policyName + ":" + $policyValue) | Out-Null }

###############################

### ForceLogoffWhenHourExpire ###
$secTemp = $secInfo | Select-String "ForceLogoffWhenHourExpire " | Out-String
$secTemp = $secTemp.split($separator, 4, $option)

$policyName = $secTemp[1]
[int]$policyValue = $secTemp[2]

if($policyValue -eq "1"){$compliant.Add($policyName + ":" + $policyValue) | Out-Null }
else{$Noncompliant.Add("Failed: " + $policyName + ":" + $policyValue) | Out-Null }

###############################

### BlockMicrosoftAccounts ###
$secTemp = $secInfo | Select-String "NoConnectedUser " | Out-String
$secTemp = $secTemp.split($separator, 4, $option)

$policyName = $secTemp[1]
[int]$policyValue = $secTemp[2]

if($policyName -like "NoConnectedUser ")
{
    if($policyValue -like "4, 3"){$compliant.Add($policyName + ":" + $policyValue) | Out-Null }
    else{$Noncompliant.Add("Failed: " + $policyName + ":" + $policyValue) | Out-Null }
}

###############################

If($DomainJoined -eq $False)
{
    if($Noncompliant -match "Failed: " -and -not $Policies)
	{
	    $resultPolicy = "## OK ## Local Policies not Compliant. See Audit-Info for more information. Not required."
	    $textForReport.Add("## OK ## Local Policies not Compliant. See Audit-Info for more information. Not required.") | Out-Null
	}
	elseif($Noncompliant -match "Failed: ")
	{
	    $resultPolicy = "## Failed ## See Audit-Info for more information"
	    $textForReport.Add("## Failed ## Local Policies not Compliant See Audit-Info for more information") | Out-Null
	}
	else
	{
	    $resultPolicy = "## OK ## All local policies was complaint"
	    $textForReport.Add("## OK ## All local policies was complaint") | Out-Null
	}
}
If($DomainJoined -eq $True)
{
	$resultPolicy = "## OK Info ## Local Policies Found and configured by Domain GPO"
	$textForReport.Add($resultPolicy) | Out-Null
}

$textForReport | out-file $AuditReport -Append

$textForReportInfo.Add("") | Out-Null
$textForReportInfo.Add("## The following local policies was compliant ##") | Out-Null
$textForReportInfo.Add($compliant) | Out-Null
$textForReportInfo.Add("## The following local policies failed audit ##") | Out-Null
$textForReportInfo.Add($Noncompliant) | Out-Null
$textForReportInfo | out-file $AuditReportInfo -Append

$AuditResults.Add($resultPolicy) | Out-Null

### Module End ###

########################################################################################################################
########################################################################################################################
### Module Start ###
### Result ###
### Audit Module
### Author: OTDU
### Approver: TBKL
### Date: 2019.05.24
### Version: 1.0
### PRD-089

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2019.05.24, OTDU, New Module

If($AuditResults -match "Failed")
{
    for ($i = 0; $i -lt $AuditResults.Count ; $i++) {
        [System.Console]::Error.WriteLine($AuditResults[$i])
    }

	$Exitcode = 1
}
Else
{
    for ($i = 0; $i -lt $AuditResults.Count ; $i++) {
        Write-Output $AuditResults[$i]
    }
	$Exitcode = 0
}

$exitcode