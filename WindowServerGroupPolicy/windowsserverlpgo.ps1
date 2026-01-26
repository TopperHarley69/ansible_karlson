### Windows Server ###
### NNIT Windows Server LGPO
### Author: RRII
### Approver: TBKL
### Date: 2025.06.04
### Version: 1.2
### MET-072

### Changelog ###
### Version, Date, Initials, Change Description
### 1.0, 2018.11.13, OTDU, New Document
### 1.1, 2022.02.16, RRII, Added Windows 2022
### 1.2, 2025.06.04, RRII, Added Windows 2025

### Get OS Info
$OS = Get-CimInstance Win32_OperatingSystem | Select Name

### Check Path
###If((Test-Path -Path HKLM:\Software\NNIT\Deployed_with\NNIT_Deployment_Settings_for_Windows_Servers) -or (Test-Path -Path HKLM:\Software\Aeven\Deployed_with\Aeven_Deployment_Settings_for_Windows_Servers))
###    {Write-host "Deployment settings already exsist, no policies applied"} 
###    Else 
###    {
### Load Local Group Policy Settings for Windows 2025
If($OS -like "*2025*")
{
Start-Process -Filepath "c:\temp\Tools\LGPO.exe" -ArgumentList "/v /m c:\temp\Tools\WindowServerGroupPolicy\Machine\EdgeMachineV2.pol" -NoNewWindow -Wait
Start-Process -Filepath "c:\temp\Tools\LGPO.exe" -ArgumentList "/v /m c:\temp\Tools\WindowServerGroupPolicy\Machine\MachineV3.pol"
Start-Process -Filepath "c:\temp\Tools\LGPO.exe" -ArgumentList "/v /u c:\temp\Tools\WindowServerGroupPolicy\User\UserV3.pol"
Start-Process -Filepath "c:\temp\Tools\LGPO.exe" -ArgumentList "/v /s c:\temp\Tools\WindowServerGroupPolicy\GptTmplV3.ini"
}

### Load Local Group Policy Settings for Windows 2022
If($OS -like "*2022*")
{
Start-Process -Filepath "c:\temp\Tools\LGPO.exe" -ArgumentList "/v /m c:\temp\Tools\WindowServerGroupPolicy\Machine\EdgeMachineV2.pol" -NoNewWindow -Wait
Start-Process -Filepath "c:\temp\Tools\LGPO.exe" -ArgumentList "/v /m c:\temp\Tools\WindowServerGroupPolicy\Machine\MachineV2.pol"
Start-Process -Filepath "c:\temp\Tools\LGPO.exe" -ArgumentList "/v /u c:\temp\Tools\WindowServerGroupPolicy\User\UserV2.pol"
Start-Process -Filepath "c:\temp\Tools\LGPO.exe" -ArgumentList "/v /s c:\temp\Tools\WindowServerGroupPolicy\GptTmplV2.ini"
}

### Load Local Group Policy Settings for older Windows versions
if($OS -NotMatch '2022|2025')
{
Start-Process -Filepath "c:\temp\Tools\LGPO.exe" -ArgumentList "/v /m c:\temp\Tools\WindowServerGroupPolicy\Machine\registry.pol"
Start-Process -Filepath "c:\temp\Tools\LGPO.exe" -ArgumentList "/v /u c:\temp\Tools\WindowServerGroupPolicy\User\registry.pol"
Start-Process -Filepath "c:\temp\Tools\LGPO.exe" -ArgumentList "/v /s c:\temp\Tools\WindowServerGroupPolicy\GptTmpl.ini"
}
###    }
