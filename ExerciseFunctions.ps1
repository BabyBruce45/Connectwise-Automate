#Run with a command like this:
#powershell "(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/DarrenWhite99/LabTech-Powershell-Module/DarrenWhite99-P2-Testing/LabTech.psm1') | iex -verbose;(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/DarrenWhite99/LabTech-Powershell-Module/TestScript/ExerciseFunctions.ps1') | iex -verbose"
#https://raw.githubusercontent.com/DarrenWhite99/LabTech-Powershell-Module/master/LabTech.psm1

'Running Test-LTPorts -Quiet'
Test-LTPorts -Quiet

'Running Test-LTPorts'
Test-LTPorts

if (!($LTServiceInfo)) {'Loading from Get-LTServiceInfo'; $LTServiceInfo = Get-LTServiceInfo}
if (!($LTServiceInfo)) {'Could not get LTServiceInfo'} else {$LTServiceInfo}
if (!($LTServiceSettings)) {'Loading from Get-LTServiceSettings'; $LTServiceSettings = Get-LTServiceSettings}
if (!($LTServiceSettings)) {'Could not get LTServiceSettings'} else {$LTServiceSettings}

'Running New-LTServiceBackup'
New-LTServiceBackup

'Running Restart-LTService'
Restart-LTService

'Checking LT Backup Settings' 
$BackupSettings = Get-LTServiceInfoBackup -ErrorAction SilentlyContinue
if (!($BackupSettings)) {'Error - Could not get BackupSettings'} else {$BackupSettings}

'Running Stop-LTService'
Stop-LTService
Sleep 5

'Running Start-LTService'
Start-LTService

'Running Reinstall-LTService'
Reinstall-LTService

