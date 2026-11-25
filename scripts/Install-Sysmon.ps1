# Download Sysmon from Microsoft Sysinternals first and place Sysmon64.exe next to this script.
param([string]$Config = "..\config\sysmon-config.xml")
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    .\Sysmon64.exe -c $Config
} else {
    .\Sysmon64.exe -accepteula -i $Config
}
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-List TimeCreated,Id,Message
