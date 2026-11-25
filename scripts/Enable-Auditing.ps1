# Enables the logging that detections depend on. Run elevated.
# Include command line in process creation events (4688)
$k = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
# PowerShell script block logging (4104)
$p = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $p -Force | Out-Null
Set-ItemProperty -Path $p -Name EnableScriptBlockLogging -Value 1 -Type DWord
# Audit policy
$cats = "Logon","Account Lockout","Process Creation","Kerberos Service Ticket Operations",
        "Kerberos Authentication Service","Security Group Management","User Account Management",
        "Directory Service Changes"
foreach ($c in $cats) { auditpol /set /subcategory:"$c" /success:enable /failure:enable | Out-Null }
Write-Host "Auditing enabled."
