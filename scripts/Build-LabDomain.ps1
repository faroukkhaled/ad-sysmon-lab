# Run on the domain controller after promoting it to lab.local (lab use only).
Import-Module ActiveDirectory
$base = "DC=lab,DC=local"
foreach ($ou in "LabUsers","LabServers","LabWorkstations","ServiceAccounts") {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'")) {
        New-ADOrganizationalUnit -Name $ou -Path $base
    }
}
$pw = Read-Host "Password for lab users" -AsSecureString
$users = @(
    @{Name="alice.hr";   Dept="HR"},
    @{Name="bob.finance";Dept="Finance"},
    @{Name="carol.it";   Dept="IT"}
)
foreach ($u in $users) {
    New-ADUser -Name $u.Name -SamAccountName $u.Name -Department $u.Dept `
      -Path "OU=LabUsers,$base" -AccountPassword $pw -Enabled $true
}
New-ADGroup -Name "IT-Admins" -GroupScope Global -Path "OU=LabUsers,$base"
Add-ADGroupMember -Identity "IT-Admins" -Members "carol.it"
# Service account with an SPN so Kerberoasting can be practised and detected
New-ADUser -Name "svc-sql" -SamAccountName "svc-sql" -Path "OU=ServiceAccounts,$base" `
  -AccountPassword $pw -Enabled $true
Set-ADUser -Identity "svc-sql" -ServicePrincipalNames @{Add="MSSQLSvc/sql01.lab.local:1433"}
Write-Host "Lab domain objects created."
