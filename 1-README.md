# Active Directory & Sysmon Lab

A home lab for learning Windows detection engineering: a small Active Directory domain with Sysmon and extended Windows auditing, plus notes on which events to watch for common attacker techniques.

## Lab layout
| Host | Role |
|------|------|
| DC01 | Domain Controller (Windows Server), domain `lab.local` |
| WS01 | Windows 10/11 workstation, domain joined, Sysmon installed |
| KALI | Attacker VM used to generate test activity (authorized lab only) |

## Contents
- `scripts/Build-LabDomain.ps1` creates OUs, users, groups and a service account for testing.
- `scripts/Enable-Auditing.ps1` turns on process creation command-line logging, PowerShell script block logging and key audit policies.
- `scripts/Install-Sysmon.ps1` installs Sysmon with the config in `config/`.
- `config/sysmon-config.xml` a compact Sysmon config focused on process creation, network, registry persistence, LSASS access and WMI.
- `docs/detection-map.md` maps ATT&CK techniques to the Windows/Sysmon events to monitor.

## Usage
1. Build two Windows VMs on an isolated host-only network.
2. On DC01 run `Build-LabDomain.ps1`, then `Enable-Auditing.ps1`.
3. On WS01 join the domain, run `Enable-Auditing.ps1` and `Install-Sysmon.ps1`.
4. Run test activity from `docs/detection-map.md` and review events in Event Viewer (`Microsoft-Windows-Sysmon/Operational`).

Lab use only. Do not run attack tests against systems you do not own.
