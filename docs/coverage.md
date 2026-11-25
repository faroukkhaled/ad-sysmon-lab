| Technique | Name | Tactic | Rules |
|---|---|---|---|
| T1003.001 | LSASS Memory | credential-access | sl-0010 (critical), sl-0005 (critical) |
| T1003.006 | DCSync | credential-access | sl-0017 (critical) |
| T1018 | Remote System Discovery | discovery | sl-0008 (medium) |
| T1021.002 | SMB/Windows Admin Shares | lateral-movement | sl-0007 (high) |
| T1033 | System Owner/User Discovery | discovery | sl-0008 (medium) |
| T1053.005 | Scheduled Task | persistence | sl-0004 (high), sl-0020 (high) |
| T1059 | Command and Scripting Interpreter | execution | sl-0002 (high) |
| T1059.001 | PowerShell | execution | sl-0001 (high) |
| T1070.001 | Clear Windows Event Logs | defense-evasion | sl-0019 (high) |
| T1071 | Application Layer Protocol | command-and-control | sl-0009 (high) |
| T1071.004 | DNS | command-and-control | sl-0014 (low) |
| T1087.001 | Local Account Discovery | discovery | sl-0008 (medium) |
| T1098 | Account Manipulation | persistence | sl-0018 (high) |
| T1105 | Ingress Tool Transfer | command-and-control | sl-0003 (medium) |
| T1110 | Brute Force | credential-access | sl-0016 (medium) |
| T1140 | Deobfuscate/Decode Files or Information | defense-evasion | sl-0003 (medium) |
| T1197 | BITS Jobs | defense-evasion | sl-0023 (medium) |
| T1204.002 | User Execution: Malicious File | execution | sl-0002 (high) |
| T1218.005 | Mshta | defense-evasion | sl-0022 (high) |
| T1218.010 | Regsvr32 | defense-evasion | sl-0021 (high) |
| T1490 | Inhibit System Recovery | impact | sl-0006 (critical) |
| T1546.003 | WMI Event Subscription | persistence | sl-0012 (high) |
| T1547.001 | Registry Run Keys / Startup Folder | persistence | sl-0013 (medium), sl-0011 (medium) |
| T1558.003 | Kerberoasting | credential-access | sl-0015 (high) |
| T1569.002 | Service Execution | execution | sl-0007 (high) |

