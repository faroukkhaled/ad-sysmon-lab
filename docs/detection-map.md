# Detection map

| Technique (ATT&CK) | Lab test (authorized lab only) | What to look for |
|---|---|---|
| T1059.001 PowerShell | `powershell -enc <base64>` | Sysmon 1 with `-enc` / `-nop` / `-w hidden`; 4104 script block |
| T1003.001 LSASS dump | Task Manager dump or a credential dumper | Sysmon 10 with TargetImage lsass.exe and unusual GrantedAccess (0x1010, 0x1410) |
| T1558.003 Kerberoasting | Request TGS for `svc-sql` | Security 4769, ticket encryption 0x17, many requests from one account |
| T1110 Brute force | Repeated bad logons | Security 4625 bursts followed by 4624 |
| T1547.001 Run key persistence | Add HKCU Run value | Sysmon 13 on `...\CurrentVersion\Run` |
| T1136 Create account | `net user x /add` | Security 4720, 4732 |
| T1021.002 SMB/Admin shares | `net use \\WS01\C$` | Security 4624 type 3, 5140 |
| T1070.001 Clear logs | `wevtutil cl Security` | Security 1102, System 104 |
