# Real telemetry samples

These files are real Windows telemetry (Sysmon and Security logs) recorded while attacks were emulated in a lab.

- Source: OTRF Security-Datasets, https://github.com/OTRF/Security-Datasets
- Licence: MIT, (c) 2021 Open Threat Research Forge. Credit goes to OTRF and the Mordor project.
- Not synthetic, but also not from any company, bank or customer. They come from OTRF's own test lab.
- Trimmed by `tools/fetch_otrf.py`: only Sysmon and selected Security events are kept and the long `Message` field is dropped. Two larger datasets (`schtasks_persistence`, `wmi_event_subscription`) are not committed; run the script to fetch them.

| File | Emulated attack |
|------|-----------------|
| mimikatz_logonpasswords | Mimikatz sekurlsa::logonpasswords via Empire (T1003.001) |
| lsass_dump_comsvcs | LSASS dump with rundll32 comsvcs.dll (T1003.001) |
| dcsync_drsuapi | DCSync via DRSUAPI (T1003.006) |
| run_key_persistence | Run key persistence (T1547.001) |
| regsvr32_sct_launcher | regsvr32 remote scriptlet (T1218.010) |
| mshta_vbscript_psh | mshta VBScript (T1218.005) |
| bitsadmin_download | BITS download (T1197) |
