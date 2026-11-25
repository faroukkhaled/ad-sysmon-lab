"""Download real attack-emulation telemetry from OTRF Security-Datasets (MIT licence)
and write trimmed JSON-lines samples that the engine can read.

    python tools/fetch_otrf.py            # writes data/real/*.jsonl

Source: https://github.com/OTRF/Security-Datasets  (c) Open Threat Research Forge, MIT.
The logs were produced by OTRF in their own lab while emulating attacks. They are real
Windows telemetry, not synthetic, and not from any employer or bank.
Trimming: only Sysmon and selected Security events are kept and the long free-text
"Message" field is dropped, so the files stay small. Nothing else is altered.
"""
import io
import json
import os
import sys
import urllib.request
import zipfile

BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"
DATASETS = {
    "mimikatz_logonpasswords": "credential_access/host/empire_mimikatz_logonpasswords.zip",
    "dcsync_drsuapi": "credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
    "lsass_dump_comsvcs": "credential_access/host/psh_lsass_memory_dump_comsvcs.zip",
    "schtasks_persistence": "persistence/host/empire_schtasks_creation_execution_elevated_user.zip",
    "run_key_persistence": "persistence/host/empire_persistence_registry_modification_run_keys_elevated_user.zip",
    "wmi_event_subscription": "persistence/host/empire_wmi_local_event_subscriptions_elevated_user.zip",
    "mshta_vbscript_psh": "defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip",
    "regsvr32_sct_launcher": "defense_evasion/host/empire_launcher_sct_regsvr32.zip",
    "bitsadmin_download": "defense_evasion/host/cmd_bitsadmin_download_psh_script.zip",
}
KEEP_SYSMON = {1, 3, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22}
KEEP_SECURITY = {4624, 4625, 4662, 4672, 4688, 4697, 4698, 4720, 4728, 4732, 4768, 4769, 7045, 1102}
DROP = {"Message", "@version", "tags", "EventReceivedTime", "SourceModuleName", "SourceModuleType", "Keywords", "Opcode", "OpcodeValue", "Severity", "SeverityValue", "ProviderGuid", "RecordNumber", "ExecutionProcessID", "ThreadID", "Task", "Version", "EventType"}


def keep(e):
    ch = str(e.get("Channel", "")).lower()
    eid = e.get("EventID")
    if "sysmon" in ch:
        return eid in KEEP_SYSMON
    if ch == "security":
        return eid in KEEP_SECURITY
    return False


def main(out_dir="data/real"):
    os.makedirs(out_dir, exist_ok=True)
    for name, rel in DATASETS.items():
        with urllib.request.urlopen(BASE + rel, timeout=120) as r:
            z = zipfile.ZipFile(io.BytesIO(r.read()))
        member = [n for n in z.namelist() if n.endswith(".json")][0]
        n_in = n_out = 0
        with open(os.path.join(out_dir, name + ".jsonl"), "w", encoding="utf-8") as fh:
            for line in z.open(member):
                n_in += 1
                e = json.loads(line)
                if keep(e):
                    fh.write(json.dumps({k: v for k, v in e.items() if k not in DROP}, separators=(",", ":")) + "\n")
                    n_out += 1
        print("%-26s %6d -> %5d events" % (name, n_in, n_out))


if __name__ == "__main__":
    main(*sys.argv[1:])
