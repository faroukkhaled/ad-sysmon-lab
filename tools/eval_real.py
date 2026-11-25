"""Run the shipped rules over the real OTRF telemetry and print a results table.

Expected rules are my own reading of what each emulated attack should trigger.
Misses are reported as misses, not tuned away.

    python tools/fetch_otrf.py && python tools/eval_real.py
"""
import os
import sys
import collections

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sysmonlab import engine, events, rules  # noqa: E402

# dataset -> (rule ids the attack should trigger, ATT&CK technique emulated)
EXPECTED = {
    "mimikatz_logonpasswords": ({"sl-0010"}, "T1003.001 LSASS credential dumping"),
    "lsass_dump_comsvcs": ({"sl-0010"}, "T1003.001 LSASS dump via comsvcs.dll"),
    "dcsync_drsuapi": ({"sl-0017"}, "T1003.006 DCSync"),
    "run_key_persistence": ({"sl-0011"}, "T1547.001 Run key"),
    "schtasks_persistence": ({"sl-0020"}, "T1053.005 Scheduled task"),
    "wmi_event_subscription": ({"sl-0012"}, "T1546.003 WMI event subscription"),
    "regsvr32_sct_launcher": ({"sl-0021"}, "T1218.010 regsvr32 scriptlet launcher"),
    "mshta_vbscript_psh": ({"sl-0022"}, "T1218.005 mshta VBScript"),
    "bitsadmin_download": ({"sl-0023"}, "T1197 BITS jobs download"),
}


def main(data_dir="data/real", rules_dir="rules"):
    rs = rules.load_rules(rules_dir)
    title = {r.id: r.title for r in rs}
    rows = []
    for name, (want, tech) in EXPECTED.items():
        path = os.path.join(data_dir, name + ".jsonl")
        if not os.path.exists(path):
            continue
        evs = events.load_events(path)
        fired = collections.Counter(d.rule.id for d in engine.run(rs, evs))
        hit = sorted(want & set(fired))
        miss = sorted(want - set(fired))
        extra = sorted(set(fired) - want)
        rows.append((name, tech, len(evs), hit, miss, extra, fired))
    print("%-26s %-40s %7s  %s" % ("dataset", "emulated technique", "events", "result"))
    for name, tech, n, hit, miss, extra, fired in rows:
        res = []
        if hit:
            res.append("detected " + ",".join(hit))
        if miss:
            res.append("MISSED " + ",".join(miss))
        if not hit and not miss:
            res.append("no rule targets this technique yet")
        if extra:
            res.append("other hits: " + ", ".join("%s x%d" % (i, fired[i]) for i in extra))
        print("%-26s %-40s %7d  %s" % (name, tech, n, "; ".join(res)))
    missed = [r for r in rows if r[4]]
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
