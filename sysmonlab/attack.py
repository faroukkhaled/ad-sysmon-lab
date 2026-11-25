"""ATT&CK coverage: which techniques the rule set claims to detect."""
import json

TECHNIQUES = {
    "T1059": ("Command and Scripting Interpreter", "execution"),
    "T1059.001": ("PowerShell", "execution"),
    "T1204.002": ("User Execution: Malicious File", "execution"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1140": ("Deobfuscate/Decode Files or Information", "defense-evasion"),
    "T1053.005": ("Scheduled Task", "persistence"),
    "T1003.001": ("LSASS Memory", "credential-access"),
    "T1003.006": ("DCSync", "credential-access"),
    "T1490": ("Inhibit System Recovery", "impact"),
    "T1021.002": ("SMB/Windows Admin Shares", "lateral-movement"),
    "T1569.002": ("Service Execution", "execution"),
    "T1033": ("System Owner/User Discovery", "discovery"),
    "T1087.001": ("Local Account Discovery", "discovery"),
    "T1018": ("Remote System Discovery", "discovery"),
    "T1071": ("Application Layer Protocol", "command-and-control"),
    "T1071.004": ("DNS", "command-and-control"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1546.003": ("WMI Event Subscription", "persistence"),
    "T1558.003": ("Kerberoasting", "credential-access"),
    "T1110": ("Brute Force", "credential-access"),
    "T1098": ("Account Manipulation", "persistence"),
    "T1197": ("BITS Jobs", "defense-evasion"),
    "T1218.005": ("Mshta", "defense-evasion"),
    "T1218.010": ("Regsvr32", "defense-evasion"),
    "T1070.001": ("Clear Windows Event Logs", "defense-evasion"),
}


def coverage(rules):
    cov = {}
    for r in rules:
        for t in r.techniques:
            cov.setdefault(t, []).append(r)
    return cov


def markdown(rules):
    cov = coverage(rules)
    lines = ["| Technique | Name | Tactic | Rules |", "|---|---|---|---|"]
    for t in sorted(cov):
        name, tactic = TECHNIQUES.get(t, ("(unmapped)", ""))
        ids = ", ".join("%s (%s)" % (r.id, r.level) for r in cov[t])
        lines.append("| %s | %s | %s | %s |" % (t, name, tactic, ids))
    return "\n".join(lines) + "\n"


def navigator_layer(rules, name="sysmonlab coverage"):
    cov = coverage(rules)
    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "techniques": [
            {"techniqueID": t, "score": len(rs), "comment": ", ".join(r.title for r in rs)}
            for t, rs in sorted(cov.items())
        ],
        "gradient": {"colors": ["#ffffff", "#66b1ff"], "minValue": 0, "maxValue": 4},
    }


def dump_layer(rules, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(navigator_layer(rules), fh, indent=2)
