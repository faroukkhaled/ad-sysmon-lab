"""Check the rules against real OTRF telemetry committed in data/real/ (see data/real/README.md)."""
import os
import unittest

from sysmonlab import engine, events, rules

ROOT = os.path.join(os.path.dirname(__file__), "..")
CASES = {
    "mimikatz_logonpasswords": "sl-0010",
    "lsass_dump_comsvcs": "sl-0010",
    "dcsync_drsuapi": "sl-0017",
    "run_key_persistence": "sl-0011",
    "regsvr32_sct_launcher": "sl-0021",
    "mshta_vbscript_psh": "sl-0022",
    "bitsadmin_download": "sl-0023",
}


class RealData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = rules.load_rules(os.path.join(ROOT, "rules"))

    def test_expected_rule_fires_on_real_telemetry(self):
        for name, rule_id in CASES.items():
            path = os.path.join(ROOT, "data", "real", name + ".jsonl")
            evs = events.load_events(path)
            self.assertGreater(len(evs), 50, name)
            fired = {d.rule.id for d in engine.run(self.rules, evs)}
            self.assertIn(rule_id, fired, name)


if __name__ == "__main__":
    unittest.main()
