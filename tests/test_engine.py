import os
import unittest

from sysmonlab import attack, engine, events, rules, simulate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "rules")


def mk(detection, **kw):
    d = {"title": "t", "id": "x-1", "level": "low", "detection": detection}
    d.update(kw)
    return rules.Rule(d)


class ModifierTests(unittest.TestCase):
    def test_contains_case_insensitive(self):
        r = mk({"s": {"CommandLine|contains": "MiMi"}, "condition": "s"})
        self.assertTrue(r.matches({"CommandLine": "run mimikatz"}))
        self.assertFalse(r.matches({"CommandLine": "run notepad"}))

    def test_all_modifier(self):
        r = mk({"s": {"CommandLine|contains|all": ["delete", "shadows"]}, "condition": "s"})
        self.assertTrue(r.matches({"CommandLine": "vssadmin delete shadows /all"}))
        self.assertFalse(r.matches({"CommandLine": "vssadmin delete foo"}))

    def test_startswith_endswith_wildcard(self):
        r = mk({"a": {"Image|endswith": ".exe"}, "b": {"User": "LAB\\*"}, "condition": "a and b"})
        self.assertTrue(r.matches({"Image": "C:\\x.exe", "User": "LAB\\bob"}))
        self.assertFalse(r.matches({"Image": "C:\\x.dll", "User": "LAB\\bob"}))

    def test_cidr_and_numeric(self):
        r = mk({"s": {"DestinationIp|cidr": "10.0.0.0/8", "DestinationPort|gt": 1000}, "condition": "s"})
        self.assertTrue(r.matches({"DestinationIp": "10.1.2.3", "DestinationPort": "4444"}))
        self.assertFalse(r.matches({"DestinationIp": "8.8.8.8", "DestinationPort": "4444"}))

    def test_regex(self):
        r = mk({"s": {"QueryName|re": "^[a-z]{5}\\d+\\.com$"}, "condition": "s"})
        self.assertTrue(r.matches({"QueryName": "abcde12.com"}))
        self.assertFalse(r.matches({"QueryName": "abc.com"}))

    def test_null_means_missing(self):
        r = mk({"s": {"ParentImage": None}, "condition": "s"})
        self.assertTrue(r.matches({"Image": "a"}))
        self.assertFalse(r.matches({"ParentImage": "b"}))


class ConditionTests(unittest.TestCase):
    def test_not_and_or_parens(self):
        det = {"a": {"X": "1"}, "b": {"Y": "2"}, "c": {"Z": "3"}, "condition": "(a or b) and not c"}
        r = mk(det)
        self.assertTrue(r.matches({"X": "1"}))
        self.assertTrue(r.matches({"Y": "2"}))
        self.assertFalse(r.matches({"X": "1", "Z": "3"}))
        self.assertFalse(r.matches({}))

    def test_one_of_and_all_of(self):
        det = {"sel_a": {"X": "1"}, "sel_b": {"Y": "2"}, "condition": "1 of sel*"}
        self.assertTrue(mk(det).matches({"Y": "2"}))
        det["condition"] = "all of them"
        self.assertFalse(mk(det).matches({"Y": "2"}))
        self.assertTrue(mk(det).matches({"X": "1", "Y": "2"}))

    def test_list_of_maps_is_or(self):
        r = mk({"s": [{"X": "1"}, {"Y": "2"}], "condition": "s"})
        self.assertTrue(r.matches({"Y": "2"}))

    def test_bad_conditions(self):
        with self.assertRaises(rules.RuleError):
            mk({"a": {"X": "1"}, "condition": "a and"})
        with self.assertRaises(rules.RuleError):
            mk({"a": {"X": "1"}, "condition": "b"})
        with self.assertRaises(rules.RuleError):
            mk({"a": {"X": "1"}, "condition": "(a"})

    def test_logsource_filters_event_id(self):
        r = mk({"s": {"Image|endswith": "a.exe"}, "condition": "s"}, logsource={"category": "process_creation"})
        self.assertTrue(r.matches({"EventID": 1, "Image": "a.exe"}))
        self.assertFalse(r.matches({"EventID": 3, "Image": "a.exe"}))


class ThresholdTests(unittest.TestCase):
    def test_threshold_fires_once_in_window(self):
        r = mk({"s": {"EventID": 4625}, "condition": "s"}, **{"x-threshold": {"group_by": ["IpAddress"], "count": 3, "window": 30}})
        evs = [{"EventID": 4625, "IpAddress": "1.1.1.1", "UtcTime": "2026-03-01T10:00:%02d" % s} for s in (0, 5, 10, 12)]
        self.assertEqual(len(engine.run([r], evs)), 1)

    def test_threshold_window_expires(self):
        r = mk({"s": {"EventID": 4625}, "condition": "s"}, **{"x-threshold": {"group_by": ["IpAddress"], "count": 3, "window": 10}})
        evs = [{"EventID": 4625, "IpAddress": "1.1.1.1", "UtcTime": "2026-03-01T10:00:%02d" % s} for s in (0, 20, 40)]
        self.assertEqual(engine.run([r], evs), [])

    def test_threshold_groups_separately(self):
        r = mk({"s": {"EventID": 4625}, "condition": "s"}, **{"x-threshold": {"group_by": ["IpAddress"], "count": 2, "window": 60}})
        evs = [{"EventID": 4625, "IpAddress": ip, "UtcTime": "2026-03-01T10:00:%02d" % s}
               for s, ip in ((0, "a"), (1, "b"), (2, "a"))]
        self.assertEqual(len(engine.run([r], evs)), 1)


class ShippedRulesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = rules.load_rules(RULES)

    def test_all_rules_load_and_have_attack_tags(self):
        self.assertGreaterEqual(len(self.rules), 19)
        for r in self.rules:
            self.assertTrue(r.techniques, r.id + " has no ATT&CK technique tag")

    def test_all_techniques_are_named(self):
        for r in self.rules:
            for t in r.techniques:
                self.assertIn(t, attack.TECHNIQUES, "%s uses unmapped %s" % (r.id, t))

    def test_simulation_has_full_recall_and_no_false_positives(self):
        res = simulate.evaluate(self.rules, simulate.generate(7, 150))
        self.assertEqual(res["missed"], [])
        self.assertEqual(res["false_positives"], [])

    def test_other_seeds_still_clean(self):
        for seed in (1, 2, 3):
            res = simulate.evaluate(self.rules, simulate.generate(seed, 200))
            self.assertEqual(res["missed"], [], seed)
            self.assertEqual(res["false_positives"], [], seed)

    def test_xml_parsing_and_detection(self):
        evs = events.load_events(os.path.join(ROOT, "data", "sample_sysmon.xml"))
        self.assertEqual(len(evs), 2)
        self.assertEqual(evs[0]["Computer"], "WS01.lab.local")
        ids = {d.rule.id for d in engine.run(self.rules, evs)}
        self.assertEqual(ids, {"sl-0001", "sl-0002", "sl-0010"})

    def test_navigator_layer(self):
        layer = attack.navigator_layer(self.rules)
        ids = {t["techniqueID"] for t in layer["techniques"]}
        self.assertIn("T1003.001", ids)


if __name__ == "__main__":
    unittest.main()
