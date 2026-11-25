import argparse
import json
import sys

from . import attack, engine, events as ev_mod, rules as rules_mod, simulate


def _load_rules(path):
    try:
        return rules_mod.load_rules(path)
    except rules_mod.RuleError as exc:
        print("rule error: %s" % exc, file=sys.stderr)
        sys.exit(2)


def cmd_detect(a):
    rules = _load_rules(a.rules)
    events = ev_mod.load_events(a.events)
    dets = engine.run(rules, events)
    if a.json:
        print(json.dumps([d.as_dict() for d in dets], indent=2))
    else:
        for d in dets:
            x = d.as_dict()
            print("[%-8s] %s  %s  %s  %s" % (x["level"].upper(), x["time"], x["computer"], x["rule_id"], x["title"]))
        print("\n%d detections from %d events using %d rules" % (len(dets), len(events), len(rules)))
    return 1 if dets and a.fail_on_detect else 0


def cmd_simulate(a):
    events = simulate.generate(a.seed, a.noise)
    with open(a.out, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
    print("wrote %d events to %s" % (len(events), a.out))
    return 0


def cmd_validate(a):
    rules = _load_rules(a.rules)
    print("ok: %d rules" % len(rules))
    return 0


def cmd_coverage(a):
    rules = _load_rules(a.rules)
    if a.layer:
        attack.dump_layer(rules, a.layer)
        print("wrote ATT&CK Navigator layer to %s" % a.layer)
    else:
        print(attack.markdown(rules))
    return 0


def cmd_evaluate(a):
    rules = _load_rules(a.rules)
    res = simulate.evaluate(rules, simulate.generate(a.seed, a.noise))
    print("rules: %(rules)d  expected: %(expected_rules)d  fired: %(fired_rules)d  detections: %(detections)d" % res)
    print("missed rules:", res["missed"] or "none")
    print("false positives:", len(res["false_positives"]))
    for fp in res["false_positives"][:10]:
        print("  ", fp["rule_id"], fp["time"], fp["command_line"] or fp["image"])
    return 0 if not res["missed"] and not res["false_positives"] else 1


def cmd_convert(a):
    events = ev_mod.load_events(a.input)
    with open(a.out, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
    print("converted %d events" % len(events))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="sysmonlab", description="Sigma-style detection lab for Sysmon/Windows events")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("detect", help="run rules over an event file (xml, jsonl, csv)")
    d.add_argument("events")
    d.add_argument("--rules", default="rules")
    d.add_argument("--json", action="store_true")
    d.add_argument("--fail-on-detect", action="store_true")
    d.set_defaults(fn=cmd_detect)
    s = sub.add_parser("simulate", help="write labelled synthetic events")
    s.add_argument("--out", default="data/sample_events.jsonl")
    s.add_argument("--seed", type=int, default=7)
    s.add_argument("--noise", type=int, default=150)
    s.set_defaults(fn=cmd_simulate)
    v = sub.add_parser("validate", help="load and compile every rule")
    v.add_argument("--rules", default="rules")
    v.set_defaults(fn=cmd_validate)
    c = sub.add_parser("coverage", help="ATT&CK coverage table or Navigator layer")
    c.add_argument("--rules", default="rules")
    c.add_argument("--layer")
    c.set_defaults(fn=cmd_coverage)
    e = sub.add_parser("evaluate", help="score rules against the labelled simulation")
    e.add_argument("--rules", default="rules")
    e.add_argument("--seed", type=int, default=7)
    e.add_argument("--noise", type=int, default=150)
    e.set_defaults(fn=cmd_evaluate)
    x = sub.add_parser("convert", help="convert xml/csv events to jsonl")
    x.add_argument("input")
    x.add_argument("--out", required=True)
    x.set_defaults(fn=cmd_convert)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
