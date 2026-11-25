"""Sigma-style rule loading and matching.

Supported subset of Sigma:
  * selections: maps (AND of fields) or lists of maps (OR)
  * field modifiers: contains, startswith, endswith, all, re, cidr, lt, lte, gt, gte
  * conditions: and / or / not / parentheses / "1 of sel*" / "all of sel*" / "1 of them" / "all of them"
  * wildcards (* and ?) in plain values, case-insensitive matching
Extension: `x-threshold: {group_by: [Field], count: N, window: seconds}` for simple aggregation.
"""
import fnmatch
import glob
import ipaddress
import os
import re

import yaml

CATEGORY_EVENT_IDS = {
    "process_creation": [1],
    "file_change_time": [2],
    "network_connection": [3],
    "driver_load": [6],
    "image_load": [7],
    "create_remote_thread": [8],
    "process_access": [10],
    "file_event": [11],
    "registry_event": [12, 13, 14],
    "registry_set": [13],
    "pipe_created": [17, 18],
    "wmi_event": [19, 20, 21],
    "dns_query": [22],
}

LEVELS = ["informational", "low", "medium", "high", "critical"]


class RuleError(Exception):
    pass


def _to_list(v):
    return v if isinstance(v, list) else [v]


def _field_matcher(field_spec, expected):
    parts = field_spec.split("|")
    field, mods = parts[0], parts[1:]
    values = _to_list(expected)
    require_all = "all" in mods

    def one(actual, exp):
        if exp is None:
            return actual in (None, "")
        if actual is None:
            return False
        if "re" in mods:
            return re.search(str(exp), str(actual), re.I) is not None
        if "cidr" in mods:
            try:
                return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(exp), strict=False)
            except ValueError:
                return False
        for op, fn in (("lt", lambda a, b: a < b), ("lte", lambda a, b: a <= b),
                       ("gt", lambda a, b: a > b), ("gte", lambda a, b: a >= b)):
            if op in mods:
                try:
                    return fn(float(actual), float(exp))
                except (TypeError, ValueError):
                    return False
        a = str(actual).lower()
        e = str(exp).lower()
        if "contains" in mods:
            return fnmatch.fnmatchcase(a, "*" + e + "*") if ("*" in e or "?" in e) else e in a
        if "startswith" in mods:
            return fnmatch.fnmatchcase(a, e + "*")
        if "endswith" in mods:
            return fnmatch.fnmatchcase(a, "*" + e)
        if "*" in e or "?" in e:
            return fnmatch.fnmatchcase(a, e)
        return a == e

    def match(event):
        actual = event.get(field)
        results = (one(actual, v) for v in values)
        return all(results) if require_all else any(results)

    return match


def _compile_selection(sel):
    if isinstance(sel, dict):
        matchers = [_field_matcher(k, v) for k, v in sel.items()]
        return lambda ev: all(m(ev) for m in matchers)
    if isinstance(sel, list):
        # list of maps -> OR; list of strings -> keyword search over all values
        subs = []
        for item in sel:
            if isinstance(item, dict):
                subs.append(_compile_selection(item))
            else:
                kw = str(item).lower()
                subs.append(lambda ev, kw=kw: any(kw in str(v).lower() for v in ev.values()))
        return lambda ev: any(s(ev) for s in subs)
    raise RuleError("bad selection: %r" % (sel,))


TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")


class _Parser:
    def __init__(self, text, selections):
        self.tokens = TOKEN_RE.findall(text)
        self.pos = 0
        self.sel = selections

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self):
        tok = self.peek()
        self.pos += 1
        return tok

    def parse(self):
        node = self.or_expr()
        if self.peek() is not None:
            raise RuleError("unexpected token %r in condition" % self.peek())
        return node

    def or_expr(self):
        left = self.and_expr()
        while (self.peek() or "").lower() == "or":
            self.take()
            right = self.and_expr()
            left = (lambda a, b: lambda ev: a(ev) or b(ev))(left, right)
        return left

    def and_expr(self):
        left = self.not_expr()
        while (self.peek() or "").lower() == "and":
            self.take()
            right = self.not_expr()
            left = (lambda a, b: lambda ev: a(ev) and b(ev))(left, right)
        return left

    def not_expr(self):
        if (self.peek() or "").lower() == "not":
            self.take()
            inner = self.not_expr()
            return lambda ev: not inner(ev)
        return self.atom()

    def atom(self):
        tok = self.take()
        if tok is None:
            raise RuleError("condition ended unexpectedly")
        if tok == "(":
            node = self.or_expr()
            if self.take() != ")":
                raise RuleError("missing )")
            return node
        low = tok.lower()
        if low in ("1", "all") and (self.peek() or "").lower() == "of":
            self.take()
            pattern = self.take()
            names = list(self.sel) if pattern == "them" else fnmatch.filter(list(self.sel), pattern)
            if not names:
                raise RuleError("no selections match %r" % pattern)
            fns = [self.sel[n] for n in names]
            if low == "all":
                return lambda ev: all(f(ev) for f in fns)
            return lambda ev: any(f(ev) for f in fns)
        if tok not in self.sel:
            raise RuleError("unknown selection %r" % tok)
        return self.sel[tok]


class Rule:
    def __init__(self, data, path=""):
        self.path = path
        self.data = data
        for key in ("title", "id", "detection", "level"):
            if key not in data:
                raise RuleError("%s: missing %r" % (path, key))
        self.title = data["title"]
        self.id = str(data["id"])
        self.level = data["level"]
        if self.level not in LEVELS:
            raise RuleError("%s: bad level %r" % (path, self.level))
        self.tags = data.get("tags", [])
        self.logsource = data.get("logsource", {})
        self.threshold = data.get("x-threshold")
        det = data["detection"]
        cond = det.get("condition")
        if not cond:
            raise RuleError("%s: detection has no condition" % path)
        sels = {k: _compile_selection(v) for k, v in det.items() if k not in ("condition", "timeframe")}
        self._match = _Parser(cond, sels).parse()
        cat = self.logsource.get("category")
        self.event_ids = CATEGORY_EVENT_IDS.get(cat) if cat else None
        if cat and self.event_ids is None:
            raise RuleError("%s: unknown logsource category %r" % (path, cat))
        self.channel = None
        if self.logsource.get("service") == "security":
            self.channel = "Security"

    @property
    def techniques(self):
        out = []
        for t in self.tags:
            m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)$", str(t).lower())
            if m:
                out.append(m.group(1).upper())
        return out

    def matches(self, event):
        if self.event_ids is not None and event.get("EventID") not in self.event_ids:
            return False
        if self.channel is not None and event.get("Channel") != self.channel:
            return False
        return bool(self._match(event))


def load_rule_file(path):
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return Rule(data, path)


def load_rules(path):
    files = [path] if os.path.isfile(path) else sorted(glob.glob(os.path.join(path, "**", "*.yml"), recursive=True))
    rules = [load_rule_file(f) for f in files]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError("duplicate rule ids: %s" % ", ".join(sorted(dupes)))
    return rules
