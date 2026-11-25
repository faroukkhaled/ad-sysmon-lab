"""Run rules over events, with optional threshold aggregation."""
from collections import defaultdict, deque
from datetime import datetime


def parse_time(s):
    if not s:
        return None
    s = str(s).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).replace(tzinfo=None)
    except ValueError:
        return None


class Detection:
    def __init__(self, rule, event, extra=None):
        self.rule = rule
        self.event = event
        self.extra = extra or {}

    def as_dict(self):
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "level": self.rule.level,
            "techniques": self.rule.techniques,
            "time": self.event.get("UtcTime"),
            "computer": self.event.get("Computer"),
            "user": self.event.get("User"),
            "image": self.event.get("Image"),
            "command_line": self.event.get("CommandLine"),
            "extra": self.extra,
        }


def run(rules, events):
    events = sorted(events, key=lambda e: parse_time(e.get("UtcTime")) or datetime.min)
    detections = []
    windows = defaultdict(deque)
    fired = set()
    for ev in events:
        for rule in rules:
            if not rule.matches(ev):
                continue
            th = rule.threshold
            if not th:
                detections.append(Detection(rule, ev))
                continue
            key = (rule.id,) + tuple(ev.get(f) for f in th["group_by"])
            now = parse_time(ev.get("UtcTime"))
            win = windows[key]
            win.append(now)
            while win and (now - win[0]).total_seconds() > th["window"]:
                win.popleft()
            if len(win) >= th["count"] and key not in fired:
                fired.add(key)
                detections.append(Detection(rule, ev, {"count": len(win), "window_s": th["window"]}))
    return detections
