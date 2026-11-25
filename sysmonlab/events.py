"""Event loading and normalisation.

Everything is turned into a flat dict using Sysmon field names (Image, CommandLine, ...)
plus a few common keys: EventID (int), Channel, Computer, UtcTime.
Supported inputs: Sysmon/Windows XML (one <Event> per file or a wrapping <Events>), JSON lines, CSV.
"""
import csv
import json
import re
import xml.etree.ElementTree as ET

NS_RE = re.compile(r"^\{.*?\}")


def _strip(tag):
    return NS_RE.sub("", tag)


def parse_xml_event(elem):
    ev = {}
    system = None
    data = None
    for child in elem:
        name = _strip(child.tag)
        if name == "System":
            system = child
        elif name == "EventData":
            data = child
    if system is not None:
        for node in system:
            name = _strip(node.tag)
            if name == "EventID":
                try:
                    ev["EventID"] = int((node.text or "0").strip())
                except ValueError:
                    ev["EventID"] = 0
            elif name == "Computer":
                ev["Computer"] = (node.text or "").strip()
            elif name == "Channel":
                ev["Channel"] = (node.text or "").strip()
            elif name == "Provider":
                ev["Provider"] = node.attrib.get("Name", "")
            elif name == "TimeCreated":
                ev["UtcTime"] = node.attrib.get("SystemTime", "")
    if data is not None:
        for node in data:
            if _strip(node.tag) == "Data" and node.attrib.get("Name"):
                ev[node.attrib["Name"]] = (node.text or "").strip()
    return normalise(ev)


def load_xml(path):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    # tolerate multiple concatenated <Event> documents (wevtutil output)
    text = re.sub(r"<\?xml[^>]*\?>", "", text)
    root = ET.fromstring("<Events>" + text + "</Events>") if not text.lstrip().startswith("<Events") else ET.fromstring(text)
    for elem in root:
        if _strip(elem.tag) == "Event":
            yield parse_xml_event(elem)


def load_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield normalise(json.loads(line))


def load_csv(path):
    with open(path, encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            yield normalise(dict(row))


def normalise(ev):
    out = dict(ev)
    if "EventID" in out:
        try:
            out["EventID"] = int(out["EventID"])
        except (TypeError, ValueError):
            out["EventID"] = 0
    if "Channel" not in out:
        out["Channel"] = "Security" if (out.get("EventID", 0) >= 4000 or out.get("EventID") == 1102) else "Microsoft-Windows-Sysmon/Operational"
    # field aliases used by other collectors (e.g. OTRF / Mordor JSON exports)
    if "Computer" not in out and out.get("Hostname"):
        out["Computer"] = out["Hostname"]
    if "UtcTime" not in out:
        for alt in ("TimeCreated", "EventTime", "@timestamp"):
            if out.get(alt):
                out["UtcTime"] = out[alt]
                break
    if "Image" in out and "ProcessName" not in out:
        out["ProcessName"] = out["Image"].rsplit("\\", 1)[-1]
    return out


def load_events(path):
    p = path.lower()
    if p.endswith(".xml"):
        return list(load_xml(path))
    if p.endswith(".csv"):
        return list(load_csv(path))
    return list(load_jsonl(path))
