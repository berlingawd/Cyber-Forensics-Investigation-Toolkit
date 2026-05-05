"""
Timeline Generator Module
=========================
Generates a chronological timeline of attack events from logs.
Used to reconstruct the sequence of events during an incident.
"""

from datetime import datetime
from pathlib import Path
import re

try:
    from dateutil import parser as date_parser
    DATEUTIL_AVAILABLE = True
except ImportError:
    DATEUTIL_AVAILABLE = False


def parse_log_timestamp(ts_str: str):
    if not ts_str or not ts_str.strip():
        return None
    ts_str = ts_str.strip()

    if DATEUTIL_AVAILABLE:
        try:
            return date_parser.parse(ts_str)
        except Exception:
            pass
        try:
            parts = ts_str.split()
            if len(parts) >= 3:
                year = datetime.now().year
                date_str = f"{parts[0]} {parts[1]} {year} {parts[2]}"
                return date_parser.parse(date_str)
        except Exception:
            pass
    else:
        # Fallback without dateutil: parse "Mon DD HH:MM:SS"
        try:
            months = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
                      "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}
            parts = ts_str.split()
            if len(parts) >= 3 and parts[0] in months:
                year = datetime.now().year
                month = months[parts[0]]
                day = int(parts[1])
                t = parts[2].split(":")
                return datetime(year, month, day, int(t[0]), int(t[1]), int(t[2]))
        except Exception:
            pass
    return None


def extract_events_from_auth_log(file_path: str) -> list:
    path = Path(file_path)
    if not path.exists():
        return []

    events = []
    ts_pattern = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            match = ts_pattern.match(line)
            if match:
                ts_str = match.group(1)
                dt = parse_log_timestamp(ts_str)
                if "Failed password" in line or "Invalid user" in line:
                    desc = "Failed login attempt"
                elif "Accepted" in line:
                    desc = "Successful login"
                elif "session opened" in line.lower():
                    desc = "Session opened"
                elif "session closed" in line.lower():
                    desc = "Session closed"
                else:
                    desc = line[line.find(" "):].strip()[:80] if len(line) > 20 else line
                events.append({
                    "time": dt,
                    "time_str": ts_str,
                    "event": desc,
                })

    return events


def build_timeline(log_events: list, pcap_events: list = None, manual_events: list = None) -> list:
    all_entries = []

    for e in log_events:
        t = e.get("time")
        if t:
            all_entries.append((t, e.get("time_str", str(t)), e.get("event", "")))

    if pcap_events:
        for e in pcap_events:
            t = e.get("time")
            if t:
                all_entries.append((t, str(t), e.get("event", "")))

    if manual_events:
        for e in manual_events:
            ts = e.get("time_str", "")
            ev = e.get("event", "")
            t = parse_log_timestamp(ts) if ts else datetime.now()
            all_entries.append((t, ts or str(t), ev))

    all_entries.sort(key=lambda x: x[0])

    return [{"time_str": ts, "event": ev} for _, ts, ev in all_entries]


def generate_timeline_from_log_file(file_path: str) -> list:
    events = extract_events_from_auth_log(file_path)
    return build_timeline(events)
