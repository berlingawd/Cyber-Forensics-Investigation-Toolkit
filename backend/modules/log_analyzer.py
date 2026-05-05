"""
Log Analyzer Module
==================
Parses Linux auth.log or system logs to detect:
- Failed login attempts
- Brute force login attempts
- Suspicious IP addresses

Returns structured results for investigation.
"""

import re
from collections import defaultdict
from pathlib import Path


FAILED_LOGIN_PATTERN = re.compile(
    r"(?:Failed password|Invalid user)\s+(?:for\s+)?(?:invalid\s+user\s+)?\S+\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE
)
AUTH_LOGIN_PATTERN = re.compile(
    r"Accepted\s+(?:password|publickey).*?\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE
)
TIMESTAMP_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

BRUTE_FORCE_THRESHOLD = 5


def extract_timestamp(line: str) -> str:
    match = TIMESTAMP_PATTERN.match(line.strip())
    return match.group(1) if match else ""


def parse_auth_log(file_path: str) -> dict:
    """
    Parse Linux auth.log style file and detect suspicious activity.

    Returns:
        Dictionary with suspicious_ips, failed_logins, brute_force_detected
    """
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}", "suspicious_ips": [], "failed_logins": [], "brute_force_detected": []}

    failed_by_ip = defaultdict(list)
    failed_logins = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                ts = extract_timestamp(line)

                match = FAILED_LOGIN_PATTERN.search(line)
                if match:
                    ip = match.group(1)
                    failed_by_ip[ip].append((ts, line[:200]))
                    failed_logins.append({"ip": ip, "timestamp": ts, "event": "Failed login"})

                auth_match = AUTH_LOGIN_PATTERN.search(line)
                if auth_match:
                    ip = auth_match.group(1)
                    failed_logins.append({"ip": ip, "timestamp": ts, "event": "Accepted login"})
    except Exception as e:
        return {"error": str(e), "suspicious_ips": [], "failed_logins": [], "brute_force_detected": []}

    suspicious_ips = []
    brute_force_detected = []

    for ip, events in failed_by_ip.items():
        count = len(events)
        event_type = "Brute force attempt" if count >= BRUTE_FORCE_THRESHOLD else "Failed login"
        suspicious_ips.append({
            "suspicious_ip": ip,
            "number_of_attempts": count,
            "event_type": event_type,
        })
        if count >= BRUTE_FORCE_THRESHOLD:
            brute_force_detected.append(ip)

    suspicious_ips.sort(key=lambda x: x["number_of_attempts"], reverse=True)

    return {
        "suspicious_ips": suspicious_ips,
        "failed_logins": failed_logins[:500],
        "brute_force_detected": brute_force_detected,
        "error": None,
    }
