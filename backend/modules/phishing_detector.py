"""
Email Phishing Detection Module
================================
Analyzes .eml email files to detect phishing and social-engineering indicators.

Checks:
  1. Header Analysis   — Sender spoofing, Reply-To mismatch, display-name impersonation
  2. Authentication    — SPF / DKIM / DMARC results
  3. URL Analysis      — IP-based URLs, URL shorteners
  4. Keyword Detection — Common phishing phrases
  5. Attachment Check  — Dangerous file types
  6. Risk Scoring      — 0–100 score with Low/Medium/High/Critical label

No external libraries required — uses only Python's built-in 'email' module.
"""

from __future__ import annotations

import email
import email.policy
import re
import urllib.parse
from pathlib import Path

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".bat", ".cmd", ".com", ".pif", ".hta",
    ".msi", ".jar", ".ps1", ".sh", ".bash", ".py", ".php", ".cgi",
    ".zip", ".rar", ".7z", ".iso", ".img",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.io", "rebrand.ly", "bl.ink", "cutt.ly", "tiny.cc",
    "is.gd", "v.gd", "rb.gy", "shorturl.at", "gg.gg", "lnkd.in",
}

TRUSTED_BRANDS = {
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "bank", "ebay", "chase", "wellsfargo", "citibank", "facebook",
    "instagram", "linkedin", "dropbox", "twitter", "support",
    "security", "helpdesk", "admin", "noreply", "service",
    "account", "billing",
}

PHISHING_PATTERNS = [
    (r"verify\s+your\s+account",                       "Verify your account"),
    (r"confirm\s+your\s+(identity|email|password)",    "Confirm your identity/email/password"),
    (r"account\s+(has been|will be|is)\s+(suspended|locked|disabled|limited|compromised)",
                                                       "Account suspended/locked/compromised"),
    (r"click\s+here\s+to\s+(verify|confirm|update|reset|activate)",
                                                       "Click here to verify/confirm/reset"),
    (r"update\s+your\s+(billing|payment|credit card|bank|account)",
                                                       "Update billing/payment info"),
    (r"unusual\s+(sign.in|login|activity|access)",     "Unusual sign-in / activity detected"),
    (r"we\s+(noticed|detected|found)\s+suspicious",    "Suspicious activity detected"),
    (r"your\s+password\s+(has expired|will expire|expires)",
                                                       "Password expired/expiring"),
    (r"act\s+(now|immediately)",                       "Act now / immediately"),
    (r"urgent\s+action\s+required",                    "Urgent action required"),
    (r"you\s+have\s+(won|been selected|been chosen)",  "You have won / been selected"),
    (r"congratulations.*prize",                        "Congratulations / prize"),
    (r"dear\s+(customer|user|member|valued\s+customer)", "Generic greeting (Dear Customer)"),
    (r"login\s+credentials",                           "Login credentials mentioned"),
    (r"one.time\s+(password|code|otp)",                "One-time password / OTP"),
    (r"kindly\s+(click|follow|visit|provide)",         "Kindly click/follow/visit"),
    (r"limited\s+time\s+offer",                        "Limited time offer"),
    (r"your\s+account\s+will\s+be\s+(closed|terminated|deleted)",
                                                       "Account will be closed/terminated"),
]

_URL_RE    = re.compile(r"https?://[^\s\"'<>)\]\}]+", re.IGNORECASE)
_IP_URL_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.IGNORECASE)
_URGENT_RE = re.compile(
    r"\b(urgent|immediately|action required|verify now|suspended|expires?|"
    r"warning|alert|attention|important notice|security alert)\b",
    re.IGNORECASE,
)
_SPAM_MAILER_RE = re.compile(
    r"(massmailer|sendblaster|phpmailer|spam|bulk.?mail|mailchimp|constant.contact)",
    re.IGNORECASE,
)


def _domain(addr: str) -> str:
    m = re.search(r"@([\w.\-]+)", addr or "")
    return m.group(1).lower().strip() if m else ""


def _check_headers(msg) -> list:
    findings = []
    from_addr   = msg.get("From", "")
    reply_to    = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    subject     = msg.get("Subject", "")
    x_mailer    = msg.get("X-Mailer", "")
    x_orig_ip   = msg.get("X-Originating-IP", "")

    from_domain        = _domain(from_addr)
    reply_to_domain    = _domain(reply_to)
    return_path_domain = _domain(return_path)

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        findings.append({
            "check":      "Reply-To Domain Mismatch",
            "finding":    f"'From' domain is '{from_domain}' but 'Reply-To' is '{reply_to_domain}'. Replies go to attacker's server.",
            "risk_score": 35,
        })

    if return_path_domain and from_domain and return_path_domain != from_domain:
        findings.append({
            "check":      "Return-Path Domain Mismatch",
            "finding":    f"'From' domain is '{from_domain}' but 'Return-Path' is '{return_path_domain}'.",
            "risk_score": 20,
        })

    if not from_addr.strip():
        findings.append({
            "check":      "Missing From Header",
            "finding":    "Email has no 'From' header — strong indicator of spam or phishing.",
            "risk_score": 40,
        })

    dn_match = re.match(r'^["\']?([^"\'<@\n]+?)["\']?\s*<([^>]+)>', from_addr)
    if dn_match:
        display_name = dn_match.group(1).strip().lower()
        actual_email = dn_match.group(2).strip().lower()
        actual_domain = _domain(actual_email)
        for brand in TRUSTED_BRANDS:
            if brand in display_name and brand not in actual_domain:
                findings.append({
                    "check":      "Display Name Spoofing",
                    "finding":    f"Display name contains '{brand}' but actual address is '{actual_email}'. Classic impersonation.",
                    "risk_score": 45,
                })
                break

    if _URGENT_RE.search(subject):
        findings.append({
            "check":      "Urgency Words in Subject",
            "finding":    f"Subject uses psychological pressure: \"{subject[:100]}\"",
            "risk_score": 15,
        })

    if x_mailer and _SPAM_MAILER_RE.search(x_mailer):
        findings.append({
            "check":      "Suspicious X-Mailer",
            "finding":    f"X-Mailer suggests a bulk/spam sending tool: \"{x_mailer}\"",
            "risk_score": 20,
        })

    if x_orig_ip:
        findings.append({
            "check":      "Originating IP Exposed",
            "finding":    f"X-Originating-IP: {x_orig_ip}. Investigate this IP for reputation.",
            "risk_score": 5,
        })

    return findings


def _check_auth(msg) -> dict:
    auth_hdr = msg.get("Authentication-Results") or msg.get("ARC-Authentication-Results") or ""
    result = {
        "spf":        "not found",
        "dkim":       "not found",
        "dmarc":      "not found",
        "raw_header": auth_hdr[:600] if auth_hdr else "No Authentication-Results header found.",
        "risk_score": 0,
    }

    if not auth_hdr:
        result["risk_score"] = 15
        result["note"] = "No Authentication-Results header. Could be from a basic mail server."
        return result

    hl = auth_hdr.lower()
    spf_m   = re.search(r"spf\s*=\s*(\w+)", hl)
    dkim_m  = re.search(r"dkim\s*=\s*(\w+)", hl)
    dmarc_m = re.search(r"dmarc\s*=\s*(\w+)", hl)

    result["spf"]   = spf_m.group(1)   if spf_m   else "not found"
    result["dkim"]  = dkim_m.group(1)  if dkim_m  else "not found"
    result["dmarc"] = dmarc_m.group(1) if dmarc_m else "not found"

    score = 0
    if result["spf"]   in ("fail", "softfail", "permerror", "none"): score += 20
    if result["dkim"]  in ("fail", "permerror", "none"):             score += 20
    if result["dmarc"] in ("fail", "permerror", "none"):             score += 20
    result["risk_score"] = score

    return result


def _get_body_text(msg) -> str:
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                parts.append(payload.decode(charset, errors="replace"))
        except Exception:
            raw = msg.get_payload()
            if isinstance(raw, str):
                parts.append(raw)
    return "\n".join(parts)


def _analyze_urls(body: str) -> dict:
    all_urls = list(dict.fromkeys(_URL_RE.findall(body)))
    ip_urls = []
    shortener_urls = []

    for url in all_urls:
        if _IP_URL_RE.match(url):
            ip_urls.append(url)
        else:
            try:
                host = urllib.parse.urlparse(url).netloc.lower().lstrip("www.")
                if host in URL_SHORTENERS:
                    shortener_urls.append(url)
            except Exception:
                pass

    score = 0
    if ip_urls:        score += min(len(ip_urls) * 20, 40)
    if shortener_urls: score += min(len(shortener_urls) * 10, 30)
    if len(all_urls) > 15: score += 10

    return {
        "total_urls":     len(all_urls),
        "urls":           all_urls[:30],
        "ip_based_urls":  ip_urls,
        "shortener_urls": shortener_urls,
        "risk_score":     score,
    }


def _check_keywords(body: str) -> dict:
    matches = []
    for pattern, label in PHISHING_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            matches.append(label)
    return {
        "keyword_matches": matches,
        "match_count":     len(matches),
        "risk_score":      min(len(matches) * 10, 40),
    }


def _check_attachments(msg) -> dict:
    all_attachments = []
    dangerous = []

    for part in msg.walk():
        disposition = part.get_content_disposition() or ""
        if "attachment" not in disposition:
            continue
        filename  = part.get_filename() or "unnamed_attachment"
        ext       = Path(filename).suffix.lower()
        mime_type = part.get_content_type()
        is_bad    = ext in DANGEROUS_EXTENSIONS

        all_attachments.append({
            "filename":     filename,
            "extension":    ext or "(none)",
            "mime_type":    mime_type,
            "is_dangerous": is_bad,
        })
        if is_bad:
            dangerous.append(filename)

    return {
        "total_attachments":     len(all_attachments),
        "attachments":           all_attachments,
        "dangerous_attachments": dangerous,
        "risk_score":            min(len(dangerous) * 30, 60),
    }


def _calculate_risk(header: int, auth: int, url: int, kw: int, attach: int):
    total = min(header + auth + url + kw + attach, 100)
    if total <= 25:   label = "Low"
    elif total <= 50: label = "Medium"
    elif total <= 75: label = "High"
    else:             label = "Critical"
    return total, label


def analyze_email(file_path: str) -> dict:
    """
    Parse a .eml file and run all phishing detection checks.

    Returns full analysis dict with risk_score, risk_level, and summary.
    """
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    try:
        raw = path.read_bytes()
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception as exc:
        return {"error": f"Failed to parse email file: {exc}"}

    header_findings  = _check_headers(msg)
    auth_results     = _check_auth(msg)
    body_text        = _get_body_text(msg)
    url_analysis     = _analyze_urls(body_text)
    keyword_analysis = _check_keywords(body_text)
    attachments      = _check_attachments(msg)

    h_score  = sum(f["risk_score"] for f in header_findings)
    a_score  = auth_results["risk_score"]
    u_score  = url_analysis["risk_score"]
    k_score  = keyword_analysis["risk_score"]
    at_score = attachments["risk_score"]

    total_score, risk_level = _calculate_risk(h_score, a_score, u_score, k_score, at_score)

    summary_parts = []
    if header_findings:
        summary_parts.append(f"{len(header_findings)} header issue(s) found (spoofing or mismatch).")
    if auth_results["spf"] not in ("pass", "not found"):
        summary_parts.append(f"SPF check: {auth_results['spf']}.")
    if auth_results["dkim"] not in ("pass", "not found"):
        summary_parts.append(f"DKIM check: {auth_results['dkim']}.")
    if auth_results["dmarc"] not in ("pass", "not found"):
        summary_parts.append(f"DMARC check: {auth_results['dmarc']}.")
    if url_analysis["ip_based_urls"]:
        summary_parts.append(f"{len(url_analysis['ip_based_urls'])} IP-based URL(s) detected.")
    if url_analysis["shortener_urls"]:
        summary_parts.append(f"{len(url_analysis['shortener_urls'])} URL shortener link(s) found.")
    if keyword_analysis["match_count"]:
        summary_parts.append(f"{keyword_analysis['match_count']} phishing keyword pattern(s) matched.")
    if attachments["dangerous_attachments"]:
        summary_parts.append(f"DANGEROUS attachment(s): {', '.join(attachments['dangerous_attachments'])}.")

    summary = " ".join(summary_parts) if summary_parts else "No significant phishing indicators found. Email appears clean."

    return {
        "email_headers": {
            "From":             msg.get("From",             "—"),
            "To":               msg.get("To",               "—"),
            "Subject":          msg.get("Subject",          "—"),
            "Date":             msg.get("Date",             "—"),
            "Reply-To":         msg.get("Reply-To",         "—"),
            "Return-Path":      msg.get("Return-Path",      "—"),
            "Message-ID":       msg.get("Message-ID",       "—"),
            "X-Mailer":         msg.get("X-Mailer",         "—"),
            "X-Originating-IP": msg.get("X-Originating-IP","—"),
            "MIME-Version":     msg.get("MIME-Version",     "—"),
        },
        "header_checks":    header_findings,
        "auth_results":     auth_results,
        "url_analysis":     url_analysis,
        "keyword_analysis": keyword_analysis,
        "attachments":      attachments,
        "risk_score":       total_score,
        "risk_level":       risk_level,
        "summary":          summary,
        "error":            None,
    }
