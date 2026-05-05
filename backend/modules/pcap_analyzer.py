"""
Network PCAP Analyzer Module
===========================
Analyzes PCAP files using Scapy to detect:
- Suspicious IP addresses (external IPs, high connection count)
- DNS queries
- Connections to unusual ports
"""

from pathlib import Path
from collections import defaultdict

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

SUSPICIOUS_PORTS = {
    4444, 4443, 5555, 6666, 6667, 8080, 31337, 12345, 12346,
    54321, 9999, 1337, 65535,
}
COMMON_PORTS = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 3306, 5432, 8080}


def analyze_pcap(file_path: str) -> dict:
    """
    Analyze a PCAP file and extract connection info, DNS, and suspicious indicators.
    """
    if not SCAPY_AVAILABLE:
        return {
            "error": "Scapy is not installed. Run: pip install scapy",
            "connections": [],
            "dns_queries": [],
            "suspicious_ips": [],
            "unusual_ports": [],
        }

    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}", "connections": [], "dns_queries": [], "suspicious_ips": [], "unusual_ports": []}

    connections = []
    connection_keys = set()
    dns_queries = []
    dst_count = defaultdict(int)
    unusual_ports_list = []

    try:
        packets = rdpcap(str(path))
    except Exception as e:
        return {"error": str(e), "connections": [], "dns_queries": [], "suspicious_ips": [], "unusual_ports": []}

    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER"
            sport = dport = None
            if pkt.haslayer(TCP):
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
            elif pkt.haslayer(UDP):
                sport, dport = pkt[UDP].sport, pkt[UDP].dport

            key = (src, dst, sport, dport)
            if key not in connection_keys and (sport is not None or dport is not None):
                connection_keys.add(key)
                connections.append({
                    "source_ip": src,
                    "destination_ip": dst,
                    "protocol": proto,
                    "source_port": sport,
                    "destination_port": dport,
                })
                dst_count[dst] += 1
                if dport and dport not in COMMON_PORTS and dport in SUSPICIOUS_PORTS:
                    unusual_ports_list.append({"ip": dst, "port": dport, "protocol": proto})

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore") if hasattr(pkt[DNSQR].qname, "decode") else str(pkt[DNSQR].qname)
                dns_queries.append({"query": qname, "source_ip": src})

    suspicious_ips = []
    for ip, count in sorted(dst_count.items(), key=lambda x: -x[1])[:30]:
        if count > 10 or ip in [u["ip"] for u in unusual_ports_list]:
            suspicious_ips.append(ip)

    seen_port = set()
    unique_unusual = []
    for u in unusual_ports_list:
        k = (u["ip"], u["port"])
        if k not in seen_port:
            seen_port.add(k)
            unique_unusual.append(u)

    return {
        "error": None,
        "connections": connections[:500],
        "dns_queries": list({q["query"] for q in dns_queries})[:200],
        "suspicious_ips": list(set(suspicious_ips)),
        "unusual_ports": unique_unusual,
    }
