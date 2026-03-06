# ============================================================
# SOC-Sentinel — AI-Powered Security Operations Center
# Author: LAHOUCINE JAKOUM
# GitHub: github.com/houssainjacoum91-hue
# ============================================================

import re
import json
import math
from collections import Counter, defaultdict
from datetime import datetime

BANNER = """
╔══════════════════════════════════════════════════════════╗
║        SOC-SENTINEL — AI Security Operations Center      ║
║        Author: LAHOUCINE JAKOUM  |  Morocco 🇲🇦           ║
║        github.com/houssainjacoum91-hue                   ║
╚══════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────
# 1. THREAT INTELLIGENCE DATABASE
# ─────────────────────────────────────────

THREAT_DB = {
    "malicious_ips": [
        "192.168.1.666", "10.0.0.999", "172.16.0.666",
        "185.220.101.45", "45.142.212.100", "91.108.4.0",
    ],
    "ransomware_signatures": [
        "wannacry", "lockbit", "ryuk", "conti", "revil", "blackcat"
    ],
    "c2_domains": [
        "malware-c2.net", "botnet-master.ru", "evil-payload.xyz",
        "data-exfil.cn", "ransomware-host.io"
    ],
    "attack_patterns": {
        "sql_injection"    : r"(union|select|insert|drop|delete|exec|sleep|benchmark)",
        "xss"              : r"(<script|onerror|alert\(|javascript:|eval\()",
        "path_traversal"   : r"(\.\./|\.\.\\|%2e%2e)",
        "cmd_injection"    : r"(;|\||&&|\$\(|`|>\s*/dev)",
        "brute_force"      : r"(admin|root|password|123456|letmein)",
        "port_scan"        : r"(nmap|masscan|zmap|unicornscan)",
        "data_exfiltration": r"(base64|wget|curl.*http|powershell.*download)",
    }
}

# ─────────────────────────────────────────
# 2. LOG PARSER
# ─────────────────────────────────────────

def parse_log(raw_log: str) -> dict:
    return {
        "timestamp" : datetime.utcnow().isoformat() + "Z",
        "raw"       : raw_log,
        "length"    : len(raw_log),
        "entropy"   : _entropy(raw_log),
        "has_ip"    : bool(re.search(r'\d{1,3}(\.\d{1,3}){3}', raw_log)),
        "ip"        : (re.findall(r'\d{1,3}(\.\d{1,3}){3}', raw_log) or [""])[0],
    }

def _entropy(s: str) -> float:
    if not s: return 0.0
    counts = Counter(s)
    total  = len(s)
    return round(-sum((c/total)*math.log2(c/total) for c in counts.values()), 3)

# ─────────────────────────────────────────
# 3. AI THREAT DETECTION ENGINE
# ─────────────────────────────────────────

def detect_threats(log: dict) -> list:
    alerts = []
    raw    = log["raw"].lower()

    # Pattern matching
    for attack, pattern in THREAT_DB["attack_patterns"].items():
        if re.search(pattern, raw, re.I):
            alerts.append({
                "type"    : attack.replace("_", " ").title(),
                "severity": _severity(attack),
                "detail"  : f"Pattern matched: {attack}",
            })

    # IP reputation check
    for ip in THREAT_DB["malicious_ips"]:
        if ip in raw:
            alerts.append({
                "type"    : "Malicious IP",
                "severity": "CRITICAL",
                "detail"  : f"Known malicious IP detected: {ip}",
            })

    # Ransomware signatures
    for sig in THREAT_DB["ransomware_signatures"]:
        if sig in raw:
            alerts.append({
                "type"    : "Ransomware Signature",
                "severity": "CRITICAL",
                "detail"  : f"Ransomware signature: {sig}",
            })

    # C2 domain check
    for domain in THREAT_DB["c2_domains"]:
        if domain in raw:
            alerts.append({
                "type"    : "C2 Communication",
                "severity": "CRITICAL",
                "detail"  : f"C2 domain detected: {domain}",
            })

    # Entropy-based obfuscation detection
    if log["entropy"] >= 5.8:
        alerts.append({
            "type"    : "Obfuscation",
            "severity": "HIGH",
            "detail"  : f"High entropy detected: {log['entropy']}",
        })

    return alerts

def _severity(attack_type: str) -> str:
    critical = ["cmd_injection", "data_exfiltration", "ransomware"]
    high     = ["sql_injection", "xss", "c2_communication"]
    medium   = ["path_traversal", "port_scan", "brute_force"]
    if attack_type in critical: return "CRITICAL"
    if attack_type in high:     return "HIGH"
    if attack_type in medium:   return "MEDIUM"
    return "LOW"

# ─────────────────────────────────────────
# 4. INCIDENT RESPONSE ENGINE
# ─────────────────────────────────────────

RESPONSE_PLAYBOOK = {
    "CRITICAL": [
        "🔴 ISOLATE affected system immediately",
        "📸 Capture memory dump & forensic image",
        "🚨 Escalate to Incident Response Team",
        "📝 Open P1 ticket — notify CISO",
        "🔒 Block source IP at perimeter firewall",
    ],
    "HIGH": [
        "🟠 Block source IP/domain",
        "📊 Increase logging verbosity",
        "🔍 Launch threat hunting session",
        "📝 Open P2 ticket",
    ],
    "MEDIUM": [
        "🟡 Add to watchlist",
        "📋 Log and monitor for 24h",
        "🔔 Notify SOC team",
    ],
    "LOW": [
        "🟢 Log event",
        "📈 Update baseline metrics",
    ],
}

def auto_respond(alerts: list) -> dict:
    if not alerts:
        return {"status": "CLEAN", "actions": ["✅ No threats detected"]}

    max_severity = max(alerts, key=lambda a: ["LOW","MEDIUM","HIGH","CRITICAL"].index(a["severity"]))
    actions      = RESPONSE_PLAYBOOK.get(max_severity["severity"], [])
    return {
        "status"  : max_severity["severity"],
        "trigger" : max_severity["type"],
        "actions" : actions,
    }

# ─────────────────────────────────────────
# 5. SOC DASHBOARD
# ─────────────────────────────────────────

SEVERITY_ICON = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","CLEAN":"✅"}

def run_soc(logs: list):
    print(BANNER)
    print(f"  {'─'*56}")
    print(f"  📡 Processing {len(logs)} log entries...")
    print(f"  {'─'*56}\n")

    stats = defaultdict(int)
    total_alerts = 0

    for i, raw_log in enumerate(logs, 1):
        log     = parse_log(raw_log)
        alerts  = detect_threats(log)
        response= auto_respond(alerts)
        status  = response["status"]
        icon    = SEVERITY_ICON.get(status, "⚪")

        print(f"  [{i:02d}] {icon} [{status}]")
        print(f"       Log: {raw_log[:65]}...")

        if alerts:
            for alert in alerts:
                sev_icon = SEVERITY_ICON.get(alert["severity"],"⚪")
                print(f"       {sev_icon} {alert['type']}: {alert['detail']}")
            print(f"       ⚡ Response: {response['actions'][0]}")
            stats[status] += 1
            total_alerts  += len(alerts)
        print()

    # Summary
    print(f"  {'═'*56}")
    print(f"  📊 SOC SUMMARY REPORT — {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC")
    print(f"  {'─'*56}")
    print(f"  Total logs analyzed : {len(logs)}")
    print(f"  Total alerts        : {total_alerts}")
    print(f"  🔴 CRITICAL : {stats['CRITICAL']}  🟠 HIGH : {stats['HIGH']}  "
          f"🟡 MEDIUM : {stats['MEDIUM']}  🟢 LOW : {stats['LOW']}")
    print(f"  {'═'*56}\n")

# ─────────────────────────────────────────
# 6. DEMO LOGS
# ─────────────────────────────────────────

DEMO_LOGS = [
    "GET /search?q=normal+query HTTP/1.1 200 Mozilla/5.0",
    "POST /login user=admin&pass=root HTTP/1.1 401",
    "GET /page?id=1 UNION SELECT username,password FROM users-- HTTP/1.1",
    "GET /file?path=../../etc/passwd HTTP/1.1 403",
    "Connection to malware-c2.net:4444 established from 10.0.1.55",
    "Process created: powershell.exe -enc base64encodedpayload==",
    "Ransomware signature detected: lockbit encryption started",
    "POST /comment msg=<script>alert(document.cookie)</script>",
    "PING sweep from 185.220.101.45 — 254 hosts scanned via nmap",
    "SSH login success: root@192.168.1.10 from 91.108.4.0",
]

if __name__ == "__main__":
    run_soc(DEMO_LOGS)
