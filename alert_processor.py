import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from sqlalchemy.orm import Session
from . import models, config

log = logging.getLogger(__name__)

SEVERITY_MAP = {
    1: "High",
    2: "Medium",
    3: "Low",
    4: "Info",
    "1": "High",
    "2": "Medium",
    "3": "Low",
    "4": "Info",
}

def parse_iso_timestamp(ts_str: str) -> datetime:
    try:
        # Handle formats like 2026-10-26T20:30:00.123456+0000 or Z
        cleaned = ts_str.replace("Z", "+00:00")
        if "+" in cleaned and len(cleaned.split("+")[-1]) == 4:
            # e.g. +0000 -> +00:00
            parts = cleaned.rsplit("+", 1)
            cleaned = f"{parts[0]}+{parts[1][:2]}:{parts[1][2:]}"
        return datetime.fromisoformat(cleaned).replace(tzinfo=None)
    except Exception:
        return datetime.utcnow()

def ingest_eve_json(db: Session, eve_path: str = None) -> int:
    """Ingest alerts from Suricata eve.json file into the database."""
    if not eve_path:
        eve_path = config.Settings.SURICATA_EVE_PATH

    path = Path(eve_path)
    if not path.is_absolute():
        path = (config.BASE_DIR / path).resolve()

    if not path.exists():
        log.warning(f"Eve JSON file not found at {path}. Seeding initial sample alerts if database is empty.")
        if db.query(models.Alert).count() == 0:
            return seed_sample_alerts(db)
        return 0

    added_count = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if event.get("event_type") != "alert":
                    continue

                alert_data = event.get("alert", {})
                sev_raw = alert_data.get("severity", 2)
                severity = SEVERITY_MAP.get(sev_raw, str(sev_raw))
                if severity not in ["High", "Medium", "Low", "Critical", "Info"]:
                    severity = "Medium"

                ts_val = parse_iso_timestamp(event.get("timestamp", ""))

                alert_obj = models.Alert(
                    timestamp=ts_val,
                    source_ip=event.get("src_ip"),
                    source_port=event.get("src_port"),
                    dest_ip=event.get("dest_ip"),
                    dest_port=event.get("dest_port"),
                    protocol=event.get("proto", "TCP").upper(),
                    signature=alert_data.get("signature", "Network Intrusion Detected"),
                    category=alert_data.get("category", "Potentially Bad Traffic"),
                    severity=severity,
                    status="open",
                    description=f"{alert_data.get('category', 'Alert')}: {alert_data.get('signature', 'Suspicious activity detected')}",
                    raw_data=line,
                )
                db.add(alert_obj)
                added_count += 1

        db.commit()
        log.info(f"Ingested {added_count} alerts from {path}")
    except Exception as e:
        db.rollback()
        log.error(f"Failed to ingest eve.json: {e}")
        raise e

    return added_count

def seed_sample_alerts(db: Session) -> int:
    """Populate realistic security alerts for testing and immediate dashboard visualization."""
    now = datetime.utcnow()
    samples = [
        {
            "offset": timedelta(minutes=4),
            "src_ip": "192.168.1.105",
            "src_port": 49201,
            "dest_ip": "10.0.0.5",
            "dest_port": 22,
            "proto": "TCP",
            "signature": "ET SCAN Potential SSH Brute Force Attack",
            "category": "Attempted Administrator Privilege Gain",
            "severity": "High",
            "status": "open",
            "description": "Rapid succession of failed SSH handshakes indicating automated credential stuffing.",
        },
        {
            "offset": timedelta(minutes=14),
            "src_ip": "198.51.100.42",
            "src_port": 51230,
            "dest_ip": "10.0.0.8",
            "dest_port": 80,
            "proto": "TCP",
            "signature": "ET WEB_SPECIFIC_APPS SQL Injection Attempt in URI",
            "category": "Web Application Attack",
            "severity": "Critical",
            "status": "investigating",
            "description": "UNION SELECT detected targeting the employee authentication backend.",
        },
        {
            "offset": timedelta(minutes=28),
            "src_ip": "192.168.1.189",
            "src_port": 60124,
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "proto": "UDP",
            "signature": "ET MALWARE Possible DNS Tunneling / Data Exfiltration",
            "category": "Command and Control",
            "severity": "High",
            "status": "open",
            "description": "Unusually long base64 encoded TXT lookup records indicating covert data exfiltration.",
        },
        {
            "offset": timedelta(hours=1, minutes=10),
            "src_ip": "185.220.101.5",
            "src_port": 41920,
            "dest_ip": "10.0.0.12",
            "dest_port": 443,
            "proto": "TCP",
            "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
            "category": "Information Gathering",
            "severity": "Medium",
            "status": "resolved",
            "description": "Reconnaissance scan identified via known nmap NSE probe signatures.",
        },
        {
            "offset": timedelta(hours=2, minutes=45),
            "src_ip": "192.168.1.77",
            "src_port": 54112,
            "dest_ip": "45.33.32.156",
            "dest_port": 4444,
            "proto": "TCP",
            "signature": "ET TROJAN Metasploit Reverse TCP Payload Active",
            "category": "A Network Trojan was detected",
            "severity": "Critical",
            "status": "open",
            "description": "Outbound reverse TCP shell session established to external suspicious IP.",
        },
        {
            "offset": timedelta(hours=4, minutes=12),
            "src_ip": "192.168.1.200",
            "src_port": 38192,
            "dest_ip": "10.0.0.254",
            "dest_port": 445,
            "proto": "TCP",
            "signature": "ET EXPLOIT SMBv1 EternalBlue Exploit Attempt (MS17-010)",
            "category": "Attempted Administrator Privilege Gain",
            "severity": "Critical",
            "status": "open",
            "description": "Malformed SMB negotiate packets matched EternalBlue exploit pattern.",
        },
        {
            "offset": timedelta(hours=6, minutes=20),
            "src_ip": "192.168.1.80",
            "src_port": 50122,
            "dest_ip": "10.0.0.1",
            "dest_port": 8080,
            "proto": "TCP",
            "signature": "ET POLICY Suspicious User-Agent (curl / python-requests)",
            "category": "Policy Violation",
            "severity": "Low",
            "status": "dismissed",
            "description": "Automated script requesting internal management portal.",
        },
        {
            "offset": timedelta(hours=12, minutes=5),
            "src_ip": "203.0.113.88",
            "src_port": 33100,
            "dest_ip": "10.0.0.5",
            "dest_port": 80,
            "proto": "TCP",
            "signature": "ET DOS Possible SYN Flood Distributed Denial of Service",
            "category": "Denial of Service",
            "severity": "High",
            "status": "resolved",
            "description": "High volume of TCP SYN packets with no completion handshakes.",
        },
        {
            "offset": timedelta(days=1, hours=3),
            "src_ip": "192.168.1.15",
            "src_port": 42100,
            "dest_ip": "1.1.1.1",
            "dest_port": 53,
            "proto": "UDP",
            "signature": "ET INFO Observed DNS Query for Tor Onion Gateway",
            "category": "Anonymity / Proxy",
            "severity": "Low",
            "status": "resolved",
            "description": "Internal workstation resolving external Tor bridge proxies.",
        },
        {
            "offset": timedelta(days=2, hours=1),
            "src_ip": "192.168.1.110",
            "src_port": 58210,
            "dest_ip": "10.0.0.15",
            "dest_port": 3389,
            "proto": "TCP",
            "signature": "ET SCAN RDP Port Sweep Across Internal Subnet",
            "category": "Lateral Movement",
            "severity": "Medium",
            "status": "investigating",
            "description": "Sequential connections to TCP port 3389 across multiple LAN endpoints.",
        }
    ]

    count = 0
    for s in samples:
        alert = models.Alert(
            timestamp=now - s["offset"],
            source_ip=s["src_ip"],
            source_port=s["src_port"],
            dest_ip=s["dest_ip"],
            dest_port=s["dest_port"],
            protocol=s["proto"],
            signature=s["signature"],
            category=s["category"],
            severity=s["severity"],
            status=s["status"],
            description=s["description"],
            raw_data=json.dumps(s),
        )
        db.add(alert)
        count += 1

    db.commit()
    log.info(f"Seeded {count} realistic intrusion alerts.")
    return count
