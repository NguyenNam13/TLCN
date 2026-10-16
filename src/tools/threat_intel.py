# -*- coding: utf-8 -*-
"""
src/tools/threat_intel.py
Bộ công cụ tra cứu Cyber Threat Intelligence (CTI).
Hỗ trợ tra cứu uy tín IP, Domain, Hash (VirusTotal, AbuseIPDB)
và ánh xạ kỹ thuật MITRE ATT&CK.
"""

from typing import Dict, Any, List
from src.core.schemas import IoCItem


class ThreatIntelTools:
    """Công cụ CTI phục vụ Threat Intelligence Agent."""

    # Cơ sở dữ liệu CTI giả lập cho môi trường Lab/Offline
    KNOWN_MALICIOUS_IPS = {
        "194.26.29.112": {
            "reputation_score": 92,
            "threat_actor": "Cobalt Strike Team / RedLine Stealer",
            "country": "RU",
            "isp": "BadHost Ltd",
            "categories": ["C2", "Botnet"]
        },
        "185.220.101.5": {
            "reputation_score": 88,
            "threat_actor": "Phishing-Group-04",
            "country": "NL",
            "isp": "Tor Exit Node",
            "categories": ["Phishing", "Proxy"]
        }
    }

    KNOWN_ATTACK_PATTERNS = {
        "powershell.exe": {
            "mitre_id": "T1059.001",
            "technique": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution"
        },
        "scheduled_task": {
            "mitre_id": "T1053.005",
            "technique": "Scheduled Task/Job: Scheduled Task",
            "tactic": "Persistence"
        },
        "port_scan_syn": {
            "mitre_id": "T1046",
            "technique": "Network Service Discovery",
            "tactic": "Discovery"
        },
        "phishing_link": {
            "mitre_id": "T1566.002",
            "technique": "Phishing: Spearphishing Link",
            "tactic": "Initial Access"
        }
    }

    @classmethod
    def lookup_ip(cls, ip: str) -> IoCItem:
        """Tra cứu danh tiếng IP từ CTI feeds."""
        if ip in cls.KNOWN_MALICIOUS_IPS:
            info = cls.KNOWN_MALICIOUS_IPS[ip]
            return IoCItem(
                ioc_type="IP",
                value=ip,
                reputation_score=info["reputation_score"],
                is_malicious=True,
                threat_actor=info.get("threat_actor"),
                details=info
            )
        return IoCItem(
            ioc_type="IP",
            value=ip,
            reputation_score=0,
            is_malicious=False,
            details={"status": "clean_or_unknown"}
        )

    @classmethod
    def match_mitre_technique(cls, keyword: str) -> List[Dict[str, str]]:
        """Ánh xạ từ khóa hành vi sang kỹ thuật MITRE ATT&CK."""
        results = []
        for key, pattern in cls.KNOWN_ATTACK_PATTERNS.items():
            if key in keyword.lower():
                results.append(pattern)
        return results
