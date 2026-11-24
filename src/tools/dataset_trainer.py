# -*- coding: utf-8 -*-
"""
src/tools/dataset_trainer.py
Module huấn luyện & trích xuất hồ sơ hành vi log (Behavioral Log Profiles & Signatures)
từ bộ dữ liệu công khai thực tế (Mordor Security Datasets & Wazuh Alert Scenarios),
đồng thời đồng bộ tri thức sang RAG Knowledge Base (RAGKnowledgeBaseTool).
"""

import os
import sys
import re
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from src.core.schemas import ParsedEvent, AttackCategory
from src.tools.parsers import LogParserTool
from src.tools.rag_knowledge_base import (
    RAGKnowledgeBaseTool,
    CORE_PROTECTED_MITRE_IDS,
    CORE_PROTECTED_WAZUH_RULE_IDS,
    MITRE_TACTIC_ID_MAP,
    parse_otrf_knowledge_doc,
)


# Tập các EventID có độ nhạy an ninh cao trong điều tra số (Sysmon, Windows Security, System, PowerShell)
SUSPICIOUS_EVENT_IDS = {
    # Sysmon
    "1", "3", "7", "8", "10", "11", "12", "13", "15", "22", "23",
    # Windows Security
    "1102", "4624", "4625", "4648", "4656", "4661", "4663", "4672",
    "4688", "4697", "4698", "4702", "4720", "4732", "4740", "4768",
    "4769", "4776", "4798", "4799", "5140", "5145", "5156", "5158",
    # Windows System
    "104", "7045",
    # PowerShell
    "400", "800", "4103", "4104",
}

SUSPICIOUS_KEYWORDS = (
    "powershell",
    "httplistener",
    "promptforcredential",
    "sharpview",
    "mimikatz",
    "lsass",
    "dumpert",
    "ntds",
    "ntdsutil",
    "wsman",
    "winrm",
    "userinitmprlogonscript",
    "currentversion\\run",
    "bitsadmin",
    "invoke-",
    "downloadstring",
    "bypass",
    "hidden",
    "-enc",
    "encodedcommand",
    "vssadmin",
    "wbadmin",
    "bcdedit",
    "wevtutil",
    "certutil",
    "schtasks",
    "net.http",
    "samr",
    "domain admins",
    "credui",
)

LOGHUB_SUSPICIOUS_KEYWORDS = (
    "failed password",
    "invalid user",
    "break-in attempt",
    "authentication failure",
    "error",
    "mod_jk",
    "root",
    "unknown user",
    "user unknown",
)

# Các kỹ thuật MITRE cốt lõi cần bảo vệ tuyệt đối không ghi đè khi nạp tài liệu ngoài
CORE_PROTECTED_MITRE_IDS = {
    "T1059.001",
    "T1566.002",
    "T1078.002",
    "T1046",
    "T1018",
    "T1056.002",
    "T1087",
    "T1087.002",
}

MITRE_TACTIC_ID_MAP = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}


class PublicDatasetTrainer:
    """
    Bộ huấn luyện hồ sơ hành vi từ tập dữ liệu công khai (Mordor, LogHub, Wazuh & OTRF Knowledge Docs).
    Cung cấp khả năng đọc, chuẩn hóa sự kiện sang ParsedEvent, rút trích
    đặc trưng thống kê (Log Profiles / Behavioral Signatures) và đồng bộ tri thức RAG.
    """

    def __init__(
        self,
        mordor_dir: Optional[str] = None,
        wazuh_dir: Optional[str] = None,
        output_model_path: Optional[str] = None,
        rag_kb: Optional[RAGKnowledgeBaseTool] = None,
        loghub_dir: Optional[str] = None,
        knowledge_docs_dir: Optional[str] = None,
    ):
        src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.root_dir = os.path.dirname(src_dir)

        self.mordor_dir = mordor_dir or os.path.join(self.root_dir, "data", "raw", "mordor")
        self.loghub_dir = loghub_dir or os.path.join(self.root_dir, "data", "raw", "loghub")
        self.knowledge_docs_dir = knowledge_docs_dir or os.path.join(
            self.root_dir, "data", "knowledge_docs"
        )
        default_sim_wazuh = os.path.join(self.root_dir, "data", "simulated", "wazuh_alerts")
        default_raw_wazuh = os.path.join(self.root_dir, "data", "raw", "wazuh")
        if wazuh_dir:
            self.wazuh_dir = wazuh_dir
        elif os.path.isdir(default_sim_wazuh):
            self.wazuh_dir = default_sim_wazuh
        else:
            self.wazuh_dir = default_raw_wazuh
        self.output_model_path = output_model_path or os.path.join(
            self.root_dir, "data", "models", "trained_log_profiles.json"
        )
        self.rag_kb = rag_kb
        self._last_ingested_docs: List[Dict[str, Any]] = []

    @staticmethod
    def _parse_timestamp(raw_obj: Dict[str, Any]) -> datetime:
        """Trích xuất và chuẩn hóa thời gian sự kiện từ nhiều trường Mordor khác nhau."""
        for key in ("@timestamp", "TimeCreated", "UtcTime", "EventTime", "timestamp"):
            val = raw_obj.get(key)
            if not val:
                continue
            val_str = str(val).strip()
            try:
                if val_str.endswith("Z"):
                    val_str = val_str[:-1] + "+00:00"
                # Xử lý định dạng UtcTime của Sysmon: '2020-11-02 04:13:06.123'
                if " " in val_str and "T" not in val_str:
                    val_str = val_str.replace(" ", "T", 1)
                dt = datetime.fromisoformat(val_str)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                continue
        return datetime.now(timezone.utc)

    @staticmethod
    def _normalize_source_type(raw_obj: Dict[str, Any]) -> str:
        """
        Chuẩn hóa source_type dựa trên Channel hoặc SourceName:
        Sysmon, PowerShell, WindowsSecurity, WindowsSystem.
        """
        channel = str(raw_obj.get("Channel", "")).strip()
        source_name = str(raw_obj.get("SourceName", "")).strip()
        combined = f"{channel} {source_name}".lower()

        if "sysmon" in combined:
            return "Sysmon"
        if "powershell" in combined:
            return "PowerShell"
        if "security-auditing" in combined or "security" in channel.lower():
            return "WindowsSecurity"
        if "system" in channel.lower():
            return "WindowsSystem"
        return "WindowsSystem"

    @staticmethod
    def _extract_hash(raw_obj: Dict[str, Any]) -> Optional[str]:
        """Trích xuất mã băm SHA256/MD5 từ trường Hashes của Sysmon hoặc trường trực tiếp."""
        for direct_key in ("SHA256", "MD5", "SHA1", "Hash", "file_hash"):
            if raw_obj.get(direct_key):
                return str(raw_obj[direct_key]).strip()

        hashes_str = raw_obj.get("Hashes")
        if isinstance(hashes_str, str) and hashes_str.strip():
            for algo in ("SHA256", "MD5", "SHA1", "IMPHASH"):
                match = re.search(rf"{algo}=([A-Fa-f0-9]+)", hashes_str, re.IGNORECASE)
                if match:
                    return match.group(1)
            return hashes_str.strip()
        return None

    @staticmethod
    def _safe_int(val: Any) -> Optional[int]:
        if val is None or val == "":
            return None
        try:
            port = int(str(val).strip())
            return port if 0 <= port <= 65535 else None
        except (ValueError, TypeError):
            return None

    @classmethod
    def parse_mordor_event(cls, raw_obj: Dict[str, Any]) -> ParsedEvent:
        """
        Chuyển đổi 1 bản ghi JSON từ tập dữ liệu Mordor thành đối tượng ParsedEvent chuẩn.
        Hỗ trợ chuẩn hóa source_type (Sysmon, PowerShell, WindowsSecurity, WindowsSystem).
        """
        if not isinstance(raw_obj, dict):
            raise ValueError("raw_obj phải là một dictionary hợp lệ.")

        event_id = str(raw_obj.get("EventID", raw_obj.get("event_id", "0"))).strip()
        timestamp = cls._parse_timestamp(raw_obj)
        source_type = cls._normalize_source_type(raw_obj)

        host_name = (
            raw_obj.get("Hostname")
            or raw_obj.get("Computer")
            or raw_obj.get("host_name")
        )
        if host_name is not None:
            host_name = str(host_name).strip()

        # Trích xuất user_name
        user_name = None
        for u_key in ("SubjectUserName", "TargetUserName", "User", "AccountName", "user_name"):
            u_val = raw_obj.get(u_key)
            if u_val and str(u_val).strip() not in ("-", ""):
                user_name = str(u_val).strip()
                break
        if not user_name and raw_obj.get("Message"):
            msg_match = re.search(r"Account Name:\s+([^\r\n\t]+)", str(raw_obj.get("Message", "")))
            if msg_match:
                candidate = msg_match.group(1).strip()
                if candidate and candidate != "-":
                    user_name = candidate

        # Trích xuất process_path và process_name
        process_path = None
        for p_key in (
            "NewProcessName",
            "Image",
            "ProcessName",
            "SourceImage",
            "Application",
            "TargetImage",
            "HostApplication",
            "process_path",
        ):
            p_val = raw_obj.get(p_key)
            if p_val and str(p_val).strip() not in ("-", ""):
                process_path = str(p_val).strip()
                break

        process_name = raw_obj.get("process_name")
        if not process_name and process_path:
            normalized_path = process_path.replace("\\", "/")
            process_name = normalized_path.split("/")[-1]
        elif not process_name and source_type == "PowerShell":
            process_name = "powershell.exe"

        # Trích xuất command_line
        command_line = None
        for c_key in ("CommandLine", "ScriptBlockText", "Payload", "ContextInfo", "command_line"):
            c_val = raw_obj.get(c_key)
            if c_val and str(c_val).strip():
                command_line = str(c_val).strip()
                break
        if not command_line and raw_obj.get("Message"):
            msg_text = str(raw_obj["Message"]).strip()
            # Tìm dòng lệnh bên trong Message nếu có
            cmd_match = re.search(r"(?:Process Command Line|CommandLine|Host Application)\s*[:=]\s*([^\r\n]+)", msg_text)
            if cmd_match and cmd_match.group(1).strip():
                command_line = cmd_match.group(1).strip()
            else:
                command_line = msg_text[:600]

        # Trích xuất parent_process & parent_command_line
        parent_process = raw_obj.get("ParentImage") or raw_obj.get("ParentProcessName") or raw_obj.get("parent_process")
        if parent_process is not None:
            parent_process = str(parent_process).strip()
        parent_command_line = raw_obj.get("ParentCommandLine") or raw_obj.get("parent_command_line")
        if parent_command_line is not None:
            parent_command_line = str(parent_command_line).strip()

        # Trích xuất thông tin mạng
        source_ip = None
        for sip_key in ("SourceAddress", "IpAddress", "SourceIp", "ClientAddress", "source_ip"):
            val = raw_obj.get(sip_key)
            if val and str(val).strip() not in ("-", "::1", "127.0.0.1", ""):
                source_ip = str(val).strip()
                break

        dest_ip = None
        for dip_key in ("DestAddress", "DestinationIp", "dest_ip"):
            val = raw_obj.get(dip_key)
            if val and str(val).strip() not in ("-", ""):
                dest_ip = str(val).strip()
                break

        source_port = cls._safe_int(raw_obj.get("SourcePort") or raw_obj.get("IpPort") or raw_obj.get("source_port"))
        dest_port = cls._safe_int(raw_obj.get("DestPort") or raw_obj.get("DestinationPort") or raw_obj.get("dest_port"))
        file_hash = cls._extract_hash(raw_obj)

        raw_attributes = {
            "channel": raw_obj.get("Channel"),
            "source_name": raw_obj.get("SourceName"),
            "category": raw_obj.get("Category"),
            "severity": raw_obj.get("Severity"),
            "keywords": raw_obj.get("Keywords"),
            "target_object": raw_obj.get("TargetObject"),
            "granted_access": raw_obj.get("GrantedAccess"),
            "share_name": raw_obj.get("ShareName"),
            "relative_target_name": raw_obj.get("RelativeTargetName"),
        }
        # Loại bỏ các khóa None để gọn nhẹ
        raw_attributes = {k: v for k, v in raw_attributes.items() if v is not None}

        return ParsedEvent(
            event_id=event_id,
            timestamp=timestamp,
            source_type=source_type,
            host_name=host_name,
            user_name=user_name,
            process_name=process_name,
            process_path=process_path,
            command_line=command_line,
            parent_process=parent_process,
            parent_command_line=parent_command_line,
            source_ip=source_ip,
            source_port=source_port,
            dest_ip=dest_ip,
            dest_port=dest_port,
            file_hash=file_hash,
            raw_attributes=raw_attributes,
        )

    @staticmethod
    def _is_suspicious_event(event: ParsedEvent, raw_obj: Dict[str, Any]) -> bool:
        """Kiểm tra sự kiện có mang tính chất nhạy cảm an ninh phục vụ điều tra hay không."""
        if str(event.event_id) in SUSPICIOUS_EVENT_IDS:
            return True

        text_parts = [
            event.process_name or "",
            event.process_path or "",
            event.command_line or "",
            str(raw_obj.get("Message", "")),
            str(raw_obj.get("ScriptBlockText", "")),
        ]
        blob = " ".join(text_parts).lower()
        return any(kw in blob for kw in SUSPICIOUS_KEYWORDS)

    @classmethod
    def load_mordor_file(
        cls,
        file_path: str,
        max_events: int = 500,
        only_suspicious: bool = False,
    ) -> List[ParsedEvent]:
        """
        Đọc file JSONL trong data/raw/mordor/*.json và chuyển đổi thành danh sách ParsedEvent.
        Khi only_suspicious=True, ưu tiên lọc các sự kiện có độ nhạy an ninh cao.
        """
        if not os.path.exists(file_path):
            return []

        events: List[ParsedEvent] = []
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if max_events and len(events) >= max_events:
                    break
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    raw_obj = json.loads(line_str)
                    if not isinstance(raw_obj, dict):
                        continue
                    parsed = cls.parse_mordor_event(raw_obj)
                    if only_suspicious and not cls._is_suspicious_event(parsed, raw_obj):
                        continue
                    events.append(parsed)
                except Exception:
                    continue

        return events

    @classmethod
    def load_loghub_file(
        cls,
        file_path: str,
        max_events: int = 500,
        only_suspicious: bool = False,
    ) -> List[ParsedEvent]:
        """
        Đọc các file .log trong data/raw/loghub/ (OpenSSH_2k.log, Linux_2k.log, Apache_2k.log).
        - Với Apache: gọi LogParserTool.parse_web_log(line).
        - Với OpenSSH / Linux: gọi LogParserTool.parse_linux_syslog(line).
        - Nếu only_suspicious=True: lọc các dòng có dấu hiệu tấn công/lỗi bảo mật.
        """
        if not os.path.exists(file_path):
            return []

        fname_lower = os.path.basename(file_path).lower()
        is_apache = "apache" in fname_lower or "web" in fname_lower or "http" in fname_lower

        events: List[ParsedEvent] = []
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if max_events and len(events) >= max_events:
                    break
                line_str = line.strip()
                if not line_str:
                    continue
                if only_suspicious:
                    line_lower = line_str.lower()
                    if not any(kw in line_lower for kw in LOGHUB_SUSPICIOUS_KEYWORDS):
                        continue
                try:
                    if is_apache:
                        parsed = LogParserTool.parse_web_log(line_str)
                    else:
                        parsed = LogParserTool.parse_linux_syslog(line_str)
                    events.append(parsed)
                except Exception:
                    continue

        return events

    @staticmethod
    def _infer_mordor_scenario_meta(filename: str) -> Dict[str, Any]:
        """Xác định thông tin kịch bản tấn công, MITRE ATT&CK và AttackCategory từ tên file Mordor."""
        lower_name = filename.lower()
        if "httplistener" in lower_name:
            return {
                "scenario_name": "Execution / C2 HttpListener (PowerShell System.Net.HttpListener)",
                "mitre_techniques": ["T1059.001", "T1071.001"],
                "attack_category": AttackCategory.MALWARE.value,
                "tactics": ["Execution", "Command and Control"],
                "description": (
                    "Kịch bản Mordor thực thi PowerShell khởi tạo máy chủ HTTP Listener cục bộ "
                    "(System.Net.HttpListener) và tương tác mạng qua cổng HTTP."
                ),
            }
        if "promptforcreds" in lower_name or "input_capture" in lower_name:
            return {
                "scenario_name": "Credential Access / GUI Input Capture (PowerShell PromptForCredential)",
                "mitre_techniques": ["T1056.002", "T1059.001"],
                "attack_category": AttackCategory.CREDENTIAL_ACCESS.value,
                "tactics": ["Credential Access", "Collection", "Execution"],
                "description": (
                    "Kịch bản Mordor thu thập thông tin đăng nhập qua hộp thoại giả mạo GUI "
                    "($host.ui.PromptForCredential / CredUIPromptForWindowsCredentials) bằng PowerShell."
                ),
            }
        if "sharpview" in lower_name or "pcre_net" in lower_name:
            return {
                "scenario_name": "Discovery / SharpView Active Directory Enumeration",
                "mitre_techniques": ["T1087.002", "T1087", "T1018", "T1046", "T1078.002"],
                "attack_category": AttackCategory.RECONNAISSANCE.value,
                "tactics": ["Discovery"],
                "description": (
                    "Kịch bản Mordor sử dụng công cụ SharpView.exe dò quét tài khoản miền Active Directory, "
                    "Domain Controllers, SMB shares (IPC$/SAMR) và cấu trúc mạng nội bộ."
                ),
            }
        if "lsass" in lower_name or "dumpert" in lower_name:
            return {
                "scenario_name": "Credential Access / LSASS Memory Dump via Syscalls",
                "mitre_techniques": ["T1003.001"],
                "attack_category": AttackCategory.CREDENTIAL_ACCESS.value,
                "tactics": ["Credential Access"],
                "description": (
                    "Kịch bản Mordor trích xuất bộ nhớ tiến trình LSASS (lsass.exe) thông qua "
                    "Dumpert direct system calls nhằm đánh cắp thông tin xác thực NTLM/Kerberos."
                ),
            }
        if "ntds" in lower_name or "ntdsutil" in lower_name:
            return {
                "scenario_name": "Credential Access / NTDS.dit Active Directory Dump",
                "mitre_techniques": ["T1003.003"],
                "attack_category": AttackCategory.CREDENTIAL_ACCESS.value,
                "tactics": ["Credential Access"],
                "description": (
                    "Kịch bản Mordor trích xuất cơ sở dữ liệu Active Directory (NTDS.dit) "
                    "bằng tiện ích ntdsutil.exe và Volume Shadow Copy."
                ),
            }
        if "smb" in lower_name or "covenant_copy" in lower_name:
            return {
                "scenario_name": "Lateral Movement / SMB Admin Share Copy",
                "mitre_techniques": ["T1021.002"],
                "attack_category": AttackCategory.LATERAL_MOVEMENT.value,
                "tactics": ["Lateral Movement"],
                "description": (
                    "Kịch bản Mordor di chuyển ngang (Lateral Movement) và sao chép payload "
                    "qua chia sẻ quản trị SMB (C$, ADMIN$)."
                ),
            }
        if "wsman" in lower_name or "winrm" in lower_name:
            return {
                "scenario_name": "Lateral Movement / WinRM WSMan Automation",
                "mitre_techniques": ["T1021.006"],
                "attack_category": AttackCategory.LATERAL_MOVEMENT.value,
                "tactics": ["Lateral Movement", "Execution"],
                "description": (
                    "Kịch bản Mordor di chuyển ngang và thực thi lệnh từ xa thông qua dịch vụ "
                    "Windows Remote Management (WinRM / WSMan Automation)."
                ),
            }
        if "userinitmprlogonscript" in lower_name or "logonscript" in lower_name:
            return {
                "scenario_name": "Persistence / Logon Script Modification",
                "mitre_techniques": ["T1037.001"],
                "attack_category": AttackCategory.PRIVILEGE_ESCALATION.value,
                "tactics": ["Persistence", "Privilege Escalation"],
                "description": (
                    "Kịch bản Mordor duy trì quyền truy cập (Persistence) bằng cách thiết lập "
                    "script đăng nhập qua khóa Registry UserInitMprLogonScript."
                ),
            }
        if "run_keys" in lower_name or "registry_modification" in lower_name:
            return {
                "scenario_name": "Persistence / Registry Run Keys Modification",
                "mitre_techniques": ["T1547.001"],
                "attack_category": AttackCategory.PRIVILEGE_ESCALATION.value,
                "tactics": ["Persistence", "Privilege Escalation"],
                "description": (
                    "Kịch bản Mordor chỉnh sửa khóa Registry Run / RunOnce nhằm duy trì quyền "
                    "truy cập tự động khi người dùng đăng nhập."
                ),
            }
        if "service_mod" in lower_name or "fax" in lower_name:
            return {
                "scenario_name": "Privilege Escalation / Windows Service Modification",
                "mitre_techniques": ["T1543.003"],
                "attack_category": AttackCategory.PRIVILEGE_ESCALATION.value,
                "tactics": ["Persistence", "Privilege Escalation"],
                "description": (
                    "Kịch bản Mordor leo thang đặc quyền và duy trì truy cập qua việc chỉnh sửa "
                    "đường dẫn thực thi của dịch vụ Windows (Fax service)."
                ),
            }
        if "bitsadmin" in lower_name:
            return {
                "scenario_name": "Defense Evasion & C2 / BITSAdmin Tool Transfer",
                "mitre_techniques": ["T1197", "T1105"],
                "attack_category": AttackCategory.MALWARE.value,
                "tactics": ["Defense Evasion", "Persistence", "Command and Control"],
                "description": (
                    "Kịch bản Mordor lạm dụng công cụ hệ thống bitsadmin.exe để tải xuống "
                    "kịch bản/mã độc từ máy chủ bên ngoài."
                ),
            }
        return {
            "scenario_name": f"Mordor Security Dataset ({filename})",
            "mitre_techniques": ["T1059.001"],
            "attack_category": AttackCategory.UNKNOWN.value,
            "tactics": ["Execution"],
            "description": f"Kịch bản sự kiện an ninh Mordor trích xuất từ {filename}.",
        }

    @staticmethod
    def _infer_loghub_scenario_meta(filename: str) -> Dict[str, Any]:
        """Xác định thông tin kịch bản, MITRE ATT&CK và AttackCategory cho tập dữ liệu LogHub."""
        lower_name = filename.lower()
        if "openssh" in lower_name or "ssh" in lower_name:
            return {
                "scenario_name": "Credential Access / OpenSSH Brute Force & Auth Failures (LogHub)",
                "mitre_techniques": ["T1110", "T1078"],
                "attack_category": AttackCategory.CREDENTIAL_ACCESS.value,
                "tactics": ["Credential Access", "Initial Access"],
                "description": (
                    "Tập log thực tế OpenSSH từ LogHub ghi nhận các đợt tấn công vét cạn mật khẩu SSH, "
                    "đăng nhập tài khoản không hợp lệ (invalid user) và cảnh báo break-in attempt."
                ),
            }
        if "apache" in lower_name or "web" in lower_name or "http" in lower_name:
            return {
                "scenario_name": "Initial Access & Impact / Apache Web Server Error & Worker Anomaly (LogHub)",
                "mitre_techniques": ["T1190", "T1071.001"],
                "attack_category": AttackCategory.WEB_ATTACK.value,
                "tactics": ["Initial Access", "Command and Control"],
                "description": (
                    "Tập log máy chủ web Apache từ LogHub ghi nhận trạng thái worker và các lỗi "
                    "mod_jk / truy vấn HTTP bất thường."
                ),
            }
        if "linux" in lower_name:
            return {
                "scenario_name": "Credential Access & Privilege Escalation / Linux Syslog & PAM Auth (LogHub)",
                "mitre_techniques": ["T1110", "T1548.003", "T1078"],
                "attack_category": AttackCategory.PRIVILEGE_ESCALATION.value,
                "tactics": ["Credential Access", "Privilege Escalation"],
                "description": (
                    "Tập log hệ thống Linux Syslog từ LogHub ghi nhận xác thực PAM, "
                    "các lần đăng nhập root thất bại và phiên làm việc su/pam_unix."
                ),
            }
        return {
            "scenario_name": f"LogHub System Dataset ({filename})",
            "mitre_techniques": ["T1059.004"],
            "attack_category": AttackCategory.UNKNOWN.value,
            "tactics": ["Execution"],
            "description": f"Tập log hệ thống LogHub trích xuất từ {filename}.",
        }

    @staticmethod
    def _parse_knowledge_doc_content(content: str, filename: str) -> Dict[str, Any]:
        """
        Phân tích nội dung tài liệu tri thức OTRF (.yaml/.yml/.json/.md) trong data/knowledge_docs/.
        Trích xuất đầy đủ: id, title, platform, tags, description, mitre_techniques,
        tactics, tools, adversary_commands, notebooks.
        """
        return parse_otrf_knowledge_doc(content, filename)

    def ingest_knowledge_docs(
        self,
        docs_dir: Optional[str] = None,
        rag_kb: Optional[RAGKnowledgeBaseTool] = None,
    ) -> int:
        """
        Đọc các file tài liệu .yaml / .yml / .json / .md trong data/knowledge_docs/
        (ví dụ các file đặc tả SDWIN-*.yaml, SDLIN-*.yaml, SDAWS-*.yaml của OTRF),
        nạp toàn bộ 20 tài liệu vào collection `knowledge_docs` VÀ bổ sung các kỹ thuật
        MITRE ATT&CK mới (ngoài `CORE_PROTECTED_MITRE_IDS`) vào `mitre_attack` qua batch upsert & flush.
        """
        target_docs_dir = docs_dir or self.knowledge_docs_dir
        kb = rag_kb or self.rag_kb or RAGKnowledgeBaseTool()
        kb.seed_expanded_knowledge()

        self._last_ingested_docs = []
        if not os.path.isdir(target_docs_dir):
            return 0

        valid_exts = (".yaml", ".yml", ".json", ".md")
        doc_files = sorted(
            f for f in os.listdir(target_docs_dir) if f.lower().endswith(valid_exts)
        )

        ingested_count = 0
        for fname in doc_files:
            fpath = os.path.join(target_docs_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if not content.strip():
                    continue

                parsed_doc = self._parse_knowledge_doc_content(content, fname)
                ingested_count += 1
                self._last_ingested_docs.append(
                    {
                        "id": parsed_doc["id"],
                        "title": parsed_doc["title"],
                        "platform": parsed_doc.get("platform", "Windows"),
                        "tags": parsed_doc.get("tags", []),
                        "tools": parsed_doc.get("tools", []),
                        "notebooks": parsed_doc.get("notebooks", []),
                        "adversary_commands": parsed_doc.get("adversary_commands", "")[:400],
                        "source_file": fname,
                        "mitre_techniques": parsed_doc["mitre_techniques"],
                        "tactics": parsed_doc["tactics"],
                        "description": parsed_doc["description"][:400],
                    }
                )

                # 1. Nạp đầy đủ tài liệu OTRF vào collection knowledge_docs (batch defer_save=True)
                kb.add_knowledge_doc(
                    doc_id=parsed_doc["id"],
                    title=parsed_doc["title"],
                    platform=parsed_doc.get("platforms") or parsed_doc.get("platform", "Windows"),
                    tags=parsed_doc.get("tags", []),
                    mitre_ids=parsed_doc["mitre_techniques"],
                    tactics=parsed_doc["tactics"],
                    description=parsed_doc["description"],
                    adversary_commands=parsed_doc.get("adversary_commands", ""),
                    tools=parsed_doc.get("tools", []),
                    notebooks=parsed_doc.get("notebooks", []),
                    source_file=fname,
                    defer_save=True,
                )

                # 2. Bổ sung kỹ thuật MITRE mới (bảo vệ CORE_PROTECTED_MITRE_IDS)
                tactic_str = ", ".join(parsed_doc["tactics"]) if parsed_doc["tactics"] else "Execution"
                tools_str = ", ".join(parsed_doc.get("tools", [])) or "N/A"
                for tech_id in parsed_doc["mitre_techniques"]:
                    tid_clean = str(tech_id).strip().upper()
                    if not tid_clean or tid_clean in CORE_PROTECTED_MITRE_IDS:
                        continue
                    if kb.get_mitre_technique(tid_clean) is None:
                        detection_text = (
                            f"Monitor OTRF Security Dataset indicators ({parsed_doc['id']}, "
                            f"Platform: {parsed_doc.get('platform', 'Windows')}, Tools: {tools_str}) "
                            f"and SIEM telemetry for {parsed_doc['title']}."
                        )
                        if parsed_doc.get("adversary_commands"):
                            detection_text += f" Sample adversary commands: {parsed_doc['adversary_commands'][:260]}"
                        kb.add_mitre_technique(
                            technique_id=tid_clean,
                            name=f"{parsed_doc['title']} ({parsed_doc['id']})",
                            tactic=tactic_str,
                            description=parsed_doc["description"],
                            mitigations=(
                                f"Apply least-privilege access controls, audit security telemetry "
                                f"and enforce endpoint/cloud hardening for {tid_clean} ({parsed_doc['title']})."
                            ),
                            detection=detection_text,
                            defer_save=True,
                            protect_core=True,
                        )
            except Exception:
                continue

        kb.fallback_store.flush()
        return ingested_count

    def train_from_public_datasets(
        self,
        mordor_dir: Optional[str] = None,
        wazuh_dir: Optional[str] = None,
        output_model_path: Optional[str] = None,
        rag_kb: Optional[RAGKnowledgeBaseTool] = None,
        loghub_dir: Optional[str] = None,
        knowledge_docs_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Huấn luyện hồ sơ hành vi log (Log Profiles & Behavioral Signatures) từ toàn bộ
        4 nguồn dữ liệu:
          1. data/raw/mordor/*.json
          2. data/raw/loghub/*.log
          3. data/raw/wazuh/*.json (hoặc data/simulated/wazuh_alerts/)
          4. data/knowledge_docs/*
        Đồng bộ tri thức vào RAGKnowledgeBaseTool và xuất file mô hình bền vững.
        """
        target_mordor_dir = mordor_dir or self.mordor_dir
        target_loghub_dir = loghub_dir or self.loghub_dir
        target_docs_dir = knowledge_docs_dir or self.knowledge_docs_dir
        target_wazuh_dir = wazuh_dir or self.wazuh_dir
        target_output_path = output_model_path or self.output_model_path
        kb = rag_kb or self.rag_kb or RAGKnowledgeBaseTool()

        # Đảm bảo cơ sở tri thức RAG đã được nạp bộ tri thức mở rộng
        kb.seed_expanded_knowledge()

        scenario_profiles: List[Dict[str, Any]] = []
        event_id_distributions: Dict[str, Dict[str, int]] = {}
        process_signatures: List[Dict[str, Any]] = []
        command_patterns: List[str] = []
        network_indicators: List[Dict[str, Any]] = []

        # Bảng ánh xạ thực nghiệm EventID -> MITRE ATT&CK
        event_to_mitre_mapping: Dict[str, List[str]] = {
            "1": ["T1059.001", "T1059.004", "T1053.005", "T1490", "T1105"],
            "3": ["T1071.001", "T1046", "T1018", "T1021.002", "T1041"],
            "7": ["T1059.001", "T1056.002", "T1003.001"],
            "10": ["T1003.001", "T1056.002"],
            "11": ["T1486", "T1505.003", "T1105"],
            "12": ["T1053.005", "T1078.002"],
            "13": ["T1053.005", "T1078.002"],
            "22": ["T1071.001", "T1018"],
            "104": ["T1070.001"],
            "1102": ["T1070.001"],
            "4103": ["T1059.001", "T1056.002", "T1027"],
            "4104": ["T1059.001", "T1056.002", "T1027"],
            "4624": ["T1078.002", "T1021.002"],
            "4625": ["T1110", "T1078.002"],
            "4661": ["T1087", "T1087.002"],
            "4672": ["T1078.002", "T1087.002"],
            "4688": ["T1059.001", "T1490", "T1087"],
            "4698": ["T1053.005"],
            "4798": ["T1087", "T1087.002"],
            "4799": ["T1087", "T1087.002"],
            "5140": ["T1021.002", "T1087.002"],
            "5145": ["T1021.002", "T1087.002"],
            "5156": ["T1071.001", "T1046", "T1018"],
            "5158": ["T1071.001"],
        }

        total_mordor_files = 0
        total_loghub_files = 0
        total_wazuh_files = 0
        total_events_trained = 0
        total_suspicious_events = 0
        all_mitre_covered = set()

        # 1. Huấn luyện từ các file Mordor Dataset thực tế
        if os.path.isdir(target_mordor_dir):
            mordor_files = sorted(
                f for f in os.listdir(target_mordor_dir) if f.endswith(".json") or f.endswith(".jsonl")
            )
            for fname in mordor_files:
                fpath = os.path.join(target_mordor_dir, fname)
                all_events = self.load_mordor_file(fpath, max_events=2000, only_suspicious=False)
                suspicious_events = self.load_mordor_file(fpath, max_events=2000, only_suspicious=True)

                if not all_events:
                    continue

                total_mordor_files += 1
                total_events_trained += len(all_events)
                total_suspicious_events += len(suspicious_events)

                meta = self._infer_mordor_scenario_meta(fname)
                scenario_name = f"{meta['scenario_name']} [{fname}]" if any(
                    p.get("scenario_name") == meta["scenario_name"] for p in scenario_profiles
                ) else meta["scenario_name"]
                for tid in meta["mitre_techniques"]:
                    all_mitre_covered.add(tid)

                # Thống kê tần suất EventID
                ev_counter = Counter(ev.event_id for ev in all_events)
                event_id_distributions[scenario_name] = dict(ev_counter.most_common(15))
                dominant_event_ids = [eid for eid, _ in ev_counter.most_common(8)]

                # Cập nhật bảng ánh xạ EventID -> MITRE từ thực nghiệm
                for eid in dominant_event_ids:
                    existing_list = event_to_mitre_mapping.setdefault(str(eid), [])
                    for tid in meta["mitre_techniques"]:
                        if tid not in existing_list:
                            existing_list.append(tid)

                # Trích xuất chữ ký tiến trình, dòng lệnh mẫu và chỉ báo mạng
                proc_counter = Counter(
                    ev.process_name.lower()
                    for ev in all_events
                    if ev.process_name and ev.process_name not in ("-", "")
                )
                key_indicators = [p for p, _ in proc_counter.most_common(6)]
                sample_cmds: List[str] = []

                for ev in suspicious_events:
                    if ev.command_line:
                        cmd_clean = " ".join(ev.command_line.split())
                        if len(cmd_clean) > 15 and cmd_clean[:240] not in sample_cmds:
                            sample_cmds.append(cmd_clean[:240])
                            if cmd_clean[:240] not in command_patterns and len(command_patterns) < 45:
                                command_patterns.append(cmd_clean[:240])
                    if (ev.source_ip or ev.dest_ip or ev.dest_port) and len(network_indicators) < 40:
                        net_item = {
                            "scenario": scenario_name,
                            "event_id": ev.event_id,
                            "source_ip": ev.source_ip,
                            "dest_ip": ev.dest_ip,
                            "dest_port": ev.dest_port,
                            "process_name": ev.process_name,
                        }
                        if net_item not in network_indicators:
                            network_indicators.append(net_item)

                for proc_name, count in proc_counter.most_common(5):
                    process_signatures.append(
                        {
                            "process_name": proc_name,
                            "occurrences": count,
                            "scenario": scenario_name,
                            "mitre_techniques": meta["mitre_techniques"],
                            "attack_category": meta["attack_category"],
                        }
                    )

                scenario_profiles.append(
                    {
                        "scenario_name": scenario_name,
                        "source_file": fname,
                        "dataset_type": "mordor",
                        "total_events_analyzed": len(all_events),
                        "suspicious_events_count": len(suspicious_events),
                        "dominant_event_ids": dominant_event_ids,
                        "mitre_techniques": meta["mitre_techniques"],
                        "attack_category": meta["attack_category"],
                        "key_indicators": key_indicators,
                        "sample_commands": sample_cmds[:5],
                    }
                )

        # 2. Huấn luyện từ các file LogHub thực tế (OpenSSH, Linux, Apache)
        if os.path.isdir(target_loghub_dir):
            loghub_files = sorted(
                f for f in os.listdir(target_loghub_dir) if f.endswith(".log")
            )
            for fname in loghub_files:
                fpath = os.path.join(target_loghub_dir, fname)
                all_events = self.load_loghub_file(fpath, max_events=2000, only_suspicious=False)
                suspicious_events = self.load_loghub_file(fpath, max_events=2000, only_suspicious=True)

                if not all_events:
                    continue

                total_loghub_files += 1
                total_events_trained += len(all_events)
                total_suspicious_events += len(suspicious_events)

                meta = self._infer_loghub_scenario_meta(fname)
                scenario_name = meta["scenario_name"]
                for tid in meta["mitre_techniques"]:
                    all_mitre_covered.add(tid)

                # Chuẩn hóa EventID prefix (bỏ hậu tố UUID ngẫu nhiên) để thống kê tần suất có ý nghĩa
                def _norm_loghub_eid(eid: str) -> str:
                    if eid.startswith(("LinuxSyslog-", "WebLog-")) and "-" in eid:
                        return eid.rsplit("-", 1)[0]
                    return eid

                ev_counter = Counter(_norm_loghub_eid(ev.event_id) for ev in all_events)
                event_id_distributions[scenario_name] = dict(ev_counter.most_common(10))
                dominant_event_ids = [eid for eid, _ in ev_counter.most_common(8)]

                proc_counter = Counter(
                    ev.process_name.lower()
                    for ev in all_events
                    if ev.process_name and ev.process_name not in ("-", "")
                )
                key_indicators = [p for p, _ in proc_counter.most_common(6)]
                sample_cmds_l: List[str] = []

                for ev in suspicious_events:
                    if ev.command_line:
                        cmd_clean = " ".join(ev.command_line.split())
                        if len(cmd_clean) > 15 and cmd_clean[:240] not in sample_cmds_l:
                            sample_cmds_l.append(cmd_clean[:240])
                            if cmd_clean[:240] not in command_patterns and len(command_patterns) < 60:
                                command_patterns.append(cmd_clean[:240])
                    if ev.source_ip and len(network_indicators) < 50:
                        net_item = {
                            "scenario": scenario_name,
                            "event_id": _norm_loghub_eid(ev.event_id),
                            "source_ip": ev.source_ip,
                            "dest_ip": ev.dest_ip,
                            "dest_port": ev.dest_port,
                            "process_name": ev.process_name,
                        }
                        if net_item not in network_indicators:
                            network_indicators.append(net_item)

                for proc_name, count in proc_counter.most_common(5):
                    process_signatures.append(
                        {
                            "process_name": proc_name,
                            "occurrences": count,
                            "scenario": scenario_name,
                            "mitre_techniques": meta["mitre_techniques"],
                            "attack_category": meta["attack_category"],
                        }
                    )

                scenario_profiles.append(
                    {
                        "scenario_name": scenario_name,
                        "source_file": fname,
                        "dataset_type": "loghub",
                        "total_events_analyzed": len(all_events),
                        "suspicious_events_count": len(suspicious_events),
                        "dominant_event_ids": dominant_event_ids,
                        "mitre_techniques": meta["mitre_techniques"],
                        "attack_category": meta["attack_category"],
                        "key_indicators": key_indicators,
                        "sample_commands": sample_cmds_l[:5],
                    }
                )

        # 3. Huấn luyện bổ sung từ các kịch bản Wazuh Alerts
        wazuh_dirs_to_scan: List[str] = []
        if os.path.isdir(target_wazuh_dir):
            wazuh_dirs_to_scan.append(target_wazuh_dir)
        fallback_raw_wazuh = os.path.join(self.root_dir, "data", "raw", "wazuh")
        if (not wazuh_dirs_to_scan or wazuh_dir is None) and os.path.isdir(fallback_raw_wazuh):
            if fallback_raw_wazuh not in wazuh_dirs_to_scan:
                wazuh_dirs_to_scan.append(fallback_raw_wazuh)

        seen_wazuh_files = set()
        for w_dir in wazuh_dirs_to_scan:
            wazuh_files = sorted(
                f for f in os.listdir(w_dir) if f.endswith(".json")
            )
            for fname in wazuh_files:
                if fname in seen_wazuh_files:
                    continue
                seen_wazuh_files.add(fname)
                fpath = os.path.join(w_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        raw_data = json.load(f)
                except Exception:
                    continue

                alerts = raw_data if isinstance(raw_data, list) else [raw_data]
                valid_alerts = [a for a in alerts if isinstance(a, dict) and "rule" in a]
                if not valid_alerts:
                    continue

                total_wazuh_files += 1
                total_events_trained += len(valid_alerts)

                rule_counter: Counter = Counter()
                mitre_set: List[str] = []
                key_inds: List[str] = []
                sample_cmds_w: List[str] = []
                susp_count = 0

                for alert in valid_alerts:
                    rule = alert.get("rule", {})
                    rid = str(rule.get("id", "")).strip()
                    lvl = int(rule.get("level", 0) or 0)
                    if rid:
                        rule_counter[rid] += 1
                    if lvl >= 7:
                        susp_count += 1

                    mitre_info = rule.get("mitre", {}) or {}
                    for tid in mitre_info.get("id", []):
                        tid_str = str(tid).strip()
                        if tid_str:
                            all_mitre_covered.add(tid_str)
                            if tid_str not in mitre_set:
                                mitre_set.append(tid_str)

                    data_sec = alert.get("data", {}) or {}
                    win_data = (data_sec.get("win", {}) or {}).get("eventdata", {}) or {}
                    cmd = (
                        win_data.get("commandLine")
                        or data_sec.get("command")
                        or alert.get("full_log")
                    )
                    if cmd:
                        cmd_str = " ".join(str(cmd).split())[:240]
                        if cmd_str not in sample_cmds_w:
                            sample_cmds_w.append(cmd_str)
                        if lvl >= 7 and cmd_str not in command_patterns and len(command_patterns) < 70:
                            command_patterns.append(cmd_str)

                    img = win_data.get("image") or data_sec.get("srcip")
                    if img and str(img) not in key_inds:
                        key_inds.append(str(img))

                total_suspicious_events += susp_count
                scenario_label = f"Wazuh Scenario ({fname})"
                event_id_distributions[scenario_label] = dict(rule_counter.most_common(10))

                scenario_profiles.append(
                    {
                        "scenario_name": scenario_label,
                        "source_file": fname,
                        "dataset_type": "wazuh_alerts",
                        "total_events_analyzed": len(valid_alerts),
                        "suspicious_events_count": susp_count,
                        "dominant_event_ids": [r for r, _ in rule_counter.most_common(8)],
                        "mitre_techniques": mitre_set,
                        "attack_category": (
                            AttackCategory.BENIGN.value
                            if "benign" in fname.lower()
                            else AttackCategory.MALWARE.value
                        ),
                        "key_indicators": key_inds[:6],
                        "sample_commands": sample_cmds_w[:5],
                    }
                )

        # 4. Nạp tài liệu tri thức OTRF Knowledge Docs (data/knowledge_docs/*) vào RAG KB
        total_knowledge_docs = self.ingest_knowledge_docs(docs_dir=target_docs_dir, rag_kb=kb)
        for doc_meta in self._last_ingested_docs:
            for tid in doc_meta.get("mitre_techniques", []):
                if tid:
                    all_mitre_covered.add(str(tid).strip().upper())

        # Tổng hợp toàn bộ các kỹ thuật MITRE có trong RAG KB
        total_kb_mitre = kb.count_mitre_techniques()
        total_kb_rules = kb.count_wazuh_rules()

        os.makedirs(os.path.dirname(target_output_path), exist_ok=True)

        report: Dict[str, Any] = {
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "total_mordor_files": total_mordor_files,
            "total_loghub_files": total_loghub_files,
            "total_wazuh_files": total_wazuh_files,
            "total_knowledge_docs": total_knowledge_docs,
            "total_events_trained": total_events_trained,
            "total_suspicious_events": total_suspicious_events,
            "scenarios_learned": len(scenario_profiles),
            "mitre_coverage_count": max(len(all_mitre_covered), total_kb_mitre),
            "observed_dataset_mitre_ids": sorted(all_mitre_covered),
            "rag_mitre_techniques_count": total_kb_mitre,
            "rag_wazuh_rules_count": total_kb_rules,
            "model_saved_path": target_output_path,
            "event_to_mitre_mapping": event_to_mitre_mapping,
            "event_id_distributions": event_id_distributions,
            "process_signatures": process_signatures,
            "command_patterns": command_patterns,
            "network_indicators": network_indicators,
            "scenario_profiles": scenario_profiles,
            "knowledge_docs_ingested": self._last_ingested_docs,
        }

        with open(target_output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        return report


def parse_mordor_event(raw_obj: Dict[str, Any]) -> ParsedEvent:
    """Hàm tiện ích cấp module chuyển đổi 1 sự kiện Mordor sang ParsedEvent."""
    return PublicDatasetTrainer.parse_mordor_event(raw_obj)


def load_mordor_file(
    file_path: str, max_events: int = 500, only_suspicious: bool = False
) -> List[ParsedEvent]:
    """Hàm tiện ích cấp module đọc danh sách ParsedEvent từ file Mordor JSONL."""
    return PublicDatasetTrainer.load_mordor_file(
        file_path=file_path, max_events=max_events, only_suspicious=only_suspicious
    )


def load_loghub_file(
    file_path: str, max_events: int = 500, only_suspicious: bool = False
) -> List[ParsedEvent]:
    """Hàm tiện ích cấp module đọc danh sách ParsedEvent từ file LogHub (.log)."""
    return PublicDatasetTrainer.load_loghub_file(
        file_path=file_path, max_events=max_events, only_suspicious=only_suspicious
    )


def train_from_public_datasets(
    mordor_dir: Optional[str] = None,
    wazuh_dir: Optional[str] = None,
    output_model_path: Optional[str] = None,
    rag_kb: Optional[RAGKnowledgeBaseTool] = None,
    loghub_dir: Optional[str] = None,
    knowledge_docs_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Hàm tiện ích cấp module chạy huấn luyện trên tập dữ liệu công khai."""
    trainer = PublicDatasetTrainer(
        mordor_dir=mordor_dir,
        wazuh_dir=wazuh_dir,
        output_model_path=output_model_path,
        rag_kb=rag_kb,
        loghub_dir=loghub_dir,
        knowledge_docs_dir=knowledge_docs_dir,
    )
    return trainer.train_from_public_datasets()


if __name__ == "__main__":
    trainer = PublicDatasetTrainer()
    summary = trainer.train_from_public_datasets()
    print(
        json.dumps(
            {
                "total_mordor_files": summary["total_mordor_files"],
                "total_loghub_files": summary["total_loghub_files"],
                "total_wazuh_files": summary["total_wazuh_files"],
                "total_knowledge_docs": summary["total_knowledge_docs"],
                "total_events_trained": summary["total_events_trained"],
                "total_suspicious_events": summary["total_suspicious_events"],
                "scenarios_learned": summary["scenarios_learned"],
                "mitre_coverage_count": summary["mitre_coverage_count"],
                "rag_mitre_techniques_count": summary["rag_mitre_techniques_count"],
                "rag_wazuh_rules_count": summary["rag_wazuh_rules_count"],
                "model_saved_path": summary["model_saved_path"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
