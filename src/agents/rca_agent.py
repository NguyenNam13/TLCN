# -*- coding: utf-8 -*-
"""
src/agents/rca_agent.py
Root Cause Analysis (RCA) Agent chuyên trách điều tra số (SOC Tier 3 / DFIR Investigator).
Nhiệm vụ trọng tâm:
1. Tái hiện cây tiến trình có hướng (Directed Process Tree / Lineage) từ danh sách ParsedEvent.
2. Xác định tiến trình gốc phát tán mã độc (Root Cause / Patient Zero) và gán is_malicious_origin = True.
3. Nhận diện phương thức xâm nhập ban đầu (Initial Access Vector): Spearphishing Attachment (Office macro),
   Spearphishing Link, External Remote Services (RDP/SSH Brute Force), Drive-by Compromise, Web Exploit, v.v.
4. Xây dựng Dòng thời gian tấn công (Attack Timeline) theo trình tự thời gian tăng dần với đầy đủ bối cảnh hành động.
5. Suy luận Chuỗi đường đi tấn công (Attack Path) và ánh xạ ma trận chiến thuật MITRE ATT&CK chuẩn Enterprise.
6. Cung cấp các phương thức analyze_events() và analyze_state() xuất đối tượng RootCauseAnalysis chuẩn Pydantic v2.
"""

from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime, timezone
import re
import logging

from src.core.schemas import (
    ParsedEvent,
    ProcessNode,
    RootCauseAnalysis,
    ThreatIntelEnrichment,
    IncidentStatus,
)
from src.core.state import IncidentState
from src.core.time_utils import format_vn_time
from src.agents.prompts import RCA_AGENT_SYSTEM_PROMPT

logger = logging.getLogger("RCAAgent")

# Danh mục ứng dụng văn phòng thường bị lợi dụng qua Macro/Phishing Attachment
OFFICE_APPLICATIONS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "eqnedt32.exe",
    "msaccess.exe",
    "visio.exe",
    "mspub.exe",
}

# Danh mục trình duyệt và trình đọc tài liệu (Spearphishing Link / Drive-by Download)
BROWSER_AND_VIEWER_APPS = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe",
    "brave.exe",
    "opera.exe",
    "acrobat.exe",
    "acrord32.exe",
    "foxitreader.exe",
}

# Danh mục dịch vụ Web và ứng dụng máy chủ công khai (Exploit Public-Facing Application)
WEB_SERVER_APPS = {
    "w3wp.exe",
    "httpd.exe",
    "nginx.exe",
    "tomcat.exe",
    "apache.exe",
    "php-cgi.exe",
    "java.exe",
}

# Danh mục tiến trình hệ thống Windows tiêu chuẩn (thường là cha hợp lệ, không phải nguồn độc hại trực tiếp)
BENIGN_SYSTEM_PARENTS = {
    "explorer.exe",
    "services.exe",
    "svchost.exe",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "lsass.exe",
    "taskhost.exe",
    "taskhostw.exe",
    "system",
}

# Chuỗi chiến thuật chuẩn MITRE ATT&CK Enterprise theo vòng đời tấn công
MITRE_TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


class RCAAgent:
    """
    Root Cause Analysis (RCA) Agent - Chuyên viên điều tra số chuyên sâu (SOC Tier 3 / DFIR).
    Kế thừa triết lý phân tích phả hệ tiến trình, phục dựng cây tiến trình có hướng,
    truy vết Patient Zero và thiết lập Dòng thời gian tấn công.
    """

    def __init__(self, system_prompt: Optional[str] = None):
        self.system_prompt = system_prompt or RCA_AGENT_SYSTEM_PROMPT
        self.name = "RootCauseAnalysisAgent"

    # =====================================================================
    # 1. PHỤC DỰNG CÂY TIẾN TRÌNH CÓ HƯỚNG (DIRECTED PROCESS TREE)
    # =====================================================================
    def _extract_process_info(self, event: ParsedEvent) -> Optional[Dict[str, Any]]:
        """Bóc tách thông tin tiến trình từ ParsedEvent bao gồm PID, ParentPID, Image, CommandLine."""
        raw = event.raw_attributes or {}

        # 1. Trích xuất PID tiến trình hiện tại
        pid = (
            raw.get("process_id")
            or raw.get("ProcessId")
            or raw.get("pid")
            or raw.get("PID")
            or raw.get("processId")
            or raw.get("ProcessGuid")
        )

        # 2. Trích xuất Parent PID
        ppid = (
            raw.get("parent_process_id")
            or raw.get("ParentProcessId")
            or raw.get("parent_id")
            or raw.get("ppid")
            or raw.get("PPID")
            or raw.get("parentProcessId")
            or raw.get("ParentProcessGuid")
        )

        p_name = event.process_name
        if not p_name and event.process_path:
            p_name = event.process_path.replace("/", "\\").split("\\")[-1]

        # Nếu không có tên tiến trình lẫn dòng lệnh, không phải sự kiện tiến trình
        if not p_name and not event.command_line and not event.parent_process:
            return None

        p_name = p_name or "unknown.exe"
        cmd = event.command_line or p_name
        parent_name = event.parent_process
        if parent_name and ("\\" in parent_name or "/" in parent_name):
            parent_name = parent_name.replace("/", "\\").split("\\")[-1]

        parent_cmd = event.parent_command_line or parent_name

        return {
            "pid": str(pid) if pid is not None else None,
            "ppid": str(ppid) if ppid is not None else None,
            "process_name": p_name,
            "command_line": cmd,
            "parent_process": parent_name,
            "parent_command_line": parent_cmd,
            "timestamp": event.timestamp,
        }

    def _build_process_tree(self, events: List[ParsedEvent]) -> List[ProcessNode]:
        """
        Xây dựng danh sách ProcessNode tái hiện cấu trúc cây phả hệ tiến trình.
        Đảm bảo liên kết ParentPID -> PID chính xác ngay cả khi thiếu dữ liệu PID tường minh.
        """
        if not events:
            return []

        nodes_by_id: Dict[str, ProcessNode] = {}
        id_counter = 1000
        name_to_last_id: Dict[str, str] = {}

        # Thu thập toàn bộ sự kiện liên quan đến tiến trình
        proc_entries = []
        for evt in events:
            info = self._extract_process_info(evt)
            if info:
                proc_entries.append(info)

        if not proc_entries:
            return []

        # Xử lý từng entry để xây dựng nút
        for entry in proc_entries:
            p_name = entry["process_name"]
            p_name_lower = p_name.lower()
            cmd = entry["command_line"]
            parent_name = entry["parent_process"]
            parent_name_lower = parent_name.lower() if parent_name else None

            # 1. Xác định PID của tiến trình hiện tại
            if entry["pid"]:
                curr_id = str(entry["pid"])
            else:
                # Nếu đã có tiến trình cùng tên đang chạy mà không phải lệnh mới khác biệt hoàn toàn
                id_counter += 1
                curr_id = f"PID-{id_counter}"

            # 2. Xác định Parent ID
            parent_id = None
            if entry["ppid"]:
                parent_id = str(entry["ppid"])
            elif parent_name_lower:
                if parent_name_lower in name_to_last_id:
                    parent_id = name_to_last_id[parent_name_lower]
                else:
                    # Tạo synthetic ID cho tiến trình cha nếu chưa có
                    id_counter += 1
                    parent_id = f"PID-{id_counter}"

            # 3. Đảm bảo tiến trình cha tồn tại trong danh sách nút
            if parent_id and parent_name and parent_id not in nodes_by_id:
                parent_node = ProcessNode(
                    process_id=parent_id,
                    process_name=parent_name,
                    command_line=entry["parent_command_line"] or parent_name,
                    parent_id=None,
                    is_malicious_origin=False,
                )
                nodes_by_id[parent_id] = parent_node
                name_to_last_id[parent_name_lower] = parent_id

            # 4. Tạo hoặc cập nhật ProcessNode hiện tại
            if curr_id in nodes_by_id:
                # Cập nhật thông tin nếu có dòng lệnh chi tiết hơn
                existing = nodes_by_id[curr_id]
                if len(cmd) > len(existing.command_line):
                    nodes_by_id[curr_id] = ProcessNode(
                        process_id=curr_id,
                        process_name=p_name,
                        command_line=cmd,
                        parent_id=existing.parent_id or parent_id,
                        is_malicious_origin=existing.is_malicious_origin,
                    )
            else:
                new_node = ProcessNode(
                    process_id=curr_id,
                    process_name=p_name,
                    command_line=cmd,
                    parent_id=parent_id,
                    is_malicious_origin=False,
                )
                nodes_by_id[curr_id] = new_node
                name_to_last_id[p_name_lower] = curr_id

        # 5. Sắp xếp các nút theo phả hệ hình cây (Topological Ancestor -> Descendant)
        sorted_nodes = self._topological_sort_tree(list(nodes_by_id.values()))

        # 6. Gán cờ is_malicious_origin = True cho tiến trình gốc phát tán mã độc
        self._assign_malicious_origin(sorted_nodes)

        return sorted_nodes

    def _topological_sort_tree(self, nodes: List[ProcessNode]) -> List[ProcessNode]:
        """Sắp xếp cây tiến trình theo thứ tự từ gốc (Root/Ancestor) đến các nhánh con (Descendants)."""
        node_map = {n.process_id: n for n in nodes}
        visited: Set[str] = set()
        result: List[ProcessNode] = []

        def visit(n: ProcessNode):
            if n.process_id in visited:
                return
            # Nếu có cha và cha nằm trong danh sách nodes, duyệt cha trước
            if n.parent_id and n.parent_id in node_map:
                visit(node_map[n.parent_id])
            visited.add(n.process_id)
            result.append(n)

        for n in nodes:
            visit(n)

        return result

    def _assign_malicious_origin(self, nodes: List[ProcessNode]):
        """
        Thuật toán phân tích phả hệ tiến trình:
        Xác định tiến trình gốc phát tán mã độc (Root Cause / Patient Zero) và gán is_malicious_origin = True.
        """
        if not nodes:
            return

        # Đặt lại toàn bộ cờ về False
        for n in nodes:
            n.is_malicious_origin = False

        parent_ids = {n.parent_id for n in nodes if n.parent_id}
        # Tập hợp các tiến trình có con (là tiến trình cha trong cây)
        nodes_with_children = {n.process_id for n in nodes if n.process_id in parent_ids}

        # Quy tắc 1: Office Macro / Phishing Attachment
        # Nếu một ứng dụng Office (winword, excel, etc.) khởi tạo các công cụ dòng lệnh (cmd, powershell, wscript)
        for n in nodes:
            p_lower = n.process_name.lower()
            if p_lower in OFFICE_APPLICATIONS and n.process_id in nodes_with_children:
                n.is_malicious_origin = True
                return

        # Quy tắc 2: Web Server Exploit (w3wp, httpd, tomcat sinh shell)
        for n in nodes:
            p_lower = n.process_name.lower()
            if p_lower in WEB_SERVER_APPS and n.process_id in nodes_with_children:
                n.is_malicious_origin = True
                return

        # Quy tắc 3: Browser / PDF Viewer sinh shell hoặc downloaders
        for n in nodes:
            p_lower = n.process_name.lower()
            if p_lower in BROWSER_AND_VIEWER_APPS and n.process_id in nodes_with_children:
                n.is_malicious_origin = True
                return

        # Quy tắc 4: Tiến trình cha hợp lệ (explorer.exe, services.exe) sinh tiến trình mã độc
        # Trong trường hợp này, tiến trình con đầu tiên được sinh ra là Patient Zero
        for n in nodes:
            if n.parent_id is None or n.parent_id not in {node.process_id for node in nodes}:
                p_lower = n.process_name.lower()
                if p_lower in BENIGN_SYSTEM_PARENTS:
                    # Tìm con trực tiếp của tiến trình hệ thống này
                    for child in nodes:
                        if child.parent_id == n.process_id:
                            child.is_malicious_origin = True
                            return

        # Quy tắc 5: Nếu gốc của cây là một Living-Off-The-Land Binary (cmd, powershell, certutil, mshta)
        # hoặc file thực thi độc hại trực tiếp
        for n in nodes:
            if n.parent_id is None or n.parent_id not in {node.process_id for node in nodes}:
                n.is_malicious_origin = True
                return

        # Fallback cuối cùng: gán cho phần tử đầu tiên trong danh sách đã sắp xếp
        nodes[0].is_malicious_origin = True

    # =====================================================================
    # 2. THUẬT TOÁN NHẬN DIỆN INITIAL ACCESS VECTOR
    # =====================================================================
    def _identify_initial_access_vector(
        self, events: List[ParsedEvent], process_tree: List[ProcessNode]
    ) -> str:
        """
        Phân tích mẫu xâm nhập ban đầu (Initial Access Vector):
        - Spearphishing Attachment (Office macro)
        - External Remote Services (RDP/SSH Brute Force)
        - Exploit Public-Facing Application (Web Exploit / Web Shell)
        - Drive-by Compromise (Spearphishing Link)
        - Valid Accounts (Compromised Credentials)
        """
        if not events and not process_tree:
            return "Unknown / Insufficient Data"

        all_proc_names = {n.process_name.lower() for n in process_tree}
        for e in events:
            if e.process_name:
                all_proc_names.add(e.process_name.lower())
            if e.parent_process:
                all_proc_names.add(e.parent_process.lower())

        all_cmds_lower = " ".join([e.command_line or "" for e in events] + [n.command_line for n in process_tree]).lower()
        all_descriptions = " ".join(
            [str(e.raw_attributes.get("wazuh_rule_description", "")) for e in events]
        ).lower()
        all_rule_ids = {str(e.raw_attributes.get("wazuh_rule_id", "")) for e in events}
        all_groups = {g.lower() for e in events for g in e.raw_attributes.get("wazuh_groups", [])}

        # 1. Nhận diện Spearphishing Attachment (Office macro)
        has_office = any(app in all_proc_names for app in OFFICE_APPLICATIONS)
        macro_indicators = [".docm", ".xlsm", ".doc", ".xls", ".vbs", "macro", "invoice", "attachment", "phishing"]
        has_macro_keywords = any(kw in all_cmds_lower or kw in all_descriptions for kw in macro_indicators)
        if has_office or ("winword" in all_cmds_lower) or ("excel" in all_cmds_lower):
            return "Spearphishing Attachment (Office Macro)"
        if has_macro_keywords and any(p in all_proc_names for p in ["powershell.exe", "cmd.exe", "wscript.exe"]):
            return "Spearphishing Attachment (Office Macro)"

        # 2. Nhận diện External Remote Services (RDP/SSH Brute Force / Credential Access)
        brute_force_terms = ["failed logins", "multiple failed", "brute force", "password spraying", "remoteinteractive", "authentication_failed"]
        has_brute_force = any(term in all_descriptions for term in brute_force_terms) or \
                          any(term in all_groups for term in ["authentication_failed"]) or \
                          any(rid in {"60105", "60115", "5710", "5712"} for rid in all_rule_ids) or \
                          any("4625" in e.event_id for e in events)

        if has_brute_force:
            return "External Remote Services (RDP/SSH Brute-Force)"

        # 3. Nhận diện Exploit Public-Facing Application (Web Server / Web Shell)
        has_web_server = any(app in all_proc_names for app in WEB_SERVER_APPS)
        web_exploit_terms = ["w3wp", "httpd", "nginx", "tomcat", "webshell", "cve-", "rce", "sql injection", "upload"]
        if has_web_server or any(term in all_descriptions or term in all_cmds_lower for term in web_exploit_terms):
            if any(p in all_proc_names for p in ["cmd.exe", "powershell.exe", "sh", "bash"]):
                return "Exploit Public-Facing Application (Web Exploit)"

        # 4. Nhận diện Drive-by Compromise / Spearphishing Link
        has_browser = any(app in all_proc_names for app in BROWSER_AND_VIEWER_APPS)
        drive_by_terms = ["http://", "https://", "download", "urlcache", "drive-by", "browser_exploit"]
        if has_browser and any(term in all_cmds_lower or term in all_descriptions for term in drive_by_terms):
            return "Drive-by Compromise (Malicious Web Link)"

        # 5. Nhận diện Valid Accounts (Compromised Credentials / Unusual External IP)
        if any(rid in {"60106", "60100"} for rid in all_rule_ids) or "unusual external ip" in all_descriptions:
            return "Valid Accounts (Compromised Credentials)"

        # 6. Fallback mặc định khi phát hiện thực thi mã độc bất thường
        if process_tree:
            return "Spearphishing / Untrusted Execution"

        return "Unknown / Unclassified Initial Access"

    # =====================================================================
    # 3. XÂY DỰNG DÒNG THỜI GIAN TẤN CÔNG (ATTACK TIMELINE)
    # =====================================================================
    def _build_attack_timeline(self, events: List[ParsedEvent]) -> List[str]:
        """
        Sắp xếp các mốc sự kiện theo trình tự thời gian tăng dần (Chronological Order).
        Format chi tiết gồm timestamp, tên tiến trình và hành động tương ứng.
        """
        if not events:
            return ["Không có sự kiện nào được ghi nhận để phân tích dòng thời gian."]

        # Sắp xếp thời gian tăng dần đảm bảo đồng nhất múi giờ UTC
        def get_event_time(e: ParsedEvent) -> datetime:
            ts = e.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts

        sorted_events = sorted(events, key=get_event_time)
        timeline: List[str] = []

        for evt in sorted_events:
            ts_str = f"{evt.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} ({format_vn_time(evt.timestamp, '%H:%M:%S ICT')})"
            proc = evt.process_name or (evt.process_path.replace("/", "\\").split("\\")[-1] if evt.process_path else "System")

            raw = evt.raw_attributes or {}
            event_id = evt.event_id

            # Trích xuất mã số sự kiện chuẩn xác (ví dụ: '11' từ 'Sysmon-11', '1' từ 'Sysmon-1', '4625' từ 'EVTX-4625')
            event_id_clean = event_id.strip()
            num_match = re.search(r"(?:sysmon|evtx|rule|wazuh)?[-_:\s]*(\d+)", event_id_clean, re.IGNORECASE)
            event_num = num_match.group(1) if num_match else ""
            groups = [g.lower() for g in raw.get("wazuh_groups", [])]

            # Case A: Sysmon Event 11 hoặc File Creation
            if event_num == "11" or "file" in event_id_clean.lower() or "sysmon_file_create" in groups or "targetFilename" in raw or "target_filename" in raw:
                target_file = (
                    raw.get("targetFilename")
                    or raw.get("target_filename")
                    or evt.file_hash
                    or "tệp tin thực thi mới"
                )
                action_desc = f"Tạo tệp tin mới trên đĩa (File Creation) -> {target_file}"

            # Case B: Sysmon Event 3, Zeek conn hoặc Network Connection
            elif event_num == "3" or "sysmon_network_connect" in groups or "zeek" in evt.source_type.lower() or (evt.dest_ip and not evt.command_line):
                dest = f"{evt.dest_ip}:{evt.dest_port}" if evt.dest_port else str(evt.dest_ip)
                action_desc = f"Kết nối mạng hướng ngoại (Outbound Connection) tới {dest}"

            # Case C: EVTX 4624 / 4625 hoặc Authentication
            elif event_num in ("4624", "4625") or "logon" in event_id_clean.lower() or "authentication_failed" in groups or "authentication_success" in groups:
                status_str = "thành công" if event_num == "4624" or "authentication_success" in groups else "thất bại (Failed Logon / Spray)"
                user_str = evt.user_name or "Unknown User"
                ip_str = evt.source_ip or "Local"
                action_desc = f"Xác thực {status_str} cho tài khoản '{user_str}' từ nguồn {ip_str}"

            # Case D: Sysmon Event 1 hoặc EVTX 4688 - Process Creation
            elif event_num in ("1", "4688") or "sysmon_process_creation" in groups or evt.command_line:
                cmd_display = evt.command_line or proc
                if len(cmd_display) > 120:
                    cmd_display = cmd_display[:117] + "..."
                parent_info = f" (Parent: {evt.parent_process})" if evt.parent_process else ""
                action_desc = f"Khởi tạo tiến trình{parent_info} -> Lệnh: {cmd_display}"

            # Case E: Cảnh báo Wazuh hoặc Security Alert chung
            else:
                rule_desc = raw.get("wazuh_rule_description") or f"Cảnh báo bảo mật {event_id}"
                action_desc = f"Cảnh báo hệ thống: {rule_desc}"

            entry = f"[{ts_str}] [{proc}] {action_desc}"
            timeline.append(entry)

        return timeline

    # =====================================================================
    # 4. SUY LUẬN CHUỖI ĐƯỜNG ĐI TẤN CÔNG & ÁNH XẠ MITRE ATT&CK
    # =====================================================================
    def _infer_mitre_tactics(
        self,
        events: List[ParsedEvent],
        initial_vector: str,
        threat_intel: Optional[ThreatIntelEnrichment] = None,
    ) -> List[str]:
        """
        Suy luận chuỗi chiến thuật MITRE ATT&CK đã diễn ra:
        Initial Access -> Execution -> Persistence -> Defense Evasion -> Command and Control...
        """
        detected: Set[str] = set()

        # 1. Initial Access
        if "Unknown" not in initial_vector and "Insufficient" not in initial_vector:
            detected.add("Initial Access")

        # 2. Quét từ các thuộc tính sự kiện
        all_cmds = " ".join([e.command_line or "" for e in events]).lower()
        all_descs = " ".join([str(e.raw_attributes.get("wazuh_rule_description", "")) for e in events]).lower()
        all_groups = {g.lower() for e in events for g in e.raw_attributes.get("wazuh_groups", [])}

        # Execution
        if any(p in all_cmds for p in ["powershell", "cmd.exe", "wscript", "cscript", "certutil", "mshta"]) or \
           any(g in all_groups for g in ["sysmon_process_creation", "execution"]) or \
           any(e.command_line for e in events):
            detected.add("Execution")

        # Persistence
        if "schtasks" in all_cmds or "currentversion\\run" in all_cmds or "persistence" in all_groups or \
           any("persistence" in d for d in [all_descs]):
            detected.add("Persistence")

        # Defense Evasion
        if any(term in all_cmds for term in ["-enc", "encodedcommand", "-windowstyle hidden", "bypass", "-w hidden"]) or \
           any(term in all_descs for term in ["obfuscated", "encoded", "defense evasion"]):
            detected.add("Defense Evasion")

        # Credential Access
        if any(g in all_groups for g in ["authentication_failed"]) or \
           any("4625" in e.event_id for e in events) or \
           any(term in all_descs for term in ["failed logins", "spray", "mimikatz", "credential"]):
            detected.add("Credential Access")

        # Discovery
        if any(term in all_cmds for term in ["whoami", "net user", "net localgroup", "ipconfig", "systeminfo", "quser", "port_scan"]):
            detected.add("Discovery")

        # Command and Control (C2)
        if any(e.dest_ip for e in events) or \
           any(term in all_cmds for term in ["downloadstring", "webclient", "invoke-webrequest", "http://", "https://", "curl", "wget"]) or \
           any(g in all_groups for g in ["sysmon_network_connect", "c2"]):
            detected.add("Command and Control")

        # 3. Làm giàu từ CTI nếu có
        if threat_intel and threat_intel.mitre_techniques:
            for t_id in threat_intel.mitre_techniques:
                if t_id.startswith("T1566"):
                    detected.add("Initial Access")
                elif t_id.startswith("T1059"):
                    detected.add("Execution")
                elif t_id.startswith("T1053") or t_id.startswith("T1547"):
                    detected.add("Persistence")
                elif t_id.startswith("T1027") or t_id.startswith("T1562"):
                    detected.add("Defense Evasion")
                elif t_id.startswith("T1110") or t_id.startswith("T1003"):
                    detected.add("Credential Access")
                elif t_id.startswith("T1046") or t_id.startswith("T1082"):
                    detected.add("Discovery")
                elif t_id.startswith("T1071") or t_id.startswith("T1105"):
                    detected.add("Command and Control")
                elif t_id.startswith("T1021") or t_id.startswith("T1047"):
                    detected.add("Lateral Movement")

        # Sắp xếp theo trình tự vòng đời tấn công MITRE ATT&CK
        ordered = [t for t in MITRE_TACTIC_ORDER if t in detected]
        if not ordered and events:
            ordered = ["Initial Access", "Execution"]

        return ordered

    # =====================================================================
    # 5. TỔNG HỢP BÁO CÁO NGUYÊN NHÂN GỐC RỄ (ROOT CAUSE SUMMARY)
    # =====================================================================
    def _generate_root_cause_summary(
        self,
        initial_vector: str,
        patient_zero: Optional[ProcessNode],
        process_tree: List[ProcessNode],
        tactics: List[str],
        timeline: List[str],
        threat_intel: Optional[ThreatIntelEnrichment] = None,
    ) -> str:
        """Biên soạn báo cáo phân tích nguyên nhân gốc rễ chi tiết (DFIR Investigation Summary)."""
        pz_info = "Không xác định được tiến trình gốc"
        if patient_zero:
            pz_info = f"{patient_zero.process_name} (PID: {patient_zero.process_id}) [Lệnh: {patient_zero.command_line}]"

        tactics_str = " -> ".join(tactics) if tactics else "N/A"

        # Tóm lược phả hệ tiến trình
        tree_flow = " -> ".join([n.process_name for n in process_tree]) if process_tree else "N/A"

        c2_info = "Không ghi nhận máy chủ C2 ngoài mạng."
        if threat_intel and threat_intel.extracted_iocs:
            c2_ips = [ioc.value for ioc in threat_intel.extracted_iocs if ioc.ioc_type == "IP" and ioc.is_malicious]
            if c2_ips:
                c2_info = f"Kết nối máy chủ C2 độc hại: {', '.join(c2_ips)}"

        summary = (
            f"[BÁO CÁO PHÂN TÍCH NGUYÊN NHÂN GỐC RỄ - SOC TIER 3 / DFIR]\n"
            f"1. Phương thức xâm nhập ban đầu (Initial Access Vector): {initial_vector}\n"
            f"2. Tiến trình khởi nguồn mã độc (Patient Zero): {pz_info}\n"
            f"3. Chuỗi phả hệ tiến trình (Process Lineage): {tree_flow} ({len(process_tree)} tiến trình liên quan)\n"
            f"4. Chuỗi chiến thuật MITRE ATT&CK: {tactics_str}\n"
            f"5. Bối cảnh CTI & C2: {c2_info}\n"
            f"6. Kết luận điều tra: Kẻ tấn công xâm nhập hệ thống thông qua {initial_vector}, "
            f"thực thi chuỗi lệnh độc hại bắt đầu từ {patient_zero.process_name if patient_zero else 'tiến trình lạ'}, "
            f"trải qua {len(timeline)} mốc sự kiện được ghi nhận trên dòng thời gian. "
            f"Khuyến nghị kích hoạt ngay quy trình ngăn chặn (Containment) để cô lập máy trạm và tiêu diệt tiến trình liên đới."
        )
        return summary

    # =====================================================================
    # 6. PHƯƠNG THỨC THỰC THI CHÍNH (ANALYZE_EVENTS & ANALYZE_STATE)
    # =====================================================================
    def analyze_events(
        self,
        events: List[ParsedEvent],
        threat_intel: Optional[ThreatIntelEnrichment] = None,
    ) -> RootCauseAnalysis:
        """
        Thực hiện phân tích nguyên nhân gốc rễ trên danh sách các sự kiện an ninh ParsedEvent.

        :param events: Danh sách ParsedEvent đã được Ingestion Agent chuẩn hóa.
        :param threat_intel: Ngữ cảnh CTI làm giàu từ Threat Intel Agent (tùy chọn).
        :return: Đối tượng RootCauseAnalysis chuẩn Pydantic v2.
        """
        logger.info(f"RCAAgent tiếp nhận {len(events)} sự kiện an ninh để phân tích.")

        if not events:
            return RootCauseAnalysis(
                initial_access_vector="Unknown / Insufficient Data",
                attack_timeline=["Không có sự kiện nào được ghi nhận để phân tích."],
                process_tree=[],
                mitre_tactics=[],
                root_cause_summary="Không đủ dữ liệu sự kiện để tái hiện cây tiến trình và nguyên nhân gốc rễ.",
                confirmed_attack_type="Unknown / Insufficient Data",
                attack_scope="Không xác định phạm vi",
            )

        # 1. Tái hiện Cây tiến trình có hướng
        process_tree = self._build_process_tree(events)

        # 2. Xác định Patient Zero (Tiến trình có is_malicious_origin = True)
        patient_zero = next((n for n in process_tree if n.is_malicious_origin), None)

        # 3. Nhận diện Initial Access Vector
        initial_vector = self._identify_initial_access_vector(events, process_tree)

        # 4. Xây dựng Dòng thời gian tấn công (Attack Timeline)
        attack_timeline = self._build_attack_timeline(events)

        # 5. Suy luận chuỗi chiến thuật MITRE ATT&CK
        mitre_tactics = self._infer_mitre_tactics(events, initial_vector, threat_intel)

        # 6. Xác định Confirmed Attack Type & Attack Scope
        all_descs = " ".join([str(e.raw_attributes.get("wazuh_rule_description", "")) for e in events]).lower()
        all_cmds = " ".join([e.command_line or "" for e in events] + [n.command_line for n in process_tree]).lower()
        all_rule_ids = {str(e.raw_attributes.get("wazuh_rule_id", "")) for e in events}
        all_groups = {g.lower() for e in events for g in e.raw_attributes.get("wazuh_groups", [])}
        all_sources = {e.source_type.lower() for e in events}

        # Kiểm tra False Positive / Benign
        is_routine_benign = all(
            str(e.raw_attributes.get("wazuh_rule_id", "")) == "60100" or
            (int(e.raw_attributes.get("wazuh_rule_level", 0)) <= 4 and "routine" in str(e.raw_attributes.get("wazuh_rule_description", "")).lower())
            for e in events
        ) and not patient_zero

        # Phân loại theo thứ tự ưu tiên chính xác
        is_malware = (
            patient_zero is not None
            or any(k in initial_vector.lower() for k in ["spearphishing", "drive-by", "macro", "malware", "powershell", "c2", "trojan"])
            or any(k in all_cmds or k in all_descs for k in [
                "powershell", "-enc", "encodedcommand", "downloadstring", "webclient",
                "schtasks", "c2", "malware", "trojan", "emotet", "reverse shell",
                "beacon", "payload.exe", "payload.ps1", "certutil", "meterpreter"
            ])
            or any("encoded_payload" in e.raw_attributes or "decoded_command" in e.raw_attributes for e in events)
        )
        is_web = (
            "Exploit Public-Facing Application" in initial_vector
            or any(app in {n.process_name.lower() for n in process_tree} for app in WEB_SERVER_APPS)
            or any(k in all_cmds or k in all_descs for k in ["webshell", "web shell", "sqli", "sql injection"])
        )
        is_cred = (
            "Brute-Force" in initial_vector
            or "Compromised Credentials" in initial_vector
            or any(term in all_descs for term in ["failed logins", "multiple failed", "password spraying", "unusual external ip", "credential"])
            or any(rid in {"60105", "60106", "60115"} for rid in all_rule_ids)
            or any("authentication_failed" in g for g in all_groups)
        )
        is_recon = (
            any(term in all_descs or term in all_cmds for term in ["scan", "sweep", "echo request", "syn packet", "port scan", "port_scan", "network_scan", "icmp sweep", "host discovery", "reconnaissance"])
            or any(rid in {"5710", "5712", "5715"} for rid in all_rule_ids)
        )

        if is_routine_benign:
            confirmed_attack_type = "Normal Administrative Activity (Benign)"
            attack_scope = "Nội bộ máy trạm - Hoạt động người dùng hợp lệ (Không có nguy cơ lây lan)"
        elif is_malware:
            confirmed_attack_type = "Endpoint Malware & C2 Reverse Shell"
        elif is_cred:
            confirmed_attack_type = "Password Spraying & Credential Theft"
        elif is_recon:
            confirmed_attack_type = "Network Scanning & Service Discovery"
        elif is_web:
            confirmed_attack_type = "Exploit Public-Facing Web Application"
        else:
            confirmed_attack_type = "Endpoint Malware & C2 Reverse Shell"

        # Tổng hợp attack_scope
        hosts = sorted(list({e.host_name for e in events if e.host_name and e.host_name.upper() not in {"UNKNOWN", ""}}))
        users = sorted(list({e.user_name for e in events if e.user_name and e.user_name.upper() not in {"UNKNOWN", ""}}))
        c2_ips = sorted(list({e.dest_ip for e in events if e.dest_ip and not e.dest_ip.startswith("127.") and not e.dest_ip.startswith("192.168.") and not e.dest_ip.startswith("10.")}))

        if not is_routine_benign:
            scope_parts = []
            if hosts:
                scope_parts.append(f"Máy trạm {', '.join(hosts)}")
            if users:
                scope_parts.append(f"Tài khoản {', '.join(users)}")
            if c2_ips:
                scope_parts.append(f"Kết nối C2 ngoại lai {', '.join(c2_ips)}")
            attack_scope = " | ".join(scope_parts) if scope_parts else "Phạm vi nội bộ máy trạm"

        # 7. Xuất bản báo cáo nguyên nhân gốc rễ
        summary = self._generate_root_cause_summary(
            initial_vector=initial_vector,
            patient_zero=patient_zero,
            process_tree=process_tree,
            tactics=mitre_tactics,
            timeline=attack_timeline,
            threat_intel=threat_intel,
        )

        return RootCauseAnalysis(
            initial_access_vector=initial_vector,
            attack_timeline=attack_timeline,
            process_tree=process_tree,
            mitre_tactics=mitre_tactics,
            root_cause_summary=summary,
            confirmed_attack_type=confirmed_attack_type,
            attack_scope=attack_scope,
        )

    def evaluate(self, events: List[ParsedEvent]) -> RootCauseAnalysis:
        """Bí danh (Alias) tương thích ngược cho analyze_events."""
        return self.analyze_events(events)

    def analyze_state(self, state: IncidentState) -> IncidentState:
        """
        Thực hiện phân tích RCA và cập nhật kết quả trực tiếp vào IncidentState của StateGraph.

        :param state: Đối tượng IncidentState xuyên suốt pipeline.
        :return: IncidentState đã được cập nhật rca_result và lịch sử chuyển dịch.
        """
        logger.info(f"[{state.incident_id}] Thực thi phân tích RCA trên IncidentState...")

        rca_output = self.analyze_events(
            events=state.parsed_events,
            threat_intel=state.threat_intel,
        )

        state.rca_result = rca_output
        if rca_output.confirmed_attack_type:
            state.attack_type = rca_output.confirmed_attack_type

        patient_zero_name = "Unknown"
        for node in rca_output.process_tree:
            if node.is_malicious_origin:
                patient_zero_name = f"{node.process_name} (PID: {node.process_id})"
                break

        state.record_transition(
            node="rca",
            to_status=IncidentStatus.INVESTIGATING,
            message=(
                f"Hoàn tất phân tích RCA: Loại tấn công={rca_output.confirmed_attack_type}, "
                f"Patient Zero={patient_zero_name}, "
                f"Vector={rca_output.initial_access_vector}, Cây tiến trình={len(rca_output.process_tree)} nút."
            ),
            metadata={
                "confirmed_attack_type": rca_output.confirmed_attack_type,
                "attack_scope": rca_output.attack_scope,
                "initial_access_vector": rca_output.initial_access_vector,
                "patient_zero": patient_zero_name,
                "process_tree_depth": len(rca_output.process_tree),
                "tactics_count": len(rca_output.mitre_tactics),
                "timeline_count": len(rca_output.attack_timeline),
            },
        )

        return state
