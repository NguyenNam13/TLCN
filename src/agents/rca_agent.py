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
    RCALLMAnalysis,
    ThreatIntelEnrichment,
    IncidentStatus,
)
from src.core.state import IncidentState
from src.core.time_utils import format_vn_time
from src.core.security_guard import (
    UNTRUSTED_LOG_SECURITY_HEADER,
    inspect_and_wrap_untrusted,
    sanitize_prompt_text,
    wrap_untrusted_log,
)
from src.agents.prompts import RCA_AGENT_SYSTEM_PROMPT
from src.agents.llm_utils import invoke_structured_llm
from src.tools.threat_intel import ThreatIntelTools

try:
    from src.tools.rag_knowledge_base import RAGKnowledgeBaseTool
except Exception:
    RAGKnowledgeBaseTool = None

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

# Danh mục Living Off The Land Binaries (LOLBins) phổ biến bị lạm dụng trong tấn công APT
LOLBINS = {
    "powershell.exe",
    "powershell_ise.exe",
    "cmd.exe",
    "certutil.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "schtasks.exe",
    "vssadmin.exe",
    "msiexec.exe",
    "curl.exe",
    "tar.exe",
    "msbuild.exe",
    "installutil.exe",
    "reg.exe",
    "net.exe",
    "nltest.exe",
    "hh.exe",
    "csc.exe",
    "at.exe",
}


class RCAAgent:
    """
    Root Cause Analysis (RCA) Agent - Chuyên viên điều tra số chuyên sâu (SOC Tier 3 / DFIR).
    Kế thừa triết lý phân tích phả hệ tiến trình, phục dựng cây tiến trình có hướng,
    truy vết Patient Zero và thiết lập Dòng thời gian tấn công.
    """

    def __init__(
        self,
        system_prompt: Optional[str] = None,
        llm_provider: Optional[Any] = None,
        llm_enabled: bool = True,
        rag_kb: Optional[Any] = None,
        enable_rag: bool = True,
        enable_security_guard: bool = True,
        lazy_init_llm: bool = False,
    ):
        self.system_prompt = system_prompt or RCA_AGENT_SYSTEM_PROMPT
        self.name = "RootCauseAnalysisAgent"
        self.llm_provider = llm_provider
        self.llm_enabled = llm_enabled
        self.enable_rag = bool(enable_rag)
        self.enable_security_guard = bool(enable_security_guard)
        self.lazy_init_llm = bool(lazy_init_llm)
        self._last_security_flags: List[Dict[str, str]] = []

        if not self.enable_rag:
            self.rag_kb = None
        else:
            self.rag_kb = rag_kb
            if self.rag_kb is None and RAGKnowledgeBaseTool is not None:
                try:
                    self.rag_kb = RAGKnowledgeBaseTool()
                except Exception as exc:
                    logger.warning(f"Không thể khởi tạo RAGKnowledgeBaseTool cho RCAAgent: {exc}")
                    self.rag_kb = None

        if self.llm_provider is None and self.llm_enabled and self.lazy_init_llm:
            try:
                from src.copilot.llm_provider import HybridLLMProvider
                self.llm_provider = HybridLLMProvider()
            except Exception as exc:
                logger.warning(f"Không thể lazy init HybridLLMProvider cho RCAAgent: {exc}")
                self.llm_provider = None

    def attach_llm_provider(self, llm_provider: Any) -> None:
        """Gắn hoặc thay thế LLM provider cho RCAAgent."""
        self.llm_provider = llm_provider

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

        # Trích xuất định danh máy trạm để tránh xung đột PID đa máy trạm
        host = (
            event.host_name
            or raw.get("Computer")
            or raw.get("computer")
            or raw.get("host")
            or raw.get("agent_name")
            or "DEFAULT_HOST"
        )

        return {
            "pid": str(pid) if pid is not None else None,
            "ppid": str(ppid) if ppid is not None else None,
            "process_name": p_name,
            "command_line": cmd,
            "parent_process": parent_name,
            "parent_command_line": parent_cmd,
            "timestamp": event.timestamp,
            "host": host,
        }

    def _build_process_tree(self, events: List[ParsedEvent]) -> List[ProcessNode]:
        """
        Xây dựng danh sách ProcessNode tái hiện cấu trúc cây phả hệ tiến trình.
        Đảm bảo liên kết ParentPID -> PID chính xác ngay cả khi thiếu dữ liệu PID tường minh.
        Hỗ trợ phân vùng cây tiến trình đa máy trạm (Host-Partitioned Process Forest) tránh xung đột PID.
        """
        if not events:
            return []

        # Thu thập toàn bộ sự kiện liên quan đến tiến trình
        proc_entries = []
        for evt in events:
            info = self._extract_process_info(evt)
            if info:
                proc_entries.append(info)

        if not proc_entries:
            return []

        distinct_hosts = {e["host"] for e in proc_entries if e.get("host") and e["host"] != "DEFAULT_HOST"}
        is_multi_host = len(distinct_hosts) > 1
        id_counter = 1000
        all_sorted_nodes: List[ProcessNode] = []

        from collections import defaultdict
        entries_by_host = defaultdict(list)
        for e in proc_entries:
            entries_by_host[e["host"]].append(e)

        for host, host_entries in entries_by_host.items():
            host_nodes_by_id: Dict[str, ProcessNode] = {}
            name_to_last_id: Dict[str, str] = {}

            for entry in host_entries:
                p_name = entry["process_name"]
                p_name_lower = p_name.lower()
                cmd = entry["command_line"]
                parent_name = entry["parent_process"]
                parent_name_lower = parent_name.lower() if parent_name else None

                # 1. Xác định PID của tiến trình hiện tại (Gán namespace nếu đa máy trạm)
                raw_pid = entry["pid"]
                if not raw_pid:
                    id_counter += 1
                    raw_pid = f"PID-{id_counter}"
                curr_id = f"{host}:{raw_pid}" if is_multi_host else raw_pid

                # 2. Xác định Parent ID
                parent_id = None
                raw_ppid = entry["ppid"]
                if raw_ppid:
                    parent_id = f"{host}:{raw_ppid}" if is_multi_host else raw_ppid
                elif parent_name_lower:
                    if parent_name_lower in name_to_last_id:
                        parent_id = name_to_last_id[parent_name_lower]
                    else:
                        id_counter += 1
                        synth_id = f"PID-{id_counter}"
                        parent_id = f"{host}:{synth_id}" if is_multi_host else synth_id

                # 3. Đảm bảo tiến trình cha tồn tại trong cây của host
                if parent_id and parent_name and parent_id not in host_nodes_by_id:
                    parent_node = ProcessNode(
                        process_id=parent_id,
                        process_name=parent_name,
                        command_line=entry["parent_command_line"] or parent_name,
                        parent_id=None,
                        is_malicious_origin=False,
                        host_name=host if is_multi_host else None,
                    )
                    host_nodes_by_id[parent_id] = parent_node
                    name_to_last_id[parent_name_lower] = parent_id

                # 4. Tạo hoặc cập nhật ProcessNode hiện tại
                if curr_id in host_nodes_by_id:
                    existing = host_nodes_by_id[curr_id]
                    if len(cmd) > len(existing.command_line):
                        host_nodes_by_id[curr_id] = ProcessNode(
                            process_id=curr_id,
                            process_name=p_name,
                            command_line=cmd,
                            parent_id=existing.parent_id or parent_id,
                            is_malicious_origin=existing.is_malicious_origin,
                            host_name=host if is_multi_host else None,
                        )
                else:
                    new_node = ProcessNode(
                        process_id=curr_id,
                        process_name=p_name,
                        command_line=cmd,
                        parent_id=parent_id,
                        is_malicious_origin=False,
                        host_name=host if is_multi_host else None,
                    )
                    host_nodes_by_id[curr_id] = new_node
                    name_to_last_id[p_name_lower] = curr_id

            sorted_host_nodes = self._topological_sort_tree(list(host_nodes_by_id.values()))
            all_sorted_nodes.extend(sorted_host_nodes)

        # 5. Gán cờ is_malicious_origin = True cho tiến trình gốc phát tán mã độc
        self._assign_malicious_origin(all_sorted_nodes)

        return all_sorted_nodes

    def _topological_sort_tree(self, nodes: List[ProcessNode]) -> List[ProcessNode]:
        """Sắp xếp cây tiến trình theo thứ tự từ gốc (Root/Ancestor) đến các nhánh con (Descendants).
        Có cơ chế phát hiện chu trình (Cycle Detection) để chống lỗi RecursionError khi PID bị lặp vòng.
        """
        node_map = {n.process_id: n for n in nodes}
        visited: Set[str] = set()
        visiting: Set[str] = set()
        result: List[ProcessNode] = []

        def visit(n: ProcessNode):
            if n.process_id in visited:
                return
            if n.process_id in visiting:
                # Bẻ gãy chu trình lặp vô hạn (Cycle detected do PID recycling)
                return
            visiting.add(n.process_id)
            # Nếu có cha và cha nằm trong danh sách nodes, duyệt cha trước
            if n.parent_id and n.parent_id in node_map and n.parent_id != n.process_id:
                visit(node_map[n.parent_id])
            visiting.remove(n.process_id)
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
        all_node_ids = {node.process_id for node in nodes}

        # Quy tắc 1-3: Office Macro, Web Server Exploit, Browser / PDF Viewer sinh shell hoặc downloaders
        for app_group in (OFFICE_APPLICATIONS, WEB_SERVER_APPS, BROWSER_AND_VIEWER_APPS):
            for n in nodes:
                if n.process_name.lower() in app_group and n.process_id in nodes_with_children:
                    n.is_malicious_origin = True
                    return

        # Quy tắc 4: Tiến trình cha hợp lệ (explorer.exe, services.exe) sinh tiến trình mã độc
        # Trong trường hợp này, tiến trình con đầu tiên được sinh ra là Patient Zero
        for n in nodes:
            if n.parent_id is None or n.parent_id not in all_node_ids:
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
            if n.parent_id is None or n.parent_id not in all_node_ids:
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
    @staticmethod
    def _extract_mitre_ids_from_events(events: List[ParsedEvent]) -> List[str]:
        """Trích xuất danh sách mã kỹ thuật MITRE ATT&CK từ raw_attributes của ParsedEvent."""
        collected: List[str] = []
        for evt in events:
            raw = evt.raw_attributes or {}
            for key in ("wazuh_mitre_ids", "mitre_ids"):
                val = raw.get(key)
                if isinstance(val, str):
                    items = [x.strip() for x in val.split(",") if x.strip()]
                elif isinstance(val, list):
                    items = [str(x).strip() for x in val if str(x).strip()]
                else:
                    items = []
                for item in items:
                    norm = item.upper()
                    if norm and norm not in collected:
                        collected.append(norm)
        return collected

    def _infer_mitre_tactics(
        self,
        events: List[ParsedEvent],
        initial_vector: str,
        threat_intel: Optional[ThreatIntelEnrichment] = None,
    ) -> List[str]:
        """
        Suy luận chuỗi chiến thuật MITRE ATT&CK đã diễn ra:
        Initial Access -> Execution -> Persistence -> Defense Evasion -> Command and Control...
        Hỗ trợ ánh xạ mở rộng (T1490/T1486, T1041, T1548, T1505, T1190) và tra cứu RAG.
        """
        detected: Set[str] = set()
        valid_tactics_map: Dict[str, str] = {t.lower(): t for t in MITRE_TACTIC_ORDER}

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
           "persistence" in all_descs:
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

        # 3. Làm giàu từ CTI & MITRE IDs trong sự kiện + tra cứu RAG
        all_mitre_ids: List[str] = []
        if threat_intel and threat_intel.mitre_techniques:
            for tid in threat_intel.mitre_techniques:
                tid_norm = str(tid).strip().upper()
                if tid_norm and tid_norm not in all_mitre_ids:
                    all_mitre_ids.append(tid_norm)
        for tid_norm in self._extract_mitre_ids_from_events(events):
            if tid_norm not in all_mitre_ids:
                all_mitre_ids.append(tid_norm)

        tactic_prefix_map: Dict[str, str] = {
            "T1566": "Initial Access",
            "T1190": "Initial Access",
            "T1059": "Execution",
            "T1053": "Persistence",
            "T1547": "Persistence",
            "T1505": "Persistence",
            "T1548": "Privilege Escalation",
            "T1027": "Defense Evasion",
            "T1562": "Defense Evasion",
            "T1110": "Credential Access",
            "T1003": "Credential Access",
            "T1046": "Discovery",
            "T1082": "Discovery",
            "T1021": "Lateral Movement",
            "T1047": "Lateral Movement",
            "T1071": "Command and Control",
            "T1105": "Command and Control",
            "T1041": "Exfiltration",
            "T1490": "Impact",
            "T1486": "Impact",
        }

        for t_id in all_mitre_ids:
            for prefix, tactic_name in tactic_prefix_map.items():
                if t_id.startswith(prefix):
                    detected.add(tactic_name)

            if self.enable_rag and self.rag_kb is not None and hasattr(self.rag_kb, "get_mitre_technique"):
                try:
                    tech_info = self.rag_kb.get_mitre_technique(t_id)
                    if isinstance(tech_info, dict) and tech_info.get("tactic"):
                        raw_tactic_str = str(tech_info["tactic"])
                        for part in re.split(r"[,;/]", raw_tactic_str):
                            canonical = valid_tactics_map.get(part.strip().lower())
                            if canonical:
                                detected.add(canonical)
                except Exception as exc:
                    logger.debug(f"Tra cứu RAG tactic cho {t_id} thất bại: {exc}")

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
        if threat_intel:
            iocs = threat_intel.extracted_iocs or threat_intel.indicators or []
            malicious_c2 = []
            for ioc in iocs:
                if ioc.is_malicious and ioc.value:
                    score_txt = f", score={ioc.reputation_score}" if ioc.reputation_score is not None else ""
                    malicious_c2.append(f"{ioc.value} ({ioc.ioc_type}{score_txt})")
            c2_parts: List[str] = []
            if malicious_c2:
                c2_parts.append(f"Kết nối máy chủ C2 độc hại: {', '.join(malicious_c2)}")
            if threat_intel.related_threat_actors:
                c2_parts.append(
                    f"Nhóm đe dọa (Threat Actors): {', '.join(threat_intel.related_threat_actors)}"
                )
            if c2_parts:
                c2_info = " | ".join(c2_parts)

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

    @staticmethod
    def _safe_int(val: Any, default: int = 0) -> int:
        """Chuyển đổi số nguyên an toàn, không crash khi gặp None, bool hoặc chuỗi không phải số."""
        if val is None or isinstance(val, bool):
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def _wrap_untrusted(
        self,
        text: Optional[str],
        field_name: str,
        max_len: int = 800,
        *,
        include_notice: bool = False,
        security_flags: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        """Kiểm tra & bọc dữ liệu chưa tin cậy khi SecurityGuard được bật và ghi nhận cờ Prompt Injection."""
        raw = "" if text is None else str(text)
        if not raw.strip() or raw.strip() == "N/A":
            return "N/A"
        if not self.enable_security_guard:
            return raw[:max_len] if max_len > 0 and len(raw) > max_len else raw
        wrapped, is_inj, reason = inspect_and_wrap_untrusted(
            raw,
            field_name=field_name,
            max_len=max_len,
            include_notice=include_notice,
        )
        if is_inj:
            flag_entry = {
                "field": field_name,
                "reason": reason or "prompt_injection_detected",
            }
            if security_flags is not None:
                security_flags.append(flag_entry)
            else:
                self._last_security_flags.append(flag_entry)
        return wrapped

    def _extract_decoded_command_maps(
        self, events: List[ParsedEvent]
    ) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
        """Đối chiếu ParsedEvent để trích xuất decoded_command theo PID, command_line và process_name."""
        pid_to_decoded: Dict[str, str] = {}
        cmd_to_decoded: Dict[str, str] = {}
        proc_to_decoded: Dict[str, str] = {}

        for evt in events:
            raw = evt.raw_attributes or {}
            decoded = raw.get("decoded_command")
            if not decoded:
                deob = raw.get("deobfuscation_result")
                if isinstance(deob, dict):
                    decoded = deob.get("deobfuscated_command")
                elif isinstance(deob, str):
                    decoded = deob
            if not decoded or not str(decoded).strip():
                continue

            decoded_str = str(decoded).strip()
            pid = (
                raw.get("process_id")
                or raw.get("ProcessId")
                or raw.get("pid")
                or raw.get("PID")
                or raw.get("processId")
                or raw.get("ProcessGuid")
            )
            host = (
                evt.host_name
                or raw.get("Computer")
                or raw.get("computer")
                or raw.get("host")
                or raw.get("agent_name")
                or "DEFAULT_HOST"
            )
            if pid is not None:
                pid_str = str(pid)
                pid_to_decoded.setdefault(pid_str, decoded_str)
                pid_to_decoded.setdefault(f"{host}:{pid_str}", decoded_str)
            if evt.command_line:
                cmd_to_decoded.setdefault(evt.command_line, decoded_str)
            if evt.process_name:
                proc_to_decoded.setdefault(evt.process_name.lower(), decoded_str)

        return pid_to_decoded, cmd_to_decoded, proc_to_decoded

    def _build_rag_context_snippet(
        self,
        state: IncidentState,
        initial_vector: str,
        process_tree: List[ProcessNode],
    ) -> str:
        """Truy vấn tối đa 3 TTP MITRE & tài liệu knowledge_docs từ RAG (giới hạn <= 650 ký tự)."""
        if not self.enable_rag or self.rag_kb is None:
            return ""

        parts: List[str] = []
        seen_tids: Set[str] = set()

        mitre_ids: List[str] = []
        if state.threat_intel and state.threat_intel.mitre_techniques:
            mitre_ids.extend(str(m).strip().upper() for m in state.threat_intel.mitre_techniques if str(m).strip())
        for m in self._extract_mitre_ids_from_events(state.parsed_events):
            if m not in mitre_ids:
                mitre_ids.append(m)

        try:
            if hasattr(self.rag_kb, "get_mitre_technique"):
                for tid in mitre_ids[:3]:
                    rec = self.rag_kb.get_mitre_technique(tid)
                    if isinstance(rec, dict):
                        t_id = str(rec.get("technique_id") or rec.get("id") or tid)
                        if t_id not in seen_tids:
                            seen_tids.add(t_id)
                            name = rec.get("name", "")
                            tactic = rec.get("tactic", "")
                            desc = str(rec.get("description", ""))[:110]
                            parts.append(f"TTP {t_id} ({name} | {tactic}): {desc}")

            query_terms = [initial_vector] + [n.process_name for n in process_tree[:4]]
            query_text = " ".join(q for q in query_terms if q and "Unknown" not in q).strip()

            if query_text and len(seen_tids) < 3 and hasattr(self.rag_kb, "query_mitre_technique"):
                for rec in self.rag_kb.query_mitre_technique(query_text, n_results=3):
                    if not isinstance(rec, dict):
                        continue
                    t_id = str(rec.get("technique_id") or rec.get("id") or "")
                    if t_id and t_id not in seen_tids:
                        seen_tids.add(t_id)
                        name = rec.get("name", "")
                        tactic = rec.get("tactic", "")
                        desc = str(rec.get("description", ""))[:90]
                        parts.append(f"TTP {t_id} ({name} | {tactic}): {desc}")
                    if len(seen_tids) >= 3:
                        break

            if query_text and hasattr(self.rag_kb, "query_knowledge_docs"):
                for doc in self.rag_kb.query_knowledge_docs(query_text, n_results=2):
                    if not isinstance(doc, dict):
                        continue
                    title = doc.get("title") or doc.get("doc_id") or doc.get("id") or "OTRF Doc"
                    summary_txt = str(doc.get("description") or doc.get("adversary_view") or doc.get("summary") or "")[:110]
                    parts.append(f"Doc [{title}]: {summary_txt}")
        except Exception as exc:
            logger.debug(f"Không thể truy vấn RAG cho RCAAgent: {exc}")

        if not parts:
            return ""

        combined = "\n".join(parts)
        if len(combined) > 650:
            combined = combined[:647].rstrip() + "..."
        return combined

    def _merge_llm_analysis_into_state(
        self,
        state: IncidentState,
        analysis: RCALLMAnalysis,
    ) -> str:
        """Hợp nhất an toàn kết quả RCALLMAnalysis vào IncidentState và dựng narrative chuẩn."""
        valid_tactics_map: Dict[str, str] = {t.lower(): t for t in MITRE_TACTIC_ORDER}

        if state.rca_result:
            # 1. Hợp nhất MITRE tactics (chỉ giữ tactic hợp lệ trong MITRE_TACTIC_ORDER)
            merged_tactics = set(state.rca_result.mitre_tactics or [])
            for raw_tac in analysis.mitre_tactics_inferred or []:
                canon = valid_tactics_map.get(str(raw_tac).strip().lower())
                if canon:
                    merged_tactics.add(canon)
            if merged_tactics:
                state.rca_result.mitre_tactics = [t for t in MITRE_TACTIC_ORDER if t in merged_tactics]

            has_feedback = bool(state.analyst_feedback and str(state.analyst_feedback).strip())

            # 2. Chỉ cập nhật initial_access_vector nếu deterministic là Unknown/generic hoặc có feedback
            det_vec = (state.rca_result.initial_access_vector or "").strip()
            det_vec_lower = det_vec.lower()
            is_generic_vec = (
                not det_vec
                or "unknown" in det_vec_lower
                or "insufficient" in det_vec_lower
                or det_vec == "Spearphishing / Untrusted Execution"
            )
            if analysis.refined_initial_access_vector and analysis.refined_initial_access_vector.strip():
                if is_generic_vec or has_feedback:
                    state.rca_result.initial_access_vector = analysis.refined_initial_access_vector.strip()

            # 3. Chỉ cập nhật confirmed_attack_type nếu deterministic là Unknown/generic hoặc có feedback
            det_type = (state.rca_result.confirmed_attack_type or "").strip()
            det_type_lower = det_type.lower()
            is_generic_type = (
                not det_type
                or "unknown" in det_type_lower
                or "insufficient" in det_type_lower
                or "unclassified" in det_type_lower
            )
            if analysis.refined_attack_type and analysis.refined_attack_type.strip():
                if is_generic_type or has_feedback:
                    refined_type = analysis.refined_attack_type.strip()
                    state.rca_result.confirmed_attack_type = refined_type
                    state.attack_type = refined_type

        narrative_parts: List[str] = []
        if analysis.cognitive_narrative and analysis.cognitive_narrative.strip():
            narrative_parts.append(analysis.cognitive_narrative.strip())
        if analysis.defense_evasion_techniques:
            narrative_parts.append(
                f"- Kỹ thuật lẩn tránh (Defense Evasion): {', '.join(analysis.defense_evasion_techniques)}"
            )
        if analysis.child_process_purposes:
            narrative_parts.append(
                f"- Mục đích tiến trình con: {'; '.join(analysis.child_process_purposes)}"
            )
        if analysis.attacker_objective and analysis.attacker_objective.strip():
            narrative_parts.append(f"- Động cơ / Mục tiêu tấn công: {analysis.attacker_objective.strip()}")
        if analysis.analyst_feedback_addressed and analysis.analyst_feedback_addressed.strip():
            narrative_parts.append(
                f"- Phản hồi chuyên viên SOC: {analysis.analyst_feedback_addressed.strip()}"
            )
        if analysis.evidence_citations:
            narrative_parts.append(f"- Bằng chứng trích dẫn: {', '.join(analysis.evidence_citations)}")

        return "\n".join(narrative_parts).strip()

    def _generate_llm_root_cause_narrative(
        self,
        state: IncidentState,
        process_tree: List[ProcessNode],
        initial_vector: str,
    ) -> Optional[str]:
        """
        Khởi tạo prompt tóm tắt cây tiến trình Sysmon (cha-con, process name, command line,
        decoded_command, LOLBins phát hiện được), CTI, RAG TTP/knowledge_docs, analyst_feedback
        và gọi invoke_structured_llm(..., schema_class=RCALLMAnalysis).
        Cập nhật kết quả vào state.rca_result.root_cause_summary và trả về narrative.
        Đảm bảo fallback: nếu không có LLM hoặc lỗi, giữ nguyên tóm tắt theo thuật toán đồ thị hiện tại.
        """
        if not self.llm_enabled or self.llm_provider is None:
            return None

        self._last_security_flags = []
        security_flags: List[Dict[str, str]] = []

        try:
            pid_to_decoded, cmd_to_decoded, proc_to_decoded = self._extract_decoded_command_maps(
                state.parsed_events
            )
            tree_summary_lines = []
            detected_lolbins = []

            for node in process_tree:
                p_name_lower = node.process_name.lower()
                is_lolbin = p_name_lower in LOLBINS
                if is_lolbin and node.process_name not in detected_lolbins:
                    detected_lolbins.append(node.process_name)

                origin_flag = " [PATIENT ZERO / GỐC MÃ ĐỘC]" if node.is_malicious_origin else ""
                lolbin_flag = " [LOLBIN]" if is_lolbin else ""
                parent_str = f"Parent PID: {node.parent_id}" if node.parent_id else "Parent: ROOT / UNKNOWN"

                wrapped_cmd = self._wrap_untrusted(
                    node.command_line,
                    field_name=f"process_tree.{node.process_id}.command_line",
                    max_len=800,
                    include_notice=False,
                    security_flags=security_flags,
                )

                decoded_cmd = (
                    pid_to_decoded.get(node.process_id)
                    or cmd_to_decoded.get(node.command_line)
                    or proc_to_decoded.get(p_name_lower)
                )

                node_block = (
                    f"- PID {node.process_id} ({node.process_name}){origin_flag}{lolbin_flag} | {parent_str}\n"
                    f"  Command:\n{wrapped_cmd}"
                )
                if decoded_cmd:
                    wrapped_decoded = self._wrap_untrusted(
                        decoded_cmd,
                        field_name=f"process_tree.{node.process_id}.decoded_command",
                        max_len=800,
                        include_notice=False,
                        security_flags=security_flags,
                    )
                    node_block += f"\n  Decoded Command:\n{wrapped_decoded}"

                    # Đồng bộ vào high_fidelity_tree nếu có
                    if state.rca_result and state.rca_result.high_fidelity_tree:
                        for hf_node in state.rca_result.high_fidelity_tree:
                            if hf_node.process_id == node.process_id and not hf_node.deobfuscated_command:
                                hf_node.deobfuscated_command = decoded_cmd

                tree_summary_lines.append(node_block)

            tree_str = "\n".join(tree_summary_lines) if tree_summary_lines else "Không ghi nhận tiến trình trong cây."
            lolbins_str = ", ".join(detected_lolbins) if detected_lolbins else "Không phát hiện LOLBin phổ biến"

            # Bối cảnh CTI
            cti_section = ""
            if state.threat_intel:
                iocs = state.threat_intel.extracted_iocs or state.threat_intel.indicators or []
                sorted_iocs = sorted(
                    [i for i in iocs if i.is_malicious],
                    key=lambda x: (x.reputation_score or 0),
                    reverse=True,
                )[:6]
                ioc_strs = [
                    f"{i.ioc_type}:{i.value} (score={i.reputation_score}, src={i.context_source or 'CTI'})"
                    for i in sorted_iocs
                ]
                actors_str = ", ".join(state.threat_intel.related_threat_actors[:5]) or "Chưa ghi nhận"
                mitre_str = ", ".join(state.threat_intel.mitre_techniques[:10]) or "Chưa ghi nhận"
                cti_summary_wrapped = (
                    self._wrap_untrusted(
                        state.threat_intel.enrichment_summary,
                        field_name="threat_intel.enrichment_summary",
                        max_len=500,
                        include_notice=False,
                        security_flags=security_flags,
                    )
                    if state.threat_intel.enrichment_summary
                    else "N/A"
                )
                cti_section = (
                    f"\n### BỐI CẢNH TÌNH BÁO MỐI ĐE DỌA (CTI):\n"
                    f"- Top IoCs độc hại: {', '.join(ioc_strs) if ioc_strs else 'Không có'}\n"
                    f"- Threat Actors liên quan: {actors_str}\n"
                    f"- MITRE Techniques từ CTI: {mitre_str}\n"
                    f"- Tóm tắt CTI:\n{cti_summary_wrapped}\n"
                )

            # Bối cảnh RAG TTP + knowledge_docs (<= 650 chars)
            rag_snippet = self._build_rag_context_snippet(state, initial_vector, process_tree)
            rag_section = ""
            if rag_snippet:
                rag_section = f"\n### TRI THỨC NỀN RAG (MITRE TTP & PLAYBOOKS):\n{rag_snippet}\n"

            # Phản hồi chuyên viên (Feedback Loop)
            feedback_section = ""
            if state.analyst_feedback and str(state.analyst_feedback).strip():
                wrapped_feedback = self._wrap_untrusted(
                    state.analyst_feedback,
                    field_name="analyst_feedback",
                    max_len=600,
                    include_notice=False,
                    security_flags=security_flags,
                )
                feedback_section = (
                    f"\n### PHẢN HỒI ĐIỀU TRA LẠI TỪ CHUYÊN VIÊN SOC (Lần thứ {state.reanalysis_count}):\n"
                    f"{wrapped_feedback}\n"
                    f"Yêu cầu bắt buộc: Giải đáp trực tiếp các nghi vấn/chỉ dẫn của chuyên viên trong `analyst_feedback_addressed`.\n"
                )

            self._last_security_flags = list(security_flags)
            guard_header = f"{UNTRUSTED_LOG_SECURITY_HEADER}\n\n" if self.enable_security_guard else ""

            prompt = (
                f"Bạn là chuyên gia điều tra số SOC Tier 3 / DFIR Investigator. Hãy phân tích chuyên sâu cây tiến trình Sysmon sau đây:\n\n"
                f"{guard_header}"
                f"### BỐI CẢNH SỰ CỐ:\n"
                f"- Mã sự cố: {state.incident_id}\n"
                f"- Phương thức xâm nhập ban đầu (Initial Access Vector): {initial_vector}\n"
                f"- Danh sách LOLBins phát hiện được: {lolbins_str}\n\n"
                f"### CÂY TIẾN TRÌNH SYSMON (PROCESS LINEAGE):\n"
                f"{tree_str}\n"
                f"{cti_section}"
                f"{rag_section}"
                f"{feedback_section}\n"
                f"### YÊU CẦU PHÂN TÍCH CHUYÊN SÂU:\n"
                f"1. Kỹ thuật lẩn tránh (Defense Evasion): Kẻ tấn công áp dụng kỹ thuật lẩn tránh nào (mã hóa câu lệnh base64, lợi dụng LOLBins hệ thống, quy trình con ngụy trang, vô hiệu hóa cơ chế phòng vệ)?\n"
                f"2. Mục đích của các tiến trình con: Vai trò và mục tiêu cụ thể của từng tiến trình trong cây (tải payload từ C2, trinh sát mạng/hệ thống, leo thang đặc quyền, duy trì quyền truy cập)?\n"
                f"3. Động cơ và bản chất cuộc tấn công: Mục đích cuối cùng của kẻ tấn công là gì (gián điệp mạng, triển khai ransomware, đánh cắp thông tin định danh, thiết lập bàn đạp lây lan)?\n\n"
                f"Hãy phản hồi bằng JSON chuẩn schema RCALLMAnalysis bám sát bằng chứng đã cung cấp."
            )

            structured_obj, used_real_llm, info = invoke_structured_llm(
                self.llm_provider,
                prompt=prompt,
                schema_class=RCALLMAnalysis,
                system_prompt=self.system_prompt,
                incident_state=state,
                model_tier="reasoning",
                temperature=0.15,
                agent_name="RCAAgent",
            )

            narrative: Optional[str] = None
            if isinstance(structured_obj, RCALLMAnalysis) and used_real_llm:
                narrative = self._merge_llm_analysis_into_state(state, structured_obj)
            elif used_real_llm and isinstance(info, str) and info.strip():
                # Tương thích MockLLMProvider tối giản chỉ định nghĩa generate_response()
                narrative = info.strip()
            else:
                return None

            if not narrative:
                return None

            # Cập nhật kết quả vào state.rca_result.root_cause_summary nếu có
            if state.rca_result:
                base_summary = state.rca_result.root_cause_summary or ""
                heading = "### 🧠 Phân tích Nhận thức Chuyên sâu (LLM Cognitive Narrative):"
                if heading in base_summary:
                    base_summary = base_summary.split(heading)[0].rstrip()
                state.rca_result.root_cause_summary = (
                    f"{base_summary}\n\n"
                    f"{heading}\n"
                    f"{narrative}"
                )

            return narrative

        except Exception as e:
            logger.warning(f"Lỗi khi thực thi LLM Root Cause Narrative: {e}")
            return None

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
        all_descs = " ".join(
            [str((e.raw_attributes or {}).get("wazuh_rule_description", "")) for e in events]
        ).lower()
        all_cmds = " ".join([e.command_line or "" for e in events] + [n.command_line for n in process_tree]).lower()
        all_rule_ids = {str((e.raw_attributes or {}).get("wazuh_rule_id", "")) for e in events}
        all_groups = {
            str(g).lower()
            for e in events
            for g in ((e.raw_attributes or {}).get("wazuh_groups", []) or [])
            if g
        }
        all_proc_names = {n.process_name.lower() for n in process_tree if n.process_name}
        for e in events:
            if e.process_name:
                all_proc_names.add(e.process_name.lower())
            if e.parent_process:
                all_proc_names.add(e.parent_process.lower())
        all_proc_stems = {p.rsplit(".", 1)[0] for p in all_proc_names}
        web_server_stems = {w.rsplit(".", 1)[0] for w in WEB_SERVER_APPS} | {"apache2"}
        combined_text = f"{all_cmds} {all_descs}"

        # Kiểm tra False Positive / Benign (an toàn với wazuh_rule_level=None hoặc chuỗi rác)
        is_routine_benign = all(
            str((e.raw_attributes or {}).get("wazuh_rule_id", "")) == "60100"
            or (
                self._safe_int((e.raw_attributes or {}).get("wazuh_rule_level"), 0) <= 4
                and "routine" in str((e.raw_attributes or {}).get("wazuh_rule_description", "")).lower()
            )
            for e in events
        ) and not patient_zero

        # Đánh giá các nhóm tấn công chuyên biệt trước, tránh để patient_zero chung chung nuốt Web/Cred/Recon
        is_web = (
            "Exploit Public-Facing Application" in initial_vector
            or any(app in all_proc_names for app in WEB_SERVER_APPS)
            or any(stem in web_server_stems for stem in all_proc_stems)
            or any(
                k in combined_text
                for k in ["webshell", "web shell", "sql injection", "union select", "path traversal", "web exploit"]
            )
            or bool(re.search(r"\b(?:sqli|xss|rce)\b", combined_text))
            or any(g in all_groups for g in ["web", "web_app", "web_attack"])
        )
        is_cred = (
            "Brute-Force" in initial_vector
            or "Compromised Credentials" in initial_vector
            or any(
                term in combined_text
                for term in [
                    "failed logins", "multiple failed", "password spraying", "unusual external ip",
                    "credential", "failed password", "invalid user", "authentication failure",
                    "mimikatz", "sekurlsa", "comsvcs.dll", "minidump", "ntdsutil", "ntds.dit", "dumpert",
                ]
            )
            or any(rid in {"60105", "60106", "60115"} for rid in all_rule_ids)
            or any("4625" in str(e.event_id) for e in events)
            or any("authentication_failed" in g or "authentication_failure" in g for g in all_groups)
        )
        is_recon = (
            any(
                term in combined_text
                for term in [
                    "sweep", "echo request", "syn packet", "port scan", "port_scan",
                    "network_scan", "icmp sweep", "host discovery", "reconnaissance",
                    "banner grabbing", "nmap", "masscan", "sharpview",
                ]
            )
            or bool(re.search(r"(?<![a-z0-9_])scan(?:ning)?(?![a-z0-9_])", combined_text))
            or any(rid in {"5710", "5712", "5715"} for rid in all_rule_ids)
            or any(g in all_groups for g in ["network_scan", "reconnaissance", "port_scan", "vulnerability_scan"])
        )
        is_malware = (
            any(
                k in initial_vector.lower()
                for k in ["spearphishing attachment", "office macro", "drive-by", "macro", "malware", "powershell", "c2", "trojan"]
            )
            or any(
                k in combined_text
                for k in [
                    "powershell", "-enc", "encodedcommand", "downloadstring", "webclient",
                    "schtasks", "malware", "trojan", "emotet", "reverse shell",
                    "beacon", "payload.exe", "payload.ps1", "certutil", "meterpreter",
                    "bitsadmin", "mshta", "regsvr32", "vssadmin", "ransomware",
                ]
            )
            or bool(re.search(r"(?<![a-z0-9])c2(?![a-z0-9])", combined_text))
            or any(
                "encoded_payload" in (e.raw_attributes or {}) or "decoded_command" in (e.raw_attributes or {})
                for e in events
            )
            or any(g in all_groups for g in ["malware", "c2"])
            or any(p in LOLBINS for p in all_proc_names)
        )

        if is_routine_benign:
            confirmed_attack_type = "Normal Administrative Activity (Benign)"
            attack_scope = "Nội bộ máy trạm - Hoạt động người dùng hợp lệ (Không có nguy cơ lây lan)"
        elif is_web:
            confirmed_attack_type = "Exploit Public-Facing Web Application"
        elif is_cred:
            confirmed_attack_type = "Password Spraying & Credential Theft"
        elif is_recon:
            confirmed_attack_type = "Network Scanning & Service Discovery"
        elif is_malware:
            confirmed_attack_type = "Endpoint Malware & C2 Reverse Shell"
        else:
            confirmed_attack_type = "Endpoint Malware & C2 Reverse Shell"

        # Tổng hợp attack_scope
        hosts = sorted(list({e.host_name for e in events if e.host_name and e.host_name.upper() not in {"UNKNOWN", ""}}))
        users = sorted(list({e.user_name for e in events if e.user_name and e.user_name.upper() not in {"UNKNOWN", ""}}))
        c2_ips = sorted(list({e.dest_ip for e in events if e.dest_ip and not ThreatIntelTools.is_private_ip(e.dest_ip)}))

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

    def analyze_state(self, state: IncidentState, run_llm: bool = True) -> IncidentState:
        """
        Thực hiện phân tích RCA và cập nhật kết quả trực tiếp vào IncidentState của StateGraph.

        :param state: Đối tượng IncidentState xuyên suốt pipeline.
        :param run_llm: Cho phép thực thi pha tổng hợp nhận thức LLM ngay hay trì hoãn sang pha correlation.
        :return: IncidentState đã được cập nhật rca_result và lịch sử chuyển dịch.
        """
        logger.info(f"[{state.incident_id}] Thực thi phân tích RCA trên IncidentState (run_llm={run_llm})...")

        self._last_security_flags = []
        rca_output = self.analyze_events(
            events=state.parsed_events,
            threat_intel=state.threat_intel,
        )

        state.rca_result = rca_output
        if rca_output.confirmed_attack_type:
            state.attack_type = rca_output.confirmed_attack_type

        # Đưa khả năng nhận thức và suy luận LLM vào RCA Agent khi run_llm=True
        llm_analysis: Optional[str] = None
        if run_llm and self.llm_enabled and self.llm_provider is not None:
            llm_analysis = self._generate_llm_root_cause_narrative(
                state=state,
                process_tree=rca_output.process_tree,
                initial_vector=rca_output.initial_access_vector,
            )

        patient_zero_name = "Unknown"
        for node in rca_output.process_tree:
            if node.is_malicious_origin:
                patient_zero_name = f"{node.process_name} (PID: {node.process_id})"
                break

        transition_metadata: Dict[str, Any] = {
            "confirmed_attack_type": rca_output.confirmed_attack_type,
            "attack_scope": rca_output.attack_scope,
            "initial_access_vector": rca_output.initial_access_vector,
            "patient_zero": patient_zero_name,
            "process_tree_depth": len(rca_output.process_tree),
            "tactics_count": len(rca_output.mitre_tactics),
            "timeline_count": len(rca_output.attack_timeline),
            "llm_executed": bool(llm_analysis is not None),
        }
        if self._last_security_flags:
            transition_metadata["security_guard_flags"] = list(self._last_security_flags)

        state.record_transition(
            node="rca",
            to_status=IncidentStatus.INVESTIGATING,
            message=(
                f"Hoàn tất phân tích RCA: Loại tấn công={rca_output.confirmed_attack_type}, "
                f"Patient Zero={patient_zero_name}, "
                f"Vector={rca_output.initial_access_vector}, Cây tiến trình={len(rca_output.process_tree)} nút."
            ),
            metadata=transition_metadata,
        )

        return state

    def correlate_with_threat_intel(
        self,
        state: IncidentState,
        run_llm: bool = True,
    ) -> IncidentState:
        """
        Pha Join (Fan-in) sau khi ThreatIntelAgent hoàn tất song song với RCA deterministic:
        1. Tái dựng danh sách chiến thuật MITRE ATT&CK và root_cause_summary với C2 IoCs / Threat Actors thực từ state.threat_intel.
        2. Thực thi tổng hợp nhận thức LLM đúng 1 lần khi run_llm=True (kèm CTI, RAG, decoded_command, analyst_feedback).
        """
        if state.rca_result is None:
            return self.analyze_state(state, run_llm=run_llm)

        self._last_security_flags = []
        rca_res = state.rca_result
        patient_zero = next((n for n in rca_res.process_tree if n.is_malicious_origin), None)

        # 1. Tái dựng chiến thuật MITRE ATT&CK có xét thêm state.threat_intel và RAG
        rebuilt_tactics = self._infer_mitre_tactics(
            state.parsed_events,
            rca_res.initial_access_vector,
            state.threat_intel,
        )
        merged_tactics_set = set(rebuilt_tactics) | {
            t for t in (rca_res.mitre_tactics or []) if t in MITRE_TACTIC_ORDER
        }
        rca_res.mitre_tactics = [t for t in MITRE_TACTIC_ORDER if t in merged_tactics_set]

        # 2. Tái dựng root_cause_summary deterministic với bối cảnh CTI/C2 thực
        rca_res.root_cause_summary = self._generate_root_cause_summary(
            initial_vector=rca_res.initial_access_vector,
            patient_zero=patient_zero,
            process_tree=rca_res.process_tree,
            tactics=rca_res.mitre_tactics,
            timeline=rca_res.attack_timeline,
            threat_intel=state.threat_intel,
        )

        # 3. Bổ sung IoC C2 độc hại từ CTI vào attack_scope nếu chưa có
        if (
            state.threat_intel
            and rca_res.confirmed_attack_type != "Normal Administrative Activity (Benign)"
        ):
            iocs = state.threat_intel.extracted_iocs or state.threat_intel.indicators or []
            malicious_ext_ips = sorted(
                {
                    ioc.value
                    for ioc in iocs
                    if ioc.is_malicious
                    and ioc.ioc_type.upper() == "IP"
                    and ioc.value
                    and not ThreatIntelTools.is_private_ip(ioc.value)
                }
            )
            current_scope = rca_res.attack_scope or ""
            missing_ips = [ip for ip in malicious_ext_ips if ip not in current_scope]
            if missing_ips:
                extra_scope = f"Kết nối C2 ngoại lai (CTI) {', '.join(missing_ips)}"
                rca_res.attack_scope = f"{current_scope} | {extra_scope}" if current_scope else extra_scope

        if rca_res.confirmed_attack_type:
            state.attack_type = rca_res.confirmed_attack_type

        # 4. Chạy LLM synthesis đúng 1 lần khi run_llm=True
        llm_analysis: Optional[str] = None
        if run_llm and self.llm_enabled and self.llm_provider is not None:
            llm_analysis = self._generate_llm_root_cause_narrative(
                state=state,
                process_tree=rca_res.process_tree,
                initial_vector=rca_res.initial_access_vector,
            )

        corr_metadata: Dict[str, Any] = {
            "confirmed_attack_type": rca_res.confirmed_attack_type,
            "initial_access_vector": rca_res.initial_access_vector,
            "tactics_count": len(rca_res.mitre_tactics),
            "cti_correlated": state.threat_intel is not None,
            "llm_executed": bool(llm_analysis is not None),
        }
        if self._last_security_flags:
            corr_metadata["security_guard_flags"] = list(self._last_security_flags)

        state.record_transition(
            node="rca_correlation",
            to_status=IncidentStatus.INVESTIGATING,
            message=(
                f"Đối chiếu RCA + Threat Intel hoàn tất: "
                f"MITRE Tactics={len(rca_res.mitre_tactics)}, "
                f"Attack Type={rca_res.confirmed_attack_type}."
            ),
            metadata=corr_metadata,
        )

        return state
