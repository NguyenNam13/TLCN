# -*- coding: utf-8 -*-
"""
src/tools/wazuh_client.py
Công cụ tích hợp Wazuh SIEM cho hệ thống Multi-Agent SOC.
Hỗ trợ:
1. Nạp cảnh báo từ file snapshot /var/ossec/logs/alerts/alerts.json (Offline/Replay Mode).
2. Kết nối truy vấn Wazuh REST API (Live Mode).
3. Chuyển đổi chuẩn hóa WazuhAlert sang ParsedEvent cho pipeline Agent.
4. Giao tiếp cơ chế Active Response của Wazuh.
"""

import json
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from src.core.schemas import (
    WazuhAlert,
    WazuhRuleInfo,
    WazuhAgentInfo,
    WazuhMitreInfo,
    ParsedEvent,
    SeverityLevel,
    RecommendedAction,
    ActionType
)


class WazuhClientTool:
    """Bộ công cụ giao tiếp với Wazuh Manager."""

    @staticmethod
    def map_rule_level_to_severity(level: int) -> SeverityLevel:
        """Quy đổi Wazuh Rule Level (0-15) sang SeverityLevel chuẩn của Agent."""
        if level >= 12:
            return SeverityLevel.CRITICAL
        elif level >= 8:
            return SeverityLevel.HIGH
        elif level >= 5:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    @classmethod
    def parse_alert_dict(cls, data: Dict[str, Any]) -> WazuhAlert:
        """Parse dictionary thành đối tượng WazuhAlert."""
        rule_data = data.get("rule", {})
        mitre_data = rule_data.get("mitre")
        mitre_obj = None
        if mitre_data:
            mitre_obj = WazuhMitreInfo(
                id=mitre_data.get("id", []),
                tactic=mitre_data.get("tactic", []),
                technique=mitre_data.get("technique", [])
            )

        rule_obj = WazuhRuleInfo(
            id=str(rule_data.get("id", "0")),
            level=int(rule_data.get("level", 0)),
            description=rule_data.get("description", "No description"),
            groups=rule_data.get("groups", []),
            mitre=mitre_obj
        )

        agent_data = data.get("agent", {})
        agent_obj = WazuhAgentInfo(
            id=str(agent_data.get("id", "000")),
            name=agent_data.get("name", "wazuh-agent"),
            ip=agent_data.get("ip")
        )

        return WazuhAlert(
            id=str(data.get("id", data.get("_id", "wazuh-alert-default"))),
            timestamp=datetime.now(timezone.utc),
            rule=rule_obj,
            agent=agent_obj,
            full_log=data.get("full_log"),
            data=data.get("data", {})
        )

    @classmethod
    def load_alerts_from_file(cls, file_path: str) -> List[WazuhAlert]:
        """
        Đọc danh sách cảnh báo từ file JSON hoặc JSON Lines (alerts.json).
        Phục vụ chế độ Replay/Mock từ EVE-NG.
        """
        alerts = []
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return alerts
            
            # Kiểm tra xem là JSON Array hay JSON Lines
            if content.startswith("["):
                items = json.loads(content)
                for item in items:
                    alerts.append(cls.parse_alert_dict(item))
            else:
                for line in content.split("\n"):
                    if line.strip():
                        item = json.loads(line)
                        alerts.append(cls.parse_alert_dict(item))
        return alerts

    @classmethod
    def convert_to_parsed_event(cls, alert: WazuhAlert) -> ParsedEvent:
        """
        Chuyển đổi một cảnh báo WazuhAlert sang đối tượng chuẩn ParsedEvent
        để truyền vào StateGraph của hệ thống Multi-Agent.
        """
        win_data = alert.data.get("win", {}) if isinstance(alert.data, dict) else {}
        eventdata = win_data.get("eventdata", {}) if isinstance(win_data, dict) else {}
        system_data = win_data.get("system", {}) if isinstance(win_data, dict) else {}

        # Trích xuất thông tin tiến trình & lệnh
        process_path = eventdata.get("image") or eventdata.get("ImagePath")
        process_name = process_path.split("\\")[-1] if process_path else None
        cmd_line = eventdata.get("commandLine") or eventdata.get("CommandLine")
        parent_process = eventdata.get("parentImage", "").split("\\")[-1] if eventdata.get("parentImage") else None

        # Trích xuất network / authentication
        source_ip = (
            eventdata.get("sourceIp")
            or eventdata.get("SourceIp")
            or eventdata.get("IpAddress")
            or eventdata.get("ipAddress")
        )
        dest_ip = (
            eventdata.get("destinationIp")
            or eventdata.get("DestinationIp")
            or eventdata.get("destinationIP")
        )
        raw_dest_port = eventdata.get("destinationPort")
        dest_port = None
        if raw_dest_port:
            try:
                dest_port = int(str(raw_dest_port).strip())
            except (ValueError, TypeError):
                dest_port = None
        file_hash = eventdata.get("hashes") or eventdata.get("Hashes")
        user_name = (
            eventdata.get("user")
            or eventdata.get("TargetUserName")
            or eventdata.get("targetUserName")
            or eventdata.get("AccountName")
        )

        # UPGRADE: Multi-format support - Linux/Generic Wazuh fields
        generic_data = alert.data if isinstance(alert.data, dict) else {}
        if not process_path:
            process_path = generic_data.get("program_name") or generic_data.get("command")
        if not process_name and process_path:
            process_name = process_path.replace("\\", "/").split("/")[-1]
        if not cmd_line:
            cmd_line = (
                generic_data.get("command")
                or generic_data.get("url")
                or generic_data.get("request")
                or alert.full_log
            )
        if not source_ip:
            source_ip = (
                generic_data.get("srcip")
                or generic_data.get("src_ip")
                or generic_data.get("remote_ip")
                or generic_data.get("clientip")
                or generic_data.get("hostname")
            )
        if not dest_ip:
            dest_ip = (
                generic_data.get("dstip")
                or generic_data.get("dest_ip")
                or generic_data.get("dst_ip")
            )
        if not user_name:
            user_name = (
                generic_data.get("srcuser")
                or generic_data.get("dstuser")
                or generic_data.get("user")
                or generic_data.get("username")
            )

        # UPGRADE: Suricata IDS alert format
        suricata = generic_data.get("alert", {}) if isinstance(generic_data, dict) else {}
        if suricata and isinstance(suricata, dict):
            if not source_ip:
                source_ip = generic_data.get("src_ip")
            if not dest_ip:
                dest_ip = generic_data.get("dest_ip")
            if not cmd_line and suricata.get("signature"):
                cmd_line = suricata.get("signature")

        # UPGRADE: Regex fallback from full_log if still missing
        if alert.full_log and not source_ip:
            ip_match = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", alert.full_log)
            if ip_match:
                source_ip = ip_match.group(1)

        # Fallback cuối cùng sang agent IP nếu không tìm thấy IP nguồn tấn công nào
        if not source_ip and alert.agent and alert.agent.ip:
            source_ip = alert.agent.ip

        if alert.full_log and not user_name:
            m = re.search(r'(?:invalid\s+user|user\s+name|user|account)[\s=:]+([a-zA-Z0-9_\.\-]+)', alert.full_log, re.IGNORECASE)
            if m and m.group(1).lower() not in ("invalid", "unknown", "none", "a", "an", "the"):
                user_name = m.group(1).strip()
            else:
                m2 = re.search(r'(?:for|by|as)\s+(?:user\s+|account\s+|invalid\s+)?([a-zA-Z0-9_\.\-]+)(?:\s+from|\s+at|\s+on|\s*[,;:]|\s*$)', alert.full_log, re.IGNORECASE)
                if m2 and m2.group(1).lower() not in ("invalid", "user", "unknown", "none", "a", "an", "the", "authentication", "failed", "password"):
                    user_name = m2.group(1).strip()

        if alert.full_log and not cmd_line:
            cmd_line = alert.full_log[:500]  # Giới hạn 500 ký tự

        if not dest_port:
            raw_dport = (
                generic_data.get("dstport")
                or generic_data.get("dest_port")
                or generic_data.get("dst_port")
                or (alert.data.get("dest_port") if isinstance(alert.data, dict) else None)
            )
            if raw_dport:
                try:
                    dest_port = int(str(raw_dport).strip())
                except (ValueError, TypeError):
                    pass

        raw_sport = (
            eventdata.get("sourcePort")
            or eventdata.get("SourcePort")
            or generic_data.get("srcport")
            or generic_data.get("src_port")
            or (alert.data.get("src_port") if isinstance(alert.data, dict) else None)
        )
        source_port = None
        if raw_sport:
            try:
                source_port = int(str(raw_sport).strip())
            except (ValueError, TypeError):
                source_port = None

        raw_attrs = {
            "wazuh_alert_id": alert.id,
            "wazuh_rule_id": alert.rule.id,
            "wazuh_rule_level": alert.rule.level,
            "wazuh_rule_description": alert.rule.description,
            "wazuh_agent_id": alert.agent.id,
            "wazuh_agent_name": alert.agent.name,
            "wazuh_groups": alert.rule.groups,
        }

        if alert.rule.mitre and alert.rule.mitre.id:
            raw_attrs["wazuh_mitre_ids"] = alert.rule.mitre.id

        # UPGRADE: Preserve Suricata / Web / Linux metadata if present
        if isinstance(suricata, dict) and suricata.get("signature"):
            raw_attrs["suricata_signature"] = suricata.get("signature")
        if generic_data.get("proto"):
            raw_attrs["proto"] = generic_data.get("proto")

        # Giải mã chuỗi PowerShell Base64 nếu có trong command line
        if cmd_line and "-enc" in cmd_line.lower():
            match = re.search(r"-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]+)", cmd_line, re.IGNORECASE)
            if match:
                raw_attrs["encoded_payload"] = match.group(1)

        event_id = system_data.get("eventID") or f"Wazuh-Rule-{alert.rule.id}"

        return ParsedEvent(
            event_id=f"Wazuh-{event_id}",
            timestamp=alert.timestamp,
            source_type="WazuhSIEM",
            host_name=alert.agent.name,
            user_name=user_name,
            process_name=process_name,
            process_path=process_path,
            command_line=cmd_line,
            parent_process=parent_process,
            source_ip=source_ip,
            source_port=source_port,
            dest_ip=dest_ip,
            dest_port=dest_port,
            file_hash=file_hash,
            raw_attributes=raw_attrs
        )

    @classmethod
    def execute_active_response(
        cls,
        agent_id: str,
        command: str,
        target_ip: Optional[str] = None
    ) -> RecommendedAction:
        """
        Khởi tạo hành động Wazuh Active Response (chặn IP, cô lập máy).
        Đóng gói thành RecommendedAction tương thích hệ thống.
        """
        action_map = {
            "firewall-drop": ActionType.BLOCK_IP,
            "host-isolate": ActionType.ISOLATE_HOST,
            "kill-process": ActionType.KILL_PROCESS
        }
        
        act_type = action_map.get(command, ActionType.WAZUH_ACTIVE_RESPONSE)
        target = target_ip if target_ip else f"Agent-{agent_id}"

        return RecommendedAction(
            action_type=act_type,
            target=target,
            description=f"Wazuh Active Response [{command}] trên Agent ID {agent_id} (Target: {target}).",
            priority=1,
            require_human_approval=True
        )
