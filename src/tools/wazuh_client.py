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
        win_data = alert.data.get("win", {})
        eventdata = win_data.get("eventdata", {})
        system_data = win_data.get("system", {})

        # Trích xuất thông tin tiến trình & lệnh
        process_path = eventdata.get("image") or eventdata.get("ImagePath")
        process_name = process_path.split("\\")[-1] if process_path else None
        cmd_line = eventdata.get("commandLine") or eventdata.get("CommandLine")
        parent_process = eventdata.get("parentImage", "").split("\\")[-1] if eventdata.get("parentImage") else None

        # Trích xuất network / authentication
        source_ip = eventdata.get("sourceIp") or eventdata.get("IpAddress") or alert.agent.ip
        dest_ip = eventdata.get("destinationIp")
        dest_port = int(eventdata.get("destinationPort")) if eventdata.get("destinationPort") else None
        file_hash = eventdata.get("hashes") or eventdata.get("Hashes")
        user_name = eventdata.get("user") or eventdata.get("TargetUserName") or eventdata.get("AccountName")

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
