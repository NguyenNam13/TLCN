# -*- coding: utf-8 -*-
"""
src/tools/parsers.py
Công cụ phân tích cú pháp (Log Parsers) cho Data Ingestion Agent.
Chuyển đổi dữ liệu log thô (Sysmon, Zeek, EVTX, MailGateway) thành đối tượng chuẩn ParsedEvent.
"""

import json
import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from src.core.schemas import ParsedEvent


class LogParserTool:
    """Bộ công cụ trích xuất và chuẩn hóa log an ninh mạng."""

    @staticmethod
    def parse_sysmon(raw_payload: str) -> ParsedEvent:
        """Phân tích log Sysmon (định dạng JSON hoặc dict)."""
        data = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
        
        event_id = str(data.get("EventID", "1"))
        cmd_line = data.get("CommandLine", "")
        
        # Bóc tách và giải mã PowerShell Base64 nếu có
        raw_attrs: Dict[str, Any] = {}
        if "-enc" in cmd_line.lower():
            match = re.search(r"-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]+)", cmd_line, re.IGNORECASE)
            if match:
                raw_attrs["encoded_payload"] = match.group(1)
        
        return ParsedEvent(
            event_id=f"Sysmon-{event_id}",
            timestamp=datetime.now(timezone.utc),
            source_type="Sysmon",
            host_name=data.get("Computer", "UNKNOWN-HOST"),
            user_name=data.get("User", "UNKNOWN-USER"),
            process_name=data.get("Image", "").split("\\")[-1] if data.get("Image") else None,
            process_path=data.get("Image"),
            command_line=cmd_line,
            parent_process=data.get("ParentImage", "").split("\\")[-1] if data.get("ParentImage") else None,
            source_ip=data.get("SourceIp"),
            source_port=int(data.get("SourcePort")) if data.get("SourcePort") else None,
            dest_ip=data.get("DestinationIp"),
            dest_port=int(data.get("DestinationPort")) if data.get("DestinationPort") else None,
            file_hash=data.get("Hashes"),
            raw_attributes=raw_attrs
        )

    @staticmethod
    def parse_zeek_conn(raw_payload: str) -> ParsedEvent:
        """Phân tích log Zeek conn.log."""
        data = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
        
        return ParsedEvent(
            event_id="Zeek-conn",
            timestamp=datetime.now(timezone.utc),
            source_type="Zeek",
            source_ip=data.get("id.orig_h"),
            source_port=data.get("id.orig_p"),
            dest_ip=data.get("id.resp_h"),
            dest_port=data.get("id.resp_p"),
            raw_attributes={
                "proto": data.get("proto"),
                "conn_state": data.get("conn_state"),
                "history": data.get("history"),
                "service": data.get("service")
            }
        )

    @staticmethod
    def parse_windows_evtx(raw_payload: str) -> ParsedEvent:
        """Phân tích log Windows Security EVTX (Event ID 4624, 4625, 7045)."""
        data = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
        
        event_id = str(data.get("EventID", "UNKNOWN"))
        return ParsedEvent(
            event_id=f"EVTX-{event_id}",
            timestamp=datetime.now(timezone.utc),
            source_type="WindowsSecurity",
            host_name=data.get("WorkstationName", "UNKNOWN-PC"),
            user_name=data.get("TargetUserName", data.get("AccountName")),
            source_ip=data.get("IpAddress"),
            source_port=int(data.get("IpPort")) if data.get("IpPort") else None,
            raw_attributes={
                "LogonType": data.get("LogonType"),
                "ServiceName": data.get("ServiceName"),
                "ImagePath": data.get("ImagePath"),
                "TargetDomainName": data.get("TargetDomainName")
            }
        )
