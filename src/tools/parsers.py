# -*- coding: utf-8 -*-
"""
src/tools/parsers.py
Công cụ phân tích cú pháp (Log Parsers) cho Data Ingestion Agent.
Chuyển đổi dữ liệu log thô (Sysmon, Zeek, EVTX, MailGateway) thành đối tượng chuẩn ParsedEvent.
"""

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Union

from src.core.schemas import ParsedEvent


class LogParserTool:
    """Bộ công cụ trích xuất và chuẩn hóa log an ninh mạng đa định dạng."""

    @staticmethod
    def parse_sysmon(raw_payload: Union[str, Dict[str, Any]]) -> ParsedEvent:
        """Phân tích log Sysmon (định dạng JSON hoặc dict) với fallback an toàn."""
        try:
            data = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
            if not isinstance(data, dict):
                data = {"raw": str(raw_payload)}
        except Exception:
            # Fallback an toàn nếu payload không phải JSON
            return LogParserTool.parse_generic_wazuh(raw_payload)
        
        event_id = str(data.get("EventID", "1"))
        cmd_line = data.get("CommandLine", "")
        
        # Bóc tách và giải mã PowerShell Base64 nếu có
        raw_attrs: Dict[str, Any] = {}
        if cmd_line and "-enc" in str(cmd_line).lower():
            match = re.search(r"-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]+)", str(cmd_line), re.IGNORECASE)
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
            command_line=str(cmd_line),
            parent_process=data.get("ParentImage", "").split("\\")[-1] if data.get("ParentImage") else None,
            source_ip=data.get("SourceIp"),
            source_port=int(data.get("SourcePort")) if data.get("SourcePort") else None,
            dest_ip=data.get("DestinationIp"),
            dest_port=int(data.get("DestinationPort")) if data.get("DestinationPort") else None,
            file_hash=data.get("Hashes"),
            raw_attributes=raw_attrs
        )

    @staticmethod
    def parse_zeek_conn(raw_payload: Union[str, Dict[str, Any]]) -> ParsedEvent:
        """Phân tích log Zeek conn.log."""
        try:
            data = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
            if not isinstance(data, dict):
                data = {"raw": str(raw_payload)}
        except Exception:
            return LogParserTool.parse_generic_wazuh(raw_payload)
        
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
    def parse_windows_evtx(raw_payload: Union[str, Dict[str, Any]]) -> ParsedEvent:
        """Phân tích log Windows Security EVTX (Event ID 4624, 4625, 7045)."""
        try:
            data = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
            if not isinstance(data, dict):
                data = {"raw": str(raw_payload)}
        except Exception:
            return LogParserTool.parse_generic_wazuh(raw_payload)
        
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

    @staticmethod
    def parse_wazuh_alert(raw_payload: Union[str, Dict[str, Any]]) -> ParsedEvent:
        """Phân tích cảnh báo từ Wazuh SIEM (JSON string hoặc dict)."""
        from src.tools.wazuh_client import WazuhClientTool
        data = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
        alert = WazuhClientTool.parse_alert_dict(data)
        return WazuhClientTool.convert_to_parsed_event(alert)

    # =====================================================================
    # UPGRADE: BỔ SUNG CÁC PARSER ĐA ĐỊNH DẠNG (LINUX, SURICATA, WEB, GENERIC)
    # =====================================================================
    @staticmethod
    def parse_suricata_alert(raw_payload: Union[str, Dict[str, Any]]) -> ParsedEvent:
        """Phân tích cảnh báo Suricata IDS/NIDS (JSON format hoặc dict)."""
        try:
            data = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
            if not isinstance(data, dict):
                data = {"raw": str(raw_payload)}
        except Exception:
            return LogParserTool.parse_generic_wazuh(raw_payload)

        alert_info = data.get("alert", {}) if isinstance(data.get("alert"), dict) else {}
        sig = alert_info.get("signature") or data.get("signature") or "Suricata Alert"
        severity = alert_info.get("severity")

        src_port = None
        try:
            if data.get("src_port"):
                src_port = int(data.get("src_port"))
        except (ValueError, TypeError):
            pass

        dest_port = None
        try:
            if data.get("dest_port"):
                dest_port = int(data.get("dest_port"))
        except (ValueError, TypeError):
            pass

        return ParsedEvent(
            event_id=f"Suricata-{data.get('event_type', 'alert')}-{uuid.uuid4().hex[:6]}",
            timestamp=datetime.now(timezone.utc),
            source_type="Suricata",
            host_name=data.get("host") or data.get("hostname") or "NIDS-SENSOR",
            user_name=None,
            process_name="suricata",
            command_line=sig,
            source_ip=data.get("src_ip"),
            source_port=src_port,
            dest_ip=data.get("dest_ip"),
            dest_port=dest_port,
            raw_attributes={
                "proto": data.get("proto"),
                "signature": sig,
                "category": alert_info.get("category"),
                "severity": severity,
                "suricata_alert": alert_info
            }
        )

    @staticmethod
    def parse_linux_syslog(raw_payload: Union[str, Dict[str, Any]]) -> ParsedEvent:
        """Phân tích Linux Syslog (SSH, sudo, PAM, auditd, cron)."""
        data = None
        if isinstance(raw_payload, str):
            try:
                data = json.loads(raw_payload)
            except Exception:
                data = None
        elif isinstance(raw_payload, dict):
            data = raw_payload

        if isinstance(data, dict):
            src_ip = data.get("srcip") or data.get("src_ip")
            user_name = data.get("srcuser") or data.get("dstuser") or data.get("user")
            prog = data.get("program_name") or data.get("process") or "syslog"
            cmd = data.get("command") or data.get("full_log") or prog
            host = data.get("hostname") or data.get("host") or "LINUX-SERVER"
            return ParsedEvent(
                event_id=f"LinuxSyslog-{prog}-{uuid.uuid4().hex[:6]}",
                timestamp=datetime.now(timezone.utc),
                source_type="LinuxSyslog",
                host_name=host,
                user_name=user_name,
                process_name=prog,
                command_line=str(cmd),
                source_ip=src_ip,
                raw_attributes={"program_name": prog, "syslog_data": data}
            )

        # Chuỗi văn bản thuần (Regex fallback)
        raw_text = str(raw_payload)
        ip_match = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", raw_text)
        src_ip = ip_match.group(1) if ip_match else None

        user_name = None
        m = re.search(r'(?:invalid\s+user|user\s+name|user|account)[\s=:]+([a-zA-Z0-9_\.\-]+)', raw_text, re.IGNORECASE)
        if m and m.group(1).lower() not in ("invalid", "unknown", "none", "a", "an", "the"):
            user_name = m.group(1).strip()
        else:
            m2 = re.search(r'(?:for|by|as)\s+(?:user\s+|account\s+|invalid\s+)?([a-zA-Z0-9_\.\-]+)(?:\s+from|\s+at|\s+on|\s*[,;:]|\s*$)', raw_text, re.IGNORECASE)
            if m2 and m2.group(1).lower() not in ("invalid", "user", "unknown", "none", "a", "an", "the", "authentication", "failed", "password"):
                user_name = m2.group(1).strip()

        prog_match = re.search(r"\b([a-zA-Z0-9_\-\.]+)(?:\[\d+\])?:\s+", raw_text)
        prog = prog_match.group(1) if prog_match else "linux-daemon"

        return ParsedEvent(
            event_id=f"LinuxSyslog-{prog}-{uuid.uuid4().hex[:6]}",
            timestamp=datetime.now(timezone.utc),
            source_type="LinuxSyslog",
            host_name="LINUX-SERVER",
            user_name=user_name,
            process_name=prog,
            command_line=raw_text[:500],
            source_ip=src_ip,
            raw_attributes={"raw_log": raw_text[:500]}
        )

    @staticmethod
    def parse_web_log(raw_payload: Union[str, Dict[str, Any]]) -> ParsedEvent:
        """Phân tích Web Server logs (Apache, Nginx, IIS access / error logs)."""
        data = None
        if isinstance(raw_payload, str):
            try:
                data = json.loads(raw_payload)
            except Exception:
                data = None
        elif isinstance(raw_payload, dict):
            data = raw_payload

        if isinstance(data, dict):
            src_ip = data.get("clientip") or data.get("srcip") or data.get("remote_ip")
            req = data.get("request") or data.get("url") or data.get("command") or ""
            status = data.get("status") or data.get("response_code")
            return ParsedEvent(
                event_id=f"WebLog-{uuid.uuid4().hex[:6]}",
                timestamp=datetime.now(timezone.utc),
                source_type="WebServer",
                host_name=data.get("host") or data.get("server_name") or "WEB-SERVER",
                user_name=data.get("srcuser") or data.get("user"),
                process_name=data.get("program_name") or "nginx",
                command_line=str(req),
                source_ip=src_ip,
                raw_attributes={"status_code": status, "method": data.get("method"), "web_data": data}
            )

        raw_text = str(raw_payload)
        ip_match = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", raw_text)
        src_ip = ip_match.group(1) if ip_match else None

        req_match = re.search(r'"([A-Z]+\s+[^"\s]+(?:\s+HTTP/[\d\.]+)?)"', raw_text)
        req = req_match.group(1) if req_match else raw_text[:300]

        return ParsedEvent(
            event_id=f"WebLog-{uuid.uuid4().hex[:6]}",
            timestamp=datetime.now(timezone.utc),
            source_type="WebServer",
            host_name="WEB-SERVER",
            user_name=None,
            process_name="webserver",
            command_line=req,
            source_ip=src_ip,
            raw_attributes={"raw_log": raw_text[:500]}
        )

    @staticmethod
    def parse_generic_wazuh(raw_payload: Union[str, Dict[str, Any]]) -> ParsedEvent:
        """
        Parser tổng quát an toàn cho bất kỳ log Wazuh / hệ thống nào không có parser chuyên dụng.
        Không bao giờ raise exception, luôn trả về ParsedEvent hợp lệ.
        """
        try:
            if isinstance(raw_payload, str):
                try:
                    data = json.loads(raw_payload)
                except Exception:
                    data = {"full_log": raw_payload}
            elif isinstance(raw_payload, dict):
                data = raw_payload
            else:
                data = {"raw_payload": str(raw_payload)}

            # Nếu có rule Wazuh, ủy quyền qua WazuhClientTool
            if "rule" in data:
                from src.tools.wazuh_client import WazuhClientTool
                alert = WazuhClientTool.parse_alert_dict(data)
                return WazuhClientTool.convert_to_parsed_event(alert)

            # Bóc tách tổng quát
            full_text = str(data.get("full_log") or data.get("message") or raw_payload)
            ip_match = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", full_text)
            src_ip = (
                data.get("srcip")
                or data.get("src_ip")
                or (ip_match.group(1) if ip_match else None)
            )

            dest_ip = data.get("dstip") or data.get("dest_ip")

            user_match = re.search(r"(?:user|for|by|from)\s+([\w.@-]+)", full_text, re.IGNORECASE)
            user_name = (
                data.get("srcuser")
                or data.get("user")
                or (user_match.group(1) if user_match else None)
            )

            cmd_line = (
                data.get("command")
                or data.get("commandLine")
                or data.get("CommandLine")
                or full_text[:400]
            )

            proc_name = (
                data.get("program_name")
                or data.get("process")
                or data.get("Image", "").split("\\")[-1]
                or "generic_process"
            )

            return ParsedEvent(
                event_id=f"Generic-{uuid.uuid4().hex[:6]}",
                timestamp=datetime.now(timezone.utc),
                source_type="GenericLog",
                host_name=data.get("host") or data.get("Computer") or "UNKNOWN-HOST",
                user_name=user_name,
                process_name=proc_name,
                command_line=str(cmd_line),
                source_ip=src_ip,
                dest_ip=dest_ip,
                raw_attributes={"original_data": data if isinstance(data, dict) else str(data)[:500]}
            )
        except Exception as err:
            return ParsedEvent(
                event_id=f"Fallback-{uuid.uuid4().hex[:6]}",
                timestamp=datetime.now(timezone.utc),
                source_type="UnparsedRaw",
                host_name="UNKNOWN-HOST",
                command_line=str(raw_payload)[:300],
                raw_attributes={"error": str(err), "raw_preview": str(raw_payload)[:200]}
            )

