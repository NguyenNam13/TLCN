# -*- coding: utf-8 -*-
"""
src/agents/ingestion_agent.py
Data Ingestion Agent cho Hệ thống Multi-Agent điều tra sự cố SOC.
Nhiệm vụ:
1. Tiếp nhận và tiền xử lý cảnh báo từ Wazuh SIEM (Stream/Batch hoặc từng bản ghi).
2. Bóc tách WazuhAlert thành đối tượng có cấu trúc ParsedEvent chuẩn.
3. Giải mã câu lệnh Base64 (đặc biệt là PowerShell -enc/UTF-16LE) và lưu vào raw_attributes['decoded_command'].
4. Trích xuất sơ bộ các chỉ số IoC (IPs, URLs, Domains, Hashes).
5. Khởi tạo đối tượng trạng thái IncidentState ban đầu với status=NEW.
"""

import re
import uuid
import base64
import ipaddress
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Union

from src.core.schemas import (
    WazuhAlert,
    ParsedEvent,
    RawLogInput,
    IncidentStatus
)
from src.core.state import IncidentState
from src.agents.prompts import INGESTION_AGENT_SYSTEM_PROMPT
from src.tools.wazuh_client import WazuhClientTool
from src.tools.wazuh_stream import WazuhAlertStreamer
from src.tools.deobfuscator import AdvancedPowerShellDeobfuscator, DeobfuscationResult


class IngestionAgent:
    """
    Agent tiếp nhận và chuẩn hóa dữ liệu cảnh báo an ninh mạng.
    Tuân thủ nghiêm ngặt INGESTION_AGENT_SYSTEM_PROMPT và định dạng ParsedEvent / IncidentState.
    """

    def __init__(self, system_prompt: Optional[str] = None):
        self.system_prompt = system_prompt or INGESTION_AGENT_SYSTEM_PROMPT
        self.name = "DataIngestionAgent"

    @staticmethod
    def decode_base64_command(command_line: Optional[str]) -> Optional[str]:
        """
        Phát hiện và giải mã chuỗi dòng lệnh Base64 (ví dụ PowerShell -enc / -e / -encodedcommand)
        kết hợp khử làm rối chuyên sâu qua AdvancedPowerShellDeobfuscator.
        Xử lý đa tầng Nested Base64, GzipStream (H4sI...), backticks và nối chuỗi.

        :param command_line: Chuỗi câu lệnh đầy đủ.
        :return: Chuỗi câu lệnh đã giải mã hoặc None nếu không phát hiện base64 / obfuscated command.
        """
        if not command_line:
            return None

        # 1. Thử giải mã qua AdvancedPowerShellDeobfuscator đa tầng
        try:
            deob_res = AdvancedPowerShellDeobfuscator.deobfuscate(command_line)
            if deob_res.has_obfuscation and deob_res.deobfuscated_command.strip() != command_line.strip():
                return deob_res.deobfuscated_command
        except Exception:
            pass

        # 2. Cơ chế bóc tách Regex trực tiếp truyền thống (Fallback)
        pattern = r"(?:-|\/)(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]{8,})"
        match = re.search(pattern, command_line, re.IGNORECASE)
        if not match:
            return None

        b64_str = match.group(1).strip()
        try:
            raw_bytes = base64.b64decode(b64_str)
            # Thử giải mã UTF-16LE (chuẩn mã hóa chuỗi của PowerShell Windows)
            try:
                decoded = raw_bytes.decode("utf-16le").strip()
                # Nếu chuỗi không chứa null bytes rác và đọc được ký tự in ấn
                if decoded and all(ord(c) >= 32 or c in "\r\n\t" for c in decoded):
                    return decoded
            except UnicodeDecodeError:
                pass

            # Thử giải mã UTF-8 thông thường
            try:
                decoded = raw_bytes.decode("utf-8").strip()
                if decoded:
                    return decoded
            except UnicodeDecodeError:
                pass

            # Fallback latin-1
            return raw_bytes.decode("latin-1", errors="ignore").strip()
        except Exception:
            return None

    @staticmethod
    def extract_preliminary_iocs(
        event: ParsedEvent, decoded_cmd: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """
        Trích xuất sơ bộ các chỉ số xâm phạm (IoCs) từ ParsedEvent:
        IPs (phân loại Public vs Private), URLs, Domains, File Hashes.

        :param event: Đối tượng ParsedEvent.
        :param decoded_cmd: Chuỗi lệnh đã giải mã nếu có.
        :return: Danh sách các chỉ số IoC tìm thấy.
        """
        iocs: List[Dict[str, str]] = []
        seen = set()

        def add_ioc(ioc_type: str, value: str, is_public: Optional[bool] = None):
            val_clean = value.strip().rstrip("/'\"")
            key = (ioc_type, val_clean)
            if key not in seen and val_clean:
                seen.add(key)
                item: Dict[str, Any] = {"type": ioc_type, "value": val_clean}
                if is_public is not None:
                    item["is_public"] = is_public
                iocs.append(item)

        # 1. Trích xuất IP từ source_ip và dest_ip
        for ip_candidate in (event.source_ip, event.dest_ip):
            if ip_candidate:
                try:
                    ip_obj = ipaddress.ip_address(ip_candidate)
                    is_public = not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
                    add_ioc("IP", ip_candidate, is_public=is_public)
                except ValueError:
                    pass

        # 2. Quét IP từ dòng lệnh và câu lệnh giải mã
        text_corpus = f"{event.command_line or ''} {decoded_cmd or ''}"
        ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        for ip_match in re.findall(ip_regex, text_corpus):
            try:
                ip_obj = ipaddress.ip_address(ip_match)
                is_public = not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
                add_ioc("IP", ip_match, is_public=is_public)
            except ValueError:
                pass

        # 3. Trích xuất URL
        url_regex = r"https?://[a-zA-Z0-9_\-\.\:]+(?:/[^\s'\"]*)?"
        for url_match in re.findall(url_regex, text_corpus):
            add_ioc("URL", url_match)

        # 4. Trích xuất File Hash
        if event.file_hash:
            # Sysmon format có thể là: "SHA256=xxx,MD5=yyy" hoặc giá trị đơn
            for part in str(event.file_hash).split(","):
                part_clean = part.strip()
                if "=" in part_clean:
                    h_type, h_val = part_clean.split("=", 1)
                    add_ioc(h_type.upper(), h_val.strip())
                elif len(part_clean) == 64:
                    add_ioc("SHA256", part_clean)
                elif len(part_clean) == 32:
                    add_ioc("MD5", part_clean)

        # 5. Trích xuất Domain bổ sung qua AdvancedPowerShellDeobfuscator
        try:
            deob_iocs = AdvancedPowerShellDeobfuscator.extract_iocs(text_corpus)
            for dom_item in deob_iocs.get("domains", []):
                add_ioc("DOMAIN", dom_item["value"])
        except Exception:
            pass

        return iocs

    def parse_alert(self, alert_input: Union[WazuhAlert, Dict[str, Any]]) -> ParsedEvent:
        """
        Bóc tách 1 cảnh báo WazuhAlert thành ParsedEvent với đầy đủ giải mã và IoCs sơ bộ.

        :param alert_input: WazuhAlert hoặc dictionary cảnh báo Wazuh thô.
        :return: ParsedEvent chuẩn hóa.
        """
        if isinstance(alert_input, dict):
            alert = WazuhClientTool.parse_alert_dict(alert_input)
        elif isinstance(alert_input, WazuhAlert):
            alert = alert_input
        else:
            raise TypeError(f"Kiểu dữ liệu alert không được hỗ trợ: {type(alert_input)}")

        # Chuyển đổi cơ bản qua WazuhClientTool
        event = WazuhClientTool.convert_to_parsed_event(alert)

        # Khử làm rối và giải mã câu lệnh chuyên sâu với AdvancedPowerShellDeobfuscator
        deob_res = AdvancedPowerShellDeobfuscator.deobfuscate(event.command_line)
        decoded_cmd = None
        if deob_res.has_obfuscation and deob_res.deobfuscated_command.strip() != (event.command_line or "").strip():
            decoded_cmd = deob_res.deobfuscated_command
            event.raw_attributes["decoded_command"] = decoded_cmd
            event.raw_attributes["deobfuscation_result"] = deob_res.to_dict()
        else:
            decoded_cmd = self.decode_base64_command(event.command_line)
            if decoded_cmd:
                event.raw_attributes["decoded_command"] = decoded_cmd

        # Trích xuất sơ bộ IoCs
        preliminary_iocs = self.extract_preliminary_iocs(event, decoded_cmd)
        if preliminary_iocs:
            event.raw_attributes["preliminary_iocs"] = preliminary_iocs

        return event

    def create_incident_state(
        self,
        alerts: Union[WazuhAlert, List[WazuhAlert], Dict[str, Any], List[Dict[str, Any]]],
        incident_id: Optional[str] = None,
    ) -> IncidentState:
        """
        Khởi tạo đối tượng IncidentState từ một hoặc nhiều cảnh báo Wazuh.

        :param alerts: Một bản ghi hoặc danh sách các bản ghi WazuhAlert / dict.
        :param incident_id: ID sự cố tùy chọn (tự sinh nếu không truyền).
        :return: IncidentState đã được khởi tạo với status=NEW.
        """
        alert_list: List[Union[WazuhAlert, Dict[str, Any]]] = (
            alerts if isinstance(alerts, (list, tuple)) else [alerts]
        )

        now = datetime.now(timezone.utc)
        if not incident_id:
            incident_id = f"INC-WAZUH-{int(now.timestamp())}-{uuid.uuid4().hex[:6].upper()}"

        parsed_events: List[ParsedEvent] = []
        raw_logs: List[RawLogInput] = []

        for raw_alert in alert_list:
            parsed_evt = self.parse_alert(raw_alert)
            parsed_events.append(parsed_evt)

            # Lưu log thô để kiểm toán và truy vết
            if isinstance(raw_alert, WazuhAlert):
                payload_str = raw_alert.model_dump_json()
            elif isinstance(raw_alert, dict):
                import json
                payload_str = json.dumps(raw_alert, ensure_ascii=False)
            else:
                payload_str = str(raw_alert)

            raw_logs.append(
                RawLogInput(
                    log_source="WazuhSIEM",
                    raw_payload=payload_str,
                    collected_at=now,
                )
            )

        return IncidentState(
            incident_id=incident_id,
            status=IncidentStatus.NEW,
            created_at=now,
            updated_at=now,
            raw_logs=raw_logs,
            parsed_events=parsed_events,
        )

    def process(
        self,
        input_data: Union[str, WazuhAlert, List[WazuhAlert], Dict[str, Any], List[Dict[str, Any]]],
        incident_id: Optional[str] = None,
        min_level: Optional[int] = None,
        groups: Optional[List[str]] = None,
    ) -> IncidentState:
        """
        Cổng tiếp nhận chính của IngestionAgent.
        Hỗ trợ nạp từ tệp tin JSON hoặc danh sách cảnh báo trong bộ nhớ.

        :param input_data: Đường dẫn file alerts.json hoặc danh sách alerts.
        :param incident_id: ID sự cố tùy chọn.
        :param min_level: Ngưỡng lọc rule level tối thiểu (tùy chọn).
        :param groups: Nhóm rules cần lọc (tùy chọn).
        :return: IncidentState sẵn sàng cho Triage Agent.
        """
        if isinstance(input_data, str):
            streamer = WazuhAlertStreamer.from_file(
                input_data, min_level=min_level, groups=groups
            )
            alerts = streamer.get_all_alerts()
        elif isinstance(input_data, (list, tuple)):
            streamer = WazuhAlertStreamer.from_list(
                input_data, min_level=min_level, groups=groups
            )
            alerts = streamer.get_all_alerts()
        else:
            alerts = [input_data]

        return self.create_incident_state(alerts, incident_id=incident_id)

    def process_state(self, state: IncidentState) -> IncidentState:
        """
        Bóc tách và chuẩn hóa toàn bộ raw_logs trong IncidentState thành parsed_events.
        Hỗ trợ tích hợp mượt mà với StateGraphOrchestrator ingestion_node.
        """
        from src.tools.parsers import LogParserTool
        import json

        for raw_item in state.raw_logs:
            source = (raw_item.log_source or "").lower()
            payload = raw_item.raw_payload

            try:
                if "wazuh" in source:
                    if isinstance(payload, str):
                        try:
                            payload_data = json.loads(payload)
                            parsed_evt = self.parse_alert(payload_data)
                        except Exception:
                            parsed_evt = LogParserTool.parse_wazuh_alert(payload)
                    else:
                        parsed_evt = self.parse_alert(payload)
                elif "sysmon" in source:
                    parsed_evt = LogParserTool.parse_sysmon(payload)
                elif "zeek" in source:
                    parsed_evt = LogParserTool.parse_zeek_conn(payload)
                elif "evtx" in source or "windows" in source:
                    parsed_evt = LogParserTool.parse_windows_evtx(payload)
                else:
                    parsed_evt = LogParserTool.parse_sysmon(payload)

                # Khử làm rối và giải mã câu lệnh chuyên sâu với AdvancedPowerShellDeobfuscator
                deob_res = AdvancedPowerShellDeobfuscator.deobfuscate(parsed_evt.command_line)
                decoded_cmd = None
                if deob_res.has_obfuscation and deob_res.deobfuscated_command.strip() != (parsed_evt.command_line or "").strip():
                    decoded_cmd = deob_res.deobfuscated_command
                    parsed_evt.raw_attributes["decoded_command"] = decoded_cmd
                    parsed_evt.raw_attributes["deobfuscation_result"] = deob_res.to_dict()
                else:
                    decoded_cmd = self.decode_base64_command(parsed_evt.command_line)
                    if decoded_cmd:
                        parsed_evt.raw_attributes["decoded_command"] = decoded_cmd

                # Trích xuất sơ bộ IoCs
                preliminary_iocs = self.extract_preliminary_iocs(parsed_evt, decoded_cmd)
                if preliminary_iocs:
                    parsed_evt.raw_attributes["preliminary_iocs"] = preliminary_iocs

                state.parsed_events.append(parsed_evt)
            except Exception as ex:
                parsed_evt = LogParserTool.parse_sysmon(payload)
                state.parsed_events.append(parsed_evt)

        return state

