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
import json
import uuid
import zlib
import base64
import hashlib
import logging
import ipaddress
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Union

from src.core.schemas import (
    WazuhAlert,
    ParsedEvent,
    RawLogInput,
    IncidentStatus
)
from src.core.state import IncidentState
from src.core.security_guard import (
    UNTRUSTED_LOG_SECURITY_HEADER,
    inspect_and_wrap_untrusted,
    sanitize_prompt_text,
)
from src.agents.prompts import INGESTION_AGENT_SYSTEM_PROMPT
from src.agents.llm_utils import invoke_structured_llm
from src.tools.parsers import LogParserTool
from src.tools.wazuh_client import WazuhClientTool
from src.tools.wazuh_stream import WazuhAlertStreamer
from src.tools.deobfuscator import AdvancedPowerShellDeobfuscator

logger = logging.getLogger("DataIngestionAgent")


class IngestionAgent:
    """
    Agent tiếp nhận và chuẩn hóa dữ liệu cảnh báo an ninh mạng.
    Tuân thủ nghiêm ngặt INGESTION_AGENT_SYSTEM_PROMPT và định dạng ParsedEvent / IncidentState.
    """

    def __init__(
        self,
        system_prompt: Optional[str] = None,
        llm_provider: Optional[Any] = None,
        enable_llm_fallback: bool = False,
        enable_security_guard: bool = True,
    ):
        self.system_prompt = system_prompt or INGESTION_AGENT_SYSTEM_PROMPT
        self.name = "DataIngestionAgent"
        self.llm_provider = llm_provider
        self.enable_llm_fallback = bool(enable_llm_fallback)
        self.enable_security_guard = bool(enable_security_guard)

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
        iocs: List[Dict[str, Any]] = []
        seen = set()

        def add_ioc(ioc_type: str, value: str, is_public: Optional[bool] = None):
            t_norm = str(ioc_type or "").strip().upper()
            val_clean = value.strip().rstrip("/'\"")
            if not val_clean:
                return
            cmp_val = val_clean.lower() if t_norm in {"MD5", "SHA1", "SHA256", "IMPHASH", "DOMAIN"} else val_clean
            key = (t_norm, cmp_val)
            if key not in seen:
                seen.add(key)
                item: Dict[str, Any] = {"type": t_norm, "value": val_clean}
                if is_public is not None:
                    item["is_public"] = is_public
                iocs.append(item)

        # 1. Trích xuất IP từ source_ip, dest_ip và quét IP từ dòng lệnh / câu lệnh giải mã
        text_corpus = f"{event.command_line or ''} {decoded_cmd or ''}"
        ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ip_candidates = [event.source_ip, event.dest_ip] + re.findall(ip_regex, text_corpus)
        for ip_candidate in ip_candidates:
            if ip_candidate:
                try:
                    ip_obj = ipaddress.ip_address(ip_candidate)
                    is_public = not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
                    add_ioc("IP", ip_candidate, is_public=is_public)
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

    @staticmethod
    def _deduplicate_preliminary_iocs(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Khử trùng lặp danh sách preliminary_iocs theo (type, normalized value)."""
        deduped: List[Dict[str, Any]] = []
        seen = set()
        for item in iocs or []:
            if not isinstance(item, dict):
                continue
            t_norm = str(item.get("type") or "").strip().upper()
            val_raw = str(item.get("value") or "").strip().rstrip("/'\"")
            if not t_norm or not val_raw:
                continue
            cmp_val = val_raw.lower() if t_norm in {"MD5", "SHA1", "SHA256", "IMPHASH", "DOMAIN"} else val_raw
            key = (t_norm, cmp_val)
            if key not in seen:
                seen.add(key)
                clean_item = dict(item)
                clean_item["type"] = t_norm
                clean_item["value"] = val_raw
                deduped.append(clean_item)
        return deduped

    @staticmethod
    def _raw_log_key(log_source: Optional[str], raw_payload: Any) -> str:
        """Tạo khóa định danh ổn định, ngắn gọn cho RawLogInput (không chứa chuỗi hex >=32 ký tự)."""
        src = str(log_source or "").strip().lower()
        if isinstance(raw_payload, dict):
            canonical = json.dumps(raw_payload, sort_keys=True, ensure_ascii=False)
        else:
            raw_str = str(raw_payload or "").strip()
            canonical = raw_str
            if raw_str.startswith("{") or raw_str.startswith("["):
                try:
                    parsed = json.loads(raw_str)
                    canonical = json.dumps(parsed, sort_keys=True, ensure_ascii=False)
                except Exception:
                    canonical = raw_str
        payload_bytes = canonical.encode("utf-8", errors="ignore")
        short_digest = hashlib.sha256(payload_bytes).hexdigest()[:16]
        return f"{src}:{zlib.crc32(payload_bytes):08x}:{len(payload_bytes)}:{short_digest}"

    @staticmethod
    def _compute_event_signature(event: ParsedEvent) -> Tuple[Any, ...]:
        """Tạo chữ ký ổn định cho ParsedEvent phục vụ khử trùng lặp idempotent."""
        raw_eid = str(event.event_id or "").strip()
        if re.match(r"^(?:Suricata|LinuxSyslog|UNKNOWN)-.*-[0-9a-fA-F]{6}$", raw_eid):
            norm_eid = re.sub(r"-[0-9a-fA-F]{6}$", "", raw_eid)
        elif raw_eid.startswith("EVT-UNKNOWN-"):
            norm_eid = "EVT-UNKNOWN"
        else:
            norm_eid = raw_eid

        attrs = event.raw_attributes or {}
        return (
            norm_eid,
            str(event.source_type or "").strip().lower(),
            str(event.host_name or "").strip().lower(),
            str(event.user_name or "").strip().lower(),
            str(event.process_name or "").strip().lower(),
            str(event.process_path or "").strip().lower(),
            str(event.command_line or "").strip(),
            str(event.parent_process or "").strip().lower(),
            str(event.source_ip or "").strip(),
            event.source_port,
            str(event.dest_ip or "").strip(),
            event.dest_port,
            str(event.file_hash or "").strip().lower(),
            str(attrs.get("wazuh_alert_id") or ""),
            str(attrs.get("wazuh_rule_id") or ""),
            str(attrs.get("zeek_ts") or ""),
            str(attrs.get("raw_payload") or attrs.get("raw_log") or ""),
        )

    @classmethod
    def _append_event_idempotent(
        cls,
        state: IncidentState,
        parsed_evt: ParsedEvent,
        raw_key: Optional[str] = None,
    ) -> bool:
        """Thêm ParsedEvent vào state nếu chưa tồn tại (idempotent). Trả về True nếu đã thêm."""
        existing_sigs = {cls._compute_event_signature(e) for e in state.parsed_events}
        evt_sig = cls._compute_event_signature(parsed_evt)
        added = False
        if evt_sig not in existing_sigs:
            state.parsed_events.append(parsed_evt)
            added = True
        if raw_key:
            ingested_keys = state.workflow_telemetry.setdefault("ingested_raw_keys", [])
            if raw_key not in ingested_keys:
                ingested_keys.append(raw_key)
        return added

    def _enrich_event_command_and_iocs(self, event: ParsedEvent) -> ParsedEvent:
        """
        Khử làm rối câu lệnh qua AdvancedPowerShellDeobfuscator và trích xuất sơ bộ IoCs.
        """
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

        existing_prelim = event.raw_attributes.get("preliminary_iocs") or []
        preliminary_iocs = self.extract_preliminary_iocs(event, decoded_cmd)
        combined_prelim = self._deduplicate_preliminary_iocs(list(existing_prelim) + list(preliminary_iocs))
        if combined_prelim:
            event.raw_attributes["preliminary_iocs"] = combined_prelim

        event.raw_attributes.setdefault("parsed_by", "deterministic_parser")
        return event

    def _needs_llm_fallback(
        self,
        parsed_evt: ParsedEvent,
        raw_payload: Any,
        used_generic_or_error: bool = False,
    ) -> bool:
        """
        Kiểm tra có cần kích hoạt LLM fallback cho bản ghi log phi cấu trúc hay không.
        Chỉ kích hoạt khi:
        - `enable_llm_fallback=True` và `llm_provider` sẵn sàng.
        - Parser deterministic rơi vào nhánh generic/error (hoặc source_type GenericLog/UnparsedRaw/Unknown).
        - Toàn bộ trường cốt lõi (process_name, source_ip, dest_ip, user_name, wazuh_rule_id) đều trống/placeholder.
        - Độ dài payload >= 10 ký tự.
        """
        if not self.enable_llm_fallback or self.llm_provider is None:
            return False
        prov_mode = str(getattr(self.llm_provider, "provider_mode", "") or "").strip().lower()
        if prov_mode == "deterministic":
            return False

        if isinstance(raw_payload, dict):
            payload_str = json.dumps(raw_payload, ensure_ascii=False)
        else:
            payload_str = str(raw_payload or "")

        if len(payload_str.strip()) < 10:
            return False

        attrs = parsed_evt.raw_attributes or {}
        proc_val = str(parsed_evt.process_name or "").strip().lower()
        user_val = str(parsed_evt.user_name or "").strip().lower()
        proc_empty = (not proc_val) or (proc_val in {"generic_process", "unknown", "n/a"})
        src_empty = not parsed_evt.source_ip
        dst_empty = not parsed_evt.dest_ip
        user_empty = (not user_val) or (user_val in {"unknown-user", "unknown", "n/a"})
        rule_empty = not attrs.get("wazuh_rule_id")

        if not (proc_empty and src_empty and dst_empty and user_empty and rule_empty):
            return False

        src_type = str(parsed_evt.source_type or "").strip()
        return bool(used_generic_or_error or src_type in {"GenericLog", "UnparsedRaw", "Unknown", ""})

    def _parse_unstructured_with_llm(
        self,
        source: str,
        raw_payload: Any,
        incident_state: Optional[IncidentState] = None,
    ) -> Tuple[Optional[ParsedEvent], bool, Optional[str]]:
        """
        Sử dụng LLM (fast tier, temperature=0.0) bóc tách log phi cấu trúc thành ParsedEvent.
        Tích hợp SecurityGuard (`inspect_and_wrap_untrusted`) nhưng vẫn bảo toàn bằng chứng nếu phát hiện injection.
        """
        if isinstance(raw_payload, dict):
            payload_str = json.dumps(raw_payload, ensure_ascii=False)
        else:
            payload_str = str(raw_payload or "")

        inj_detected = False
        inj_reason: Optional[str] = None
        safe_source = sanitize_prompt_text(source or "Unknown", max_len=120) or "Unknown"
        if self.enable_security_guard:
            wrapped_payload, inj_detected, inj_reason = inspect_and_wrap_untrusted(
                payload_str,
                field_name="ingestion_raw_payload",
                max_len=1500,
                include_notice=False,
            )
            prompt = (
                f"{UNTRUSTED_LOG_SECURITY_HEADER}\n\n"
                f"Hãy chuẩn hóa bản ghi log phi cấu trúc từ nguồn '{safe_source}' thành đối tượng JSON ParsedEvent.\n"
                f"Chỉ trích xuất các thực thể thực sự có trong log, để null nếu không xuất hiện.\n\n"
                f"Dữ liệu log thô:\n{wrapped_payload}"
            )
        else:
            wrapped_payload = payload_str[:1500]
            prompt = (
                f"Hãy chuẩn hóa bản ghi log phi cấu trúc từ nguồn '{safe_source}' thành đối tượng JSON ParsedEvent.\n"
                f"Chỉ trích xuất các thực thể thực sự có trong log, để null nếu không xuất hiện.\n\n"
                f"Dữ liệu log thô:\n{wrapped_payload}"
            )

        llm_evt, used_real_llm, info = invoke_structured_llm(
            self.llm_provider,
            prompt,
            ParsedEvent,
            system_prompt=self.system_prompt,
            incident_state=incident_state,
            model_tier="fast",
            temperature=0.0,
            max_tokens=1000,
            agent_name="IngestionAgent",
        )

        parsed_obj: Optional[ParsedEvent] = None
        if used_real_llm and isinstance(llm_evt, ParsedEvent):
            parsed_obj = llm_evt
        elif used_real_llm and llm_evt is None and isinstance(info, str) and info.strip():
            json_text = info.strip()
            if "```" in json_text:
                m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", json_text, re.DOTALL)
                if m:
                    json_text = m.group(1)
            try:
                parsed_obj = ParsedEvent.model_validate_json(json_text)
            except Exception:
                parsed_obj = None

        if parsed_obj is None:
            return None, inj_detected, inj_reason

        attrs = dict(parsed_obj.raw_attributes or {})
        attrs["parsed_by"] = "llm_fallback"
        attrs.setdefault("raw_payload", payload_str[:500])
        if inj_detected:
            attrs["prompt_injection_detected"] = True
            attrs["prompt_injection_reason"] = inj_reason or "Detected prompt injection"
        parsed_obj.raw_attributes = attrs
        return parsed_obj, inj_detected, inj_reason

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
        return self._enrich_event_command_and_iocs(event)

    def parse_wazuh_alert(
        self,
        alert_input: Union[WazuhAlert, Dict[str, Any], str],
        state: Optional[IncidentState] = None,
    ) -> ParsedEvent:
        """Bóc tách cảnh báo Wazuh và (tùy chọn) điền idempotent vào IncidentState."""
        if isinstance(alert_input, str):
            raw_key = self._raw_log_key("wazuh", alert_input)
            try:
                payload_data = json.loads(alert_input)
                parsed_evt = self.parse_alert(payload_data)
            except Exception:
                parsed_evt = self._enrich_event_command_and_iocs(LogParserTool.parse_wazuh_alert(alert_input))
        else:
            payload_str = alert_input.model_dump_json() if isinstance(alert_input, WazuhAlert) else json.dumps(alert_input, ensure_ascii=False)
            raw_key = self._raw_log_key("WazuhSIEM", payload_str)
            parsed_evt = self.parse_alert(alert_input)

        if state is not None:
            self._append_event_idempotent(state, parsed_evt, raw_key=raw_key)
        return parsed_evt

    def parse_zeek_log(
        self,
        log_input: Union[Dict[str, Any], str],
        state: Optional[IncidentState] = None,
    ) -> ParsedEvent:
        """Bóc tách log Zeek conn.log và (tùy chọn) điền idempotent vào IncidentState."""
        parsed_evt = LogParserTool.parse_zeek_conn(log_input)
        try:
            payload_obj = json.loads(log_input) if isinstance(log_input, str) else log_input
            if isinstance(payload_obj, dict) and payload_obj.get("ts") is not None:
                parsed_evt.raw_attributes["zeek_ts"] = str(payload_obj.get("ts"))
        except Exception:
            pass
        self._enrich_event_command_and_iocs(parsed_evt)
        if state is not None:
            raw_key = self._raw_log_key("zeek", log_input)
            self._append_event_idempotent(state, parsed_evt, raw_key=raw_key)
        return parsed_evt

    def create_incident_state(
        self,
        alerts: Union[WazuhAlert, List[WazuhAlert], Dict[str, Any], List[Dict[str, Any]]],
        incident_id: Optional[str] = None,
    ) -> IncidentState:
        """
        Khởi tạo đối tượng IncidentState từ một hoặc nhiều cảnh báo Wazuh (chống trùng lặp idempotent).

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
        seen_raw_keys = set()
        seen_event_sigs = set()
        ingested_raw_keys: List[str] = []

        for raw_alert in alert_list:
            # Lưu log thô để kiểm toán và truy vết
            if isinstance(raw_alert, WazuhAlert):
                payload_str = raw_alert.model_dump_json()
            elif isinstance(raw_alert, dict):
                payload_str = json.dumps(raw_alert, ensure_ascii=False)
            else:
                payload_str = str(raw_alert)

            raw_key = self._raw_log_key("WazuhSIEM", payload_str)
            if raw_key in seen_raw_keys:
                continue

            parsed_evt = self.parse_alert(raw_alert)
            evt_sig = self._compute_event_signature(parsed_evt)
            seen_raw_keys.add(raw_key)
            ingested_raw_keys.append(raw_key)

            if evt_sig in seen_event_sigs:
                continue
            seen_event_sigs.add(evt_sig)

            parsed_events.append(parsed_evt)
            raw_logs.append(
                RawLogInput(
                    log_source="WazuhSIEM",
                    raw_payload=payload_str,
                    collected_at=now,
                )
            )

        state = IncidentState(
            incident_id=incident_id,
            status=IncidentStatus.NEW,
            created_at=now,
            updated_at=now,
            raw_logs=raw_logs,
            parsed_events=parsed_events,
        )
        state.workflow_telemetry["ingested_raw_keys"] = ingested_raw_keys
        return state

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
        Bóc tách và chuẩn hóa toàn bộ raw_logs trong IncidentState thành parsed_events một cách idempotent.
        Hỗ trợ tích hợp mượt mà với StateGraphOrchestrator ingestion_node và hỗ trợ
        đa nguồn log: Wazuh, Sysmon, Zeek, Suricata NIDS, Linux Syslog, WebServer, Generic.
        """
        # 1. Khử trùng lặp parsed_events sẵn có (nếu có) và lập chỉ mục chữ ký
        deduped_existing: List[ParsedEvent] = []
        seen_event_sigs = set()
        for existing_evt in state.parsed_events:
            if existing_evt.raw_attributes.get("preliminary_iocs"):
                existing_evt.raw_attributes["preliminary_iocs"] = self._deduplicate_preliminary_iocs(
                    existing_evt.raw_attributes["preliminary_iocs"]
                )
            sig = self._compute_event_signature(existing_evt)
            if sig not in seen_event_sigs:
                seen_event_sigs.add(sig)
                deduped_existing.append(existing_evt)
        if len(deduped_existing) != len(state.parsed_events):
            state.parsed_events = deduped_existing

        ingested_keys = state.workflow_telemetry.setdefault("ingested_raw_keys", [])
        seen_raw_keys = set(ingested_keys)

        for raw_item in state.raw_logs:
            raw_key = self._raw_log_key(raw_item.log_source, raw_item.raw_payload)
            if raw_key in seen_raw_keys:
                continue

            source = (raw_item.log_source or "").lower()
            payload = raw_item.raw_payload
            parsed_evt = None
            already_enriched = False
            used_generic_or_error = False

            try:
                if "wazuh" in source:
                    if isinstance(payload, str):
                        try:
                            payload_data = json.loads(payload)
                            parsed_evt = self.parse_alert(payload_data)
                            already_enriched = True
                        except Exception:
                            parsed_evt = LogParserTool.parse_wazuh_alert(payload)
                    else:
                        parsed_evt = self.parse_alert(payload)
                        already_enriched = True
                elif "sysmon" in source:
                    parsed_evt = LogParserTool.parse_sysmon(payload)
                elif "zeek" in source:
                    parsed_evt = self.parse_zeek_log(payload)
                    already_enriched = True
                elif "suricata" in source or "nids" in source or "ids" in source:
                    parsed_evt = LogParserTool.parse_suricata_alert(payload)
                elif "linux" in source or "syslog" in source or "ssh" in source or "auditd" in source:
                    parsed_evt = LogParserTool.parse_linux_syslog(payload)
                elif "web" in source or "apache" in source or "nginx" in source or "http" in source:
                    parsed_evt = LogParserTool.parse_web_log(payload)
                elif "evtx" in source or "windows" in source:
                    parsed_evt = LogParserTool.parse_windows_evtx(payload)
                else:
                    used_generic_or_error = True
                    parsed_evt = LogParserTool.parse_generic_wazuh(payload)
            except Exception as ex:
                logger.warning(f"[DataIngestionAgent] Lỗi khi bóc tách log từ nguồn '{source}': {ex}")
                used_generic_or_error = True
                try:
                    parsed_evt = LogParserTool.parse_generic_wazuh(payload)
                except Exception as inner_ex:
                    parsed_evt = ParsedEvent(
                        event_id=f"UNKNOWN-{uuid.uuid4().hex[:6]}",
                        timestamp=datetime.now(timezone.utc),
                        source_type=source or "Unknown",
                        command_line=str(payload)[:200],
                        raw_attributes={"error": str(inner_ex), "raw_payload": str(payload)[:200]}
                    )

            if parsed_evt is None:
                used_generic_or_error = True
                parsed_evt = LogParserTool.parse_generic_wazuh(payload)

            if self._needs_llm_fallback(parsed_evt, payload, used_generic_or_error=used_generic_or_error):
                llm_evt, inj_detected, inj_reason = self._parse_unstructured_with_llm(
                    source, payload, incident_state=state
                )
                if llm_evt is not None:
                    parsed_evt = llm_evt
                    already_enriched = False
                else:
                    parsed_evt.raw_attributes["parsed_by"] = "deterministic_parser"
                    if inj_detected:
                        parsed_evt.raw_attributes["prompt_injection_detected"] = True
                        parsed_evt.raw_attributes["prompt_injection_reason"] = (
                            inj_reason or "Detected prompt injection"
                        )
            else:
                parsed_evt.raw_attributes.setdefault("parsed_by", "deterministic_parser")

            if not already_enriched:
                try:
                    self._enrich_event_command_and_iocs(parsed_evt)
                except Exception as ex:
                    logger.debug(f"[DataIngestionAgent] Bỏ qua lỗi hậu xử lý deobfuscation/IoC: {ex}")

            evt_sig = self._compute_event_signature(parsed_evt)
            if evt_sig not in seen_event_sigs:
                seen_event_sigs.add(evt_sig)
                state.parsed_events.append(parsed_evt)

            seen_raw_keys.add(raw_key)
            ingested_keys.append(raw_key)

        # Khử trùng lặp IoC trong threat_intel nếu đã tồn tại từ trước
        if state.threat_intel and getattr(state.threat_intel, "extracted_iocs", None):
            deduped_iocs = []
            seen_iocs = set()
            for ioc in state.threat_intel.extracted_iocs:
                key = (str(ioc.ioc_type or "").strip().upper(), str(ioc.value or "").strip().lower())
                if key[1] and key not in seen_iocs:
                    seen_iocs.add(key)
                    deduped_iocs.append(ioc)
            state.threat_intel.extracted_iocs = deduped_iocs
            state.threat_intel.indicators = deduped_iocs

        return state
