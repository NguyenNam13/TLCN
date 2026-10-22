# -*- coding: utf-8 -*-
"""
src/copilot/llm_provider.py
Module cung cấp kết nối LLM Hybrid đa tầng cho SOC AI Copilot.
Hỗ trợ:
1. OmniRouter / OpenRouter Gateway (API Key: sk-ef66a7d650e47f60-d829ca-68de4552)
2. Local Ollama LLM (http://localhost:11434/api/chat)
3. Tier 3 Deterministic CoT Engine: Rule-based Chain-of-Thought tổng hợp tự động từ IncidentState
   khi mất kết nối mạng hoặc API gặp sự cố timeout/lỗi.
"""

import os
import re
import json
import logging
from typing import Optional, Dict, Any, Union, Iterator, List
import requests

logger = logging.getLogger("HybridLLMProvider")

# Cấu hình mặc định
DEFAULT_OMNIROUTER_API_KEY = "sk-ef66a7d650e47f60-d829ca-68de4552"
DEFAULT_OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_OMNIROUTER_ENDPOINT = "http://localhost:20128/v1/chat/completions"
DEFAULT_MODEL = "AICODE"
FALLBACK_MODELS = [
    "AICODE",
    "meta-llama/llama-3.3-70b-instruct",
    "openai/gpt-4o-mini",
]
DEFAULT_OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_OLLAMA_MODEL = "llama3:latest"


class HybridLLMProvider:
    """Provider kết nối LLM thông minh hỗ trợ chuyển tầng linh hoạt (Hybrid Failover).
    
    Thứ tự ưu tiên xử lý:
    1. OmniRouter / OpenRouter API Cloud (Model tiên tiến, phản hồi nhanh).
    2. Local Ollama Server (Môi trường On-Premise/Offline nội bộ).
    3. Tier 3 Deterministic CoT Engine (Rule-based an toàn tuyệt đối, không phụ thuộc ngoại vi).
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        model: Optional[str] = None,
        ollama_url: Optional[str] = None,
        ollama_model: Optional[str] = None,
        provider_mode: str = "auto",  # "auto", "omnirouter", "openrouter", "ollama", "deterministic"
        timeout: float = 15.0,
        enable_fallback: bool = True,
    ):
        self.api_key = (
            api_key
            or os.getenv("OMNIROUTER_API_KEY")
            or os.getenv("OPENROUTER_API_KEY")
            or DEFAULT_OMNIROUTER_API_KEY
        )
        self.endpoint = (
            endpoint
            or os.getenv("OMNIROUTE_BASE_URL")
            or os.getenv("OMNIROUTER_BASE_URL")
            or (DEFAULT_OMNIROUTER_ENDPOINT if provider_mode in ("auto", "omnirouter") else DEFAULT_OPENROUTER_ENDPOINT)
        )
        self.model = model or os.getenv("COPILOT_MODEL") or os.getenv("OMNIROUTE_MODEL") or DEFAULT_MODEL
        self.ollama_url = ollama_url or os.getenv("OLLAMA_URL") or DEFAULT_OLLAMA_URL
        self.ollama_model = ollama_model or os.getenv("OLLAMA_MODEL") or DEFAULT_OLLAMA_MODEL
        self.provider_mode = provider_mode
        self.timeout = timeout
        self.enable_fallback = enable_fallback
        self.last_used_provider: Optional[str] = "omnirouter"
        self.last_error: Optional[str] = None

    @property
    def provider_type(self) -> str:
        """Trả về tên định danh của provider hiện tại."""
        return self.last_used_provider or self.provider_mode

    def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        stream: bool = False,
        incident_state: Optional[Any] = None,
    ) -> Union[str, Iterator[str]]:
        """Tạo phản hồi từ LLM hoặc Fallback Engine."""
        system_prompt = system_prompt or (
            "Bạn là Trợ lý SOC, chuyên gia an ninh mạng cấp cao phục vụ phân tích điều tra số "
            "(DFIR) và hỗ trợ chuyên viên SOC ra quyết định phản ứng sự cố."
        )

        # 1. Chế độ cưỡng bức Deterministic
        if self.provider_mode == "deterministic":
            self.last_used_provider = "deterministic"
            return self._deterministic_cot_generate(
                prompt=prompt,
                system_prompt=system_prompt,
                stream=stream,
                incident_state=incident_state,
            )

        # 2. Chế độ cưỡng bức Ollama
        if self.provider_mode == "ollama":
            try:
                self.last_used_provider = "ollama"
                return self._call_ollama(prompt, system_prompt, stream=stream)
            except Exception as e:
                logger.warning(f"Ollama provider failed: {e}")
                if self.enable_fallback:
                    self.last_used_provider = "deterministic"
                    return self._deterministic_cot_generate(
                        prompt, system_prompt, stream=stream, incident_state=incident_state
                    )
                raise

        # 3. Chế độ cưỡng bức hoặc tự động OpenRouter/OmniRouter
        if self.provider_mode in ("auto", "omnirouter", "openrouter"):
            try:
                self.last_used_provider = "omnirouter"
                self.last_error = None
                return self._call_openrouter(prompt, system_prompt, stream=stream)
            except Exception as e:
                self.last_error = f"OmniRouter error: {e}"
                logger.warning(f"OpenRouter/OmniRouter call failed: {e}")
                if not self.enable_fallback:
                    raise

                # Thử chuyển tiếp sang Local Ollama
                try:
                    logger.info("Falling back to Local Ollama...")
                    self.last_used_provider = "ollama"
                    return self._call_ollama(prompt, system_prompt, stream=stream)
                except Exception as ollama_err:
                    self.last_error = f"OmniRouter: {e} | Ollama: {ollama_err}"
                    logger.warning(f"Local Ollama also failed: {ollama_err}")

                # Chuyển về Tier 3 Deterministic CoT Engine
                logger.info("Falling back to Tier 3 Deterministic CoT Engine...")
                self.last_used_provider = "deterministic"
                return self._deterministic_cot_generate(
                    prompt, system_prompt, stream=stream, incident_state=incident_state
                )

        # Mặc định fallback
        self.last_used_provider = "deterministic"
        return self._deterministic_cot_generate(
            prompt, system_prompt, stream=stream, incident_state=incident_state
        )

    def stream_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        incident_state: Optional[Any] = None,
    ) -> Iterator[str]:
        """Phương thức tiện ích để stream phản hồi từng phần (Token Chunk Generator)."""
        res = self.generate_response(
            prompt=prompt,
            system_prompt=system_prompt,
            stream=True,
            incident_state=incident_state,
        )
        if isinstance(res, str):
            # Nếu trả về chuỗi thay vì generator, tách nhỏ thành generator giả lập stream
            yield res
        else:
            yield from res

    # =========================================================================
    # GIAO TIẾP OPENROUTER / OMNIROUTER REST API
    # =========================================================================
    def _call_openrouter(
        self,
        prompt: str,
        system_prompt: str,
        stream: bool = False,
    ) -> Union[str, Iterator[str]]:
        """Gửi yêu cầu Chat Completions chuẩn OpenAI qua OpenRouter/OmniRouter."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://tlcn-soc.local",
            "X-Title": "TLCN Tro Ly SOC",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "stream": stream,
            "temperature": 0.2,
            "max_tokens": 1500,
        }

        response = requests.post(
            self.endpoint,
            headers=headers,
            json=payload,
            timeout=self.timeout,
            stream=stream,
        )

        if response.status_code != 200:
            raise requests.RequestException(
                f"OmniRouter API returned error code {response.status_code}: {response.text}"
            )

        if not stream:
            data = response.json()
            choices = data.get("choices", [])
            if not choices:
                raise ValueError("OmniRouter response missing 'choices'")
            return choices[0].get("message", {}).get("content", "")

        # Xử lý SSE Streaming
        return self._stream_sse_chunks(response)

    def _stream_sse_chunks(self, response: requests.Response) -> Iterator[str]:
        """Trích xuất delta content từ luồng Server-Sent Events (SSE)."""
        try:
            for line in response.iter_lines(decode_unicode=True):
                if not line:
                    continue
                if isinstance(line, bytes):
                    line = line.decode("utf-8", errors="ignore")
                line = line.strip()
                if line.startswith("data:"):
                    raw_data = line[5:].strip()
                    if raw_data == "[DONE]":
                        break
                    try:
                        chunk_json = json.loads(raw_data)
                        delta = chunk_json.get("choices", [{}])[0].get("delta", {})
                        content = delta.get("content")
                        if content:
                            yield content
                    except json.JSONDecodeError:
                        continue
        finally:
            response.close()

    # =========================================================================
    # GIAO TIẾP LOCAL OLLAMA REST API
    # =========================================================================
    def _call_ollama(
        self,
        prompt: str,
        system_prompt: str,
        stream: bool = False,
    ) -> Union[str, Iterator[str]]:
        """Gửi yêu cầu Chat Completion tới Local Ollama Instance."""
        payload = {
            "model": self.ollama_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "stream": stream,
        }

        response = requests.post(
            self.ollama_url,
            json=payload,
            timeout=self.timeout,
            stream=stream,
        )

        if response.status_code != 200:
            raise requests.RequestException(
                f"Ollama API returned error {response.status_code}: {response.text}"
            )

        if not stream:
            data = response.json()
            return data.get("message", {}).get("content", "")

        return self._stream_ollama_ndjson(response)

    def _stream_ollama_ndjson(self, response: requests.Response) -> Iterator[str]:
        """Trích xuất message content từ newline-delimited JSON stream của Ollama."""
        try:
            for line in response.iter_lines(decode_unicode=True):
                if not line:
                    continue
                if isinstance(line, bytes):
                    line = line.decode("utf-8", errors="ignore")
                line = line.strip()
                try:
                    item = json.loads(line)
                    content = item.get("message", {}).get("content", "")
                    if content:
                        yield content
                    if item.get("done", False):
                        break
                except json.JSONDecodeError:
                    continue
        finally:
            response.close()

    # =========================================================================
    # TIER 3: DETERMINISTIC CHAIN-OF-THOUGHT (CoT) ENGINE
    # =========================================================================
    def _deterministic_cot_generate(
        self,
        prompt: str,
        system_prompt: str,
        stream: bool = False,
        incident_state: Optional[Any] = None,
    ) -> Union[str, Iterator[str]]:
        """Tự động suy luận và sinh báo cáo CoT chuẩn quy trình SOC từ IncidentState."""
        text = self._build_deterministic_text(prompt, incident_state)

        if not stream:
            return text

        # Trả về iterator chia theo từ để giả lập stream mượt mà
        def _chunk_generator():
            words = text.split(" ")
            for i, word in enumerate(words):
                yield word + (" " if i < len(words) - 1 else "")

        return _chunk_generator()

    def _build_deterministic_text(self, prompt: str, state: Optional[Any]) -> str:
        """Xây dựng nội dung phản hồi suy luận logic không cần LLM."""
        prompt_lower = prompt.lower()
        if "yêu cầu của chuyên viên soc" in prompt_lower:
            user_part = prompt_lower.split("yêu cầu của chuyên viên soc")[-1]
        else:
            user_part = prompt_lower

        is_ioc = "(lookup_ioc)" in prompt_lower or any(k in user_part for k in ["ioc", "ip", "hash", "domain", "virustotal", "cti", "độc hại"])
        is_summary = "(executive_summary)" in prompt_lower or any(k in user_part for k in ["tóm tắt", "summary", "tổng quan", "executive", "báo cáo"])
        is_rca = "(explain_rca)" in prompt_lower or any(k in user_part for k in ["rca", "nguyên nhân", "root cause", "tiến trình", "process tree", "tại sao"])
        is_action = any(k in user_part for k in ["hành động", "action", "phản ứng", "containment"])

        # 1. Thu thập thông tin từ IncidentState nếu có
        inc_id = getattr(state, "incident_id", "INC-UNKNOWN") if state else "INC-LOCAL"
        status = getattr(state, "status", None)
        status_val = status.value if hasattr(status, "value") else str(status or "UNKNOWN")
        attack_type = getattr(state, "attack_type", None) or "Chưa phân loại"

        triage = getattr(state, "triage_result", None)
        severity = getattr(triage, "severity", None)
        severity_val = severity.value if hasattr(severity, "value") else str(severity or "Chưa phân loại")
        triage_summary = getattr(triage, "summary", "Chưa có phát hiện bất thường") if triage else "Chưa có phát hiện bất thường"

        rca = getattr(state, "rca_result", None)
        threat_intel = getattr(state, "threat_intel", None)
        actions = getattr(state, "recommended_actions", []) or []

        # Kiểm tra nếu ở Live mode nhưng chưa nhận được bất kỳ log nào
        has_logs = bool(getattr(state, "raw_logs", None) or getattr(state, "parsed_events", None))
        is_live_empty = (not has_logs) and ("LIVE" in str(inc_id).upper() or status_val in ("IncidentStatus.NEW", "NEW"))

        if is_live_empty and not (triage or rca or threat_intel):
            return (
                f"### [Deterministic CoT] Trạng thái Trực tiếp Wazuh OVA: Chưa nhận được Cảnh báo\n\n"
                f"- **Mã phiên sự cố:** `{inc_id}`\n"
                f"- **Trạng thái:** `Đang trực tuyến (Live Webhook Mode)`\n"
                f"- **Nhật ký nhận được:** `0 log`\n\n"
                f"ℹ️ **Hệ thống đang túc trực tại endpoint `:8000/api/v1/wazuh-alert` nhưng máy chủ Wazuh OVA (172.16.65.143) chưa gửi bất kỳ cảnh báo nào sang.**\n\n"
                f"**Cách thực hiện tiếp theo:**\n"
                f"1. Tạo sự kiện an ninh trên Agent Wazuh để Wazuh Manager quét và tự động đẩy cảnh báo qua Webhook.\n"
                f"2. Hoặc nếu muốn kiểm thử quy trình điều tra ngay, hãy chọn **'📁 2. Kịch bản kiểm nghiệm mẫu (Offline Replay Datasets)'** ở menu bên trái."
            )

        # 2. Xử lý trường hợp tra cứu IoC / Tình báo CTI
        if is_ioc:
            iocs = (getattr(threat_intel, "extracted_iocs", None) or getattr(threat_intel, "indicators", [])) if threat_intel else []
            if iocs:
                ioc_lines = []
                for item in iocs[:5]:
                    ioc_type = getattr(item, "ioc_type", "IoC")
                    ioc_type_val = ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type)
                    val = getattr(item, "value", "")
                    score = getattr(item, "reputation_score", 85)
                    mal = "ĐỘC HẠI" if getattr(item, "is_malicious", True) else "Bình thường"
                    ioc_lines.append(f"- **[{ioc_type_val}]** `{val}` | Điểm độc hại: **{score}/100** ({mal})")
                return (
                    f"### [Deterministic CoT] Tra cứu Chỉ số Tình báo Mối đe dọa (CTI & IoC)\n\n"
                    f"Hệ thống đã thu thập và đối soát các chỉ số IoC của sự cố **{inc_id}**:\n\n"
                    + "\n".join(ioc_lines)
                    + "\n\n**Khuyến nghị phản ứng:** Chặn lập tức các IP/Domain trên Gateway Firewall và phong tỏa Hash trên toàn bộ Endpoint EDR."
                )
            else:
                return (
                    f"### [Deterministic CoT] Tra cứu Chỉ số Tình báo Mối đe dọa (CTI & IoC) - {inc_id}\n\n"
                    f"ℹ️ **Không phát hiện IoC độc hại:** Sự cố hiện tại chưa ghi nhận địa chỉ IP, Domain hay Hash tệp độc hại nào cần xử lý."
                )

        # 3. Xử lý trường hợp hỏi Tóm tắt sự cố
        if is_summary:
            if not triage:
                return (
                    f"### [Deterministic CoT] Tóm tắt Sự cố ({inc_id})\n\n"
                    f"- **Mức độ nghiêm trọng:** `Chưa phân loại`\n"
                    f"- **Trạng thái xử lý:** `{status_val}`\n"
                    f"- **Tình trạng:** Sự cố mới được tiếp nhận và chưa chạy qua bước phân loại sơ bộ (Triage Agent).\n\n"
                    f"**Đề xuất hành động:** Vui lòng nhấn **'🚀 Chạy Hết'** để hệ thống Multi-Agent thực thi phân tích."
                )

            pending_count = len([a for a in actions if getattr(a, "is_approved", None) is None])
            approved_count = len([a for a in actions if getattr(a, "is_approved", False) is True])

            return (
                f"### [Deterministic CoT] Tóm tắt Sự cố ({inc_id})\n\n"
                f"- **Mức độ nghiêm trọng:** `{severity_val}`\n"
                f"- **Trạng thái xử lý:** `{status_val}`\n"
                f"- **Loại hình tấn công:** {attack_type}\n"
                f"- **Tóm tắt phát hiện:** {triage_summary}\n\n"
                f"**Tình trạng hành động ứng phó:**\n"
                f"- Đã duyệt: **{approved_count}** hành động\n"
                f"- Đang chờ thẩm định HITL: **{pending_count}** hành động\n\n"
                f"**Đề xuất hành động tiếp theo:** Chuyên viên SOC cần hoàn tất thẩm định các hành động ngăn chặn để đưa sự cố về trạng thái `CONTAINED`."
            )

        # 4. Xử lý trường hợp hỏi về Root Cause / Cây tiến trình / RCA
        if is_rca:
            if not rca:
                return (
                    f"### [Deterministic CoT] Phân tích Nguyên nhân Gốc rễ (RCA) - {inc_id}\n\n"
                    f"⚠️ **Chưa có dữ liệu RCA:** Sự cố `{inc_id}` hiện chưa hoàn tất phân tích nguyên nhân gốc rễ hoặc chưa có log tiến trình Sysmon.\n\n"
                    f"**Chỉ dẫn:** Vui lòng nhấn nút **'🚀 Chạy Hết'** hoặc **'⏭️ Từng bước'** trên thanh thao tác bên trái để kích hoạt các Agent phân tích cây tiến trình và chuỗi tấn công."
                )

            initial_vector = getattr(rca, "initial_access_vector", "Chưa xác định")
            rca_summary = getattr(rca, "root_cause_summary", "Chưa có tóm tắt nguyên nhân gốc rễ")
            tactics = getattr(rca, "mitre_tactics", [])
            process_tree = getattr(rca, "process_tree", []) or []

            tree_str = ""
            if process_tree:
                tree_str = "\n".join([
                    f"  - [{p.process_id}] {p.process_name} (Lệnh: `{p.command_line[:60]}...`)"
                    f"{' [MÃ ĐỘC GỐC]' if getattr(p, 'is_malicious_origin', False) else ''}"
                    for p in process_tree[:5]
                ])
            else:
                tree_str = "  - Không phát hiện tiến trình độc hại nào trong cây tiến trình."

            return (
                f"### [Deterministic CoT] Phân tích Nguyên nhân Gốc rễ (RCA) - {inc_id}\n\n"
                f"**1. Phương thức xâm nhập ban đầu (Initial Access):**\n"
                f"- Nhận diện: **{initial_vector}**\n\n"
                f"**2. Cây tiến trình điều tra (Process Lineage):**\n"
                f"{tree_str}\n\n"
                f"**3. Suy luận kỹ thuật (Root Cause Summary):**\n"
                f"{rca_summary}\n\n"
                f"**4. Chiến thuật MITRE ATT&CK liên quan:**\n"
                f"- {', '.join(tactics) if isinstance(tactics, list) and tactics else 'Chưa có'}\n\n"
                f"**5. Đánh giá chuyên viên:** Tiến trình gốc cần được giám sát và xử lý theo quy trình ứng phó sự cố."
            )

        # 5. Phản hồi thông tin hành động / kế hoạch ứng phó
        if is_action:
            if actions:
                action_items = []
                for act in actions:
                    act_id = getattr(act, "action_id", "ACT-XXX")
                    act_type = getattr(act, "action_type", "")
                    act_type_val = act_type.value if hasattr(act_type, "value") else str(act_type)
                    target = getattr(act, "target", "")
                    appr = getattr(act, "is_approved", None)
                    status_badge = "ĐÃ DUYỆT" if appr is True else ("TỪ CHỐI" if appr is False else "CHỜ DUYỆT")
                    action_items.append(f"- **{act_id}**: `{act_type_val}` đối tượng `{target}` -> [{status_badge}]")
                action_str = "\n".join(action_items)
            else:
                action_str = "- Không có hành động nào được ghi nhận."

            return (
                f"### [Deterministic CoT] Danh mục Hành động Ứng phó ({inc_id})\n\n"
                f"{action_str}\n\n"
                f"Chuyên viên có thể nhập: `duyệt [Mã Action]` hoặc `duyệt tất cả` để Trợ lý SOC thực thi."
            )

        # 6. Mặc định phản hồi tổng quan phân tích SOC
        if not triage:
            return (
                f"### [Deterministic CoT] Tổng quan Sự cố - {inc_id}\n\n"
                f"- **Trạng thái:** `{status_val}`\n"
                f"- **Tình trạng:** Sự cố mới tiếp nhận, chưa có kết quả phân loại từ các Agent.\n"
                f"- **Chỉ dẫn:** Nhấn **'🚀 Chạy Hết'** trên menu bên trái để kích hoạt tiến trình điều tra tự động."
            )

        return (
            f"### [Deterministic CoT] Phân tích Hỗ trợ Điều tra - {inc_id}\n\n"
            f"- **Trạng thái:** `{status_val}` | **Mức độ:** `{severity_val}`\n"
            f"- **Tóm lược:** {triage_summary}\n"
            f"- **Chỉ dẫn:** Chuyên viên có thể hỏi sâu về:\n"
            f"  1. *Nguyên nhân gốc rễ và cây tiến trình (RCA)*\n"
            f"  2. *Danh mục IoC độc hại và độ nguy hiểm (CTI)*\n"
            f"  3. *Tóm tắt sự cố*\n"
            f"  4. *Phê duyệt hoặc từ chối hành động ứng phó (HITL Approve/Reject)*"
        )
