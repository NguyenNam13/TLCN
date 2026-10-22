# -*- coding: utf-8 -*-
"""
src/copilot/engine.py
Module lõi điều khiển Trợ lý ảo SOC AI Copilot Engine.
Chức năng chính:
1. serialize_incident_context(state): nén context toàn diện về sự cố < 800 tokens.
2. process_message(user_message, state, chat_history): bóc tách intent của chuyên viên SOC
   (EXPLAIN_RCA, LOOKUP_IOC, EXECUTIVE_SUMMARY, APPROVE_ACTION, REJECT_ACTION, GENERAL_QUERY).
3. Tích hợp trực tiếp với HITLManager để phê duyệt hoặc từ chối hành động ứng phó trong state,
   cập nhật is_approved và ghi vết chuyển đổi trạng thái (state.record_transition).
"""

import re
import logging
from enum import Enum
from typing import Optional, List, Dict, Any, Union, Iterator
from pydantic import BaseModel, Field

from src.core.schemas import IncidentStatus, RecommendedAction
from src.core.state import IncidentState
from src.core.hitl_manager import HITLManager, HITLDecision, DecisionType
from src.copilot.llm_provider import HybridLLMProvider

logger = logging.getLogger("SOCCopilotEngine")


class CopilotIntent(str, Enum):
    """Danh mục Ý định (Intent) của chuyên viên SOC khi tương tác với Copilot."""
    EXPLAIN_RCA = "EXPLAIN_RCA"
    LOOKUP_IOC = "LOOKUP_IOC"
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"
    APPROVE_ACTION = "APPROVE_ACTION"
    REJECT_ACTION = "REJECT_ACTION"
    GENERAL_QUERY = "GENERAL_QUERY"


class CopilotResponse(BaseModel):
    """Mô hình phản hồi chuẩn từ SOCCopilotEngine."""
    intent: str = Field(..., description="Mã định danh intent nhận diện được")
    response: str = Field(..., description="Nội dung văn bản phản hồi cho chuyên viên")
    state: IncidentState = Field(..., description="Trạng thái sự cố đã được đồng bộ")
    action_taken: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Chi tiết quyết định HITL vừa thực thi nếu có"
    )
    raw_stream: Optional[Any] = Field(
        default=None,
        description="Generator stream tokens nếu gọi ở chế độ streaming"
    )

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    @property
    def response_text(self) -> str:
        return self.response

    @property
    def executed_action(self) -> Optional[Dict[str, Any]]:
        return self.action_taken


class SOCCopilotEngine:
    """Bộ xử lý trung tâm SOC AI Copilot Engine."""

    def __init__(
        self,
        llm_provider: Optional[HybridLLMProvider] = None,
        hitl_manager: Optional[HITLManager] = None,
        analyst_id: str = "soc_assistant",
    ):
        self.llm_provider = llm_provider or HybridLLMProvider()
        self.hitl_manager = hitl_manager or HITLManager(default_analyst_id=analyst_id)
        self.analyst_id = analyst_id

    @property
    def provider(self) -> HybridLLMProvider:
        """Thuộc tính tương thích ngược cho giao diện Dashboard và API ngoài."""
        return self.llm_provider

    @provider.setter
    def provider(self, value: HybridLLMProvider) -> None:
        self.llm_provider = value

    # =========================================================================
    # 1. NÉN VÀ TUẦN TỰ HÓA NGỮ CẢNH SỰ CỐ (< 800 TOKENS)
    # =========================================================================
    def serialize_incident_context(self, state: IncidentState) -> str:
        """Nén thông tin IncidentState thành chuỗi súc tích chuẩn kỹ thuật < 800 tokens.
        
        Quy tắc nén:
        - Giữ lại các trường trọng yếu: Incident ID, Severity, Attack Type, Status.
        - Trích xuất Initial Access Vector và Root Cause Process ngắn gọn.
        - Giữ tối đa 5 IoC độc hại nhất kèm Reputation Score.
        - Tóm tắt danh sách Recommended Actions kèm Action ID và trạng thái duyệt.
        - Giới hạn độ dài an toàn tối đa khoảng 2500 - 2800 ký tự (~600-700 tokens).
        """
        lines = []
        lines.append(f"=== INCIDENT CONTEXT: {state.incident_id} ===")
        lines.append(f"- Status: {state.status.value}")
        if state.attack_type:
            lines.append(f"- Attack Type: {state.attack_type}")

        # Triage summary
        if state.triage_result:
            sev = state.triage_result.severity.value if hasattr(state.triage_result.severity, "value") else str(state.triage_result.severity)
            lines.append(f"- Severity: {sev} (Confidence: {state.triage_result.confidence_score:.2f})")
            if state.triage_result.summary:
                clean_sum = state.triage_result.summary.strip().replace("\n", " ")[:200]
                lines.append(f"- Triage Summary: {clean_sum}")

        # RCA summary
        if state.rca_result:
            lines.append(f"- Initial Access: {state.rca_result.initial_access_vector}")
            if state.rca_result.mitre_tactics:
                tactics = ", ".join(state.rca_result.mitre_tactics[:3])
                lines.append(f"- MITRE Tactics: {tactics}")

            # Top malicious process
            malicious_nodes = [p for p in state.rca_result.process_tree if getattr(p, "is_malicious_origin", False)]
            if malicious_nodes:
                p = malicious_nodes[0]
                lines.append(f"- Root Process: [{p.process_id}] {p.process_name} (Cmd: {p.command_line[:80]})")
            elif state.rca_result.process_tree:
                p = state.rca_result.process_tree[0]
                lines.append(f"- Key Process: [{p.process_id}] {p.process_name}")

            if state.rca_result.root_cause_summary:
                clean_rca = state.rca_result.root_cause_summary.strip().replace("\n", " ")[:250]
                lines.append(f"- RCA Summary: {clean_rca}")

        # Top IoCs
        raw_iocs = (getattr(state.threat_intel, "extracted_iocs", None) or getattr(state.threat_intel, "indicators", None)) if state.threat_intel else None
        if raw_iocs:
            mal_iocs = [i for i in raw_iocs if getattr(i, "is_malicious", False)]
            target_iocs = mal_iocs if mal_iocs else raw_iocs
            ioc_strs = []
            for ioc in target_iocs[:4]:
                ioc_type = ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else str(ioc.ioc_type)
                ioc_strs.append(f"{ioc_type}:{ioc.value}(rep:{ioc.reputation_score})")
            lines.append(f"- Top IoCs: {', '.join(ioc_strs)}")

        # Recommended Actions
        if state.recommended_actions:
            act_strs = []
            for act in state.recommended_actions[:4]:
                act_id = act.action_id or "ACT-???"
                act_type = act.action_type.value if hasattr(act.action_type, "value") else str(act.action_type)
                appr_str = "Approved" if act.is_approved is True else ("Rejected" if act.is_approved is False else "Pending")
                act_strs.append(f"[{act_id}] {act_type}->{act.target} ({appr_str})")
            lines.append(f"- Actions: {'; '.join(act_strs)}")

        context_text = "\n".join(lines)

        # Chặn ngưỡng cứng < 2800 ký tự để đảm bảo < 800 tokens
        if len(context_text) > 2800:
            context_text = context_text[:2750] + "\n... [Context truncated to < 800 tokens]"

        return context_text

    # =========================================================================
    # 2. PHÂN LOẠI Ý ĐỊNH (INTENT CLASSIFICATION)
    # =========================================================================
    def classify_intent(self, user_message: str) -> CopilotIntent:
        """Nhận diện ý định của câu lệnh từ chuyên viên SOC bằng biểu thức chính quy (NLU Rule Engine)."""
        msg = user_message.strip().lower()

        # 1. Từ chối hành động (ưu tiên kiểm tra trước duyệt để tránh phủ định bị bắt nhầm)
        if re.search(r"\b(từ chối|reject|bác bỏ|không duyệt|hủy bỏ|deny)\b", msg):
            return CopilotIntent.REJECT_ACTION

        # 2. Phê duyệt hành động
        if re.search(r"\b(duyệt|approve|chấp thuận|đồng ý|accept|thực thi)\b", msg):
            return CopilotIntent.APPROVE_ACTION

        # 3. Giải thích RCA / Cây tiến trình / Nguyên nhân gốc rễ
        if re.search(
            r"\b(rca|nguyên nhân|root cause|tiến trình|process tree|cây tiến trình|lineage|chuỗi tấn công|tại sao|nguồn gốc|initial access|timeline)\b",
            msg,
        ):
            return CopilotIntent.EXPLAIN_RCA

        # 4. Tra cứu IoC / Tình báo CTI
        if re.search(
            r"\b(ioc|ip|domain|hash|sha256|md5|virustotal|abuseipdb|reputation|chỉ số|độc hại)\b",
            msg,
        ):
            return CopilotIntent.LOOKUP_IOC

        # 5. Tóm lược điều hành (Executive Summary)
        if re.search(
            r"\b(tóm tắt|summary|tổng quan|executive|báo cáo|tình hình|overview)\b",
            msg,
        ):
            return CopilotIntent.EXECUTIVE_SUMMARY

        # 6. Mặc định hỏi đáp thông thường
        return CopilotIntent.GENERAL_QUERY

    # =========================================================================
    # 3. TRÍCH XUẤT ACTION ID TỪ TIN NHẮN
    # =========================================================================
    def _extract_action_id(self, message: str) -> Optional[str]:
        """Trích xuất mã Action ID dạng ACT-XXX hoặc số thứ tự."""
        match = re.search(r"\bACT-[A-Za-z0-9]+\b", message, re.IGNORECASE)
        if match:
            return match.group(0).upper()

        # Bắt trường hợp người dùng gõ số: "duyệt 1", "duyệt action 1"
        num_match = re.search(r"\b(?:action|hành động)?\s*#?([0-9]+)\b", message, re.IGNORECASE)
        if num_match:
            idx = int(num_match.group(1))
            return f"ACT-{idx:03d}"

        return None

    # =========================================================================
    # 4. XỬ LÝ TIN NHẮN CHÍNH (PROCESS MESSAGE)
    # =========================================================================
    def process_message(
        self,
        user_message: str,
        state: IncidentState,
        chat_history: Optional[List[Dict[str, str]]] = None,
        stream: bool = False,
    ) -> CopilotResponse:
        """Tiếp nhận tin nhắn người dùng, phân tích intent, điều khiển HITL hoặc gọi LLM."""
        intent = self.classify_intent(user_message)
        logger.info(f"Classified intent: {intent.value} for message: '{user_message}'")

        # Đảm bảo các actions trong state đều có action_id
        for idx, act in enumerate(state.recommended_actions):
            if not act.action_id:
                act.action_id = f"ACT-{idx+1:03d}"

        # ---------------------------------------------------------------------
        # XỬ LÝ LỆNH HITL: APPROVE_ACTION
        # ---------------------------------------------------------------------
        if intent == CopilotIntent.APPROVE_ACTION:
            target_id = self._extract_action_id(user_message)
            is_all = any(k in user_message.lower() for k in ["tất cả", "all", "toàn bộ"])

            if is_all or (not target_id and len(self.hitl_manager.get_pending_actions(state)) > 0):
                # Phê duyệt toàn bộ
                pending_actions = self.hitl_manager.get_pending_actions(state)
                updated_state = self.hitl_manager.approve_all(
                    state,
                    analyst_id=self.analyst_id,
                    notes=f"Trợ lý SOC: {user_message}",
                )
                approved_ids = [a.action_id for a in pending_actions]
                reply_text = (
                    f"✅ **Đã phê duyệt toàn bộ ({len(approved_ids)}) hành động ứng phó:**\n"
                    + "\n".join([f"- `{aid}`: Đã chuyển sang trạng thái **Approved**" for aid in approved_ids])
                    + f"\n\nSự cố hiện đã chuyển sang trạng thái: **`{updated_state.status.value}`**."
                )
                action_info = {"type": "APPROVE_ALL", "action_ids": approved_ids}
                return CopilotResponse(
                    intent=intent.value,
                    response=reply_text,
                    state=updated_state,
                    action_taken=action_info,
                )

            elif target_id:
                # Phê duyệt hành động cụ thể
                decision = HITLDecision(
                    decision_type=DecisionType.APPROVE,
                    action_id=target_id,
                    analyst_id=self.analyst_id,
                    feedback_notes=f"Trợ lý SOC phê duyệt: {user_message}",
                )
                try:
                    updated_state = self.hitl_manager.submit_decision(state, decision)
                    reply_text = (
                        f"✅ **Đã phê duyệt thành công hành động `{target_id}`**.\n\n"
                        f"- Trạng thái: `Approved = True`\n"
                        f"- Ghi chú vết: Đã lưu vào State Transition History.\n"
                        f"- Các hành động còn chờ duyệt: {len(self.hitl_manager.get_pending_actions(updated_state))}."
                    )
                    action_info = {"type": "APPROVE", "action_id": target_id}
                    return CopilotResponse(
                        intent=intent.value,
                        response=reply_text,
                        state=updated_state,
                        action_taken=action_info,
                    )
                except ValueError as err:
                    reply_text = f"⚠️ Lỗi phê duyệt: {err}"
                    return CopilotResponse(
                        intent=intent.value,
                        response=reply_text,
                        state=state,
                        action_taken={"error": str(err)},
                    )

            else:
                reply_text = "ℹ️ Hiện tại không có hành động nào đang chờ phê duyệt trong sự cố này."
                return CopilotResponse(
                    intent=intent.value,
                    response=reply_text,
                    state=state,
                )

        # ---------------------------------------------------------------------
        # XỬ LÝ LỆNH HITL: REJECT_ACTION
        # ---------------------------------------------------------------------
        if intent == CopilotIntent.REJECT_ACTION:
            target_id = self._extract_action_id(user_message)
            is_all = any(k in user_message.lower() for k in ["tất cả", "all", "toàn bộ"])

            if is_all:
                pending_actions = self.hitl_manager.get_pending_actions(state)
                updated_state = self.hitl_manager.reject_all(
                    state,
                    analyst_id=self.analyst_id,
                    notes=f"Trợ lý SOC từ chối: {user_message}",
                )
                rejected_ids = [a.action_id for a in pending_actions]
                reply_text = (
                    f"⛔ **Đã từ chối toàn bộ ({len(rejected_ids)}) hành động ứng phó:**\n"
                    + "\n".join([f"- `{aid}`: Đã chuyển sang trạng thái **Rejected**" for aid in rejected_ids])
                    + f"\n\nSự cố duy trì trạng thái: **`{updated_state.status.value}`** để tiếp tục điều tra."
                )
                action_info = {"type": "REJECT_ALL", "action_ids": rejected_ids}
                return CopilotResponse(
                    intent=intent.value,
                    response=reply_text,
                    state=updated_state,
                    action_taken=action_info,
                )

            elif target_id:
                decision = HITLDecision(
                    decision_type=DecisionType.REJECT,
                    action_id=target_id,
                    analyst_id=self.analyst_id,
                    feedback_notes=f"Trợ lý SOC từ chối: {user_message}",
                )
                try:
                    updated_state = self.hitl_manager.submit_decision(state, decision)
                    reply_text = (
                        f"⛔ **Đã từ chối hành động `{target_id}`**.\n\n"
                        f"- Trạng thái: `Approved = False` (Bác bỏ thực thi)\n"
                        f"- Ghi chú vết: Đã lưu vào State Transition History."
                    )
                    action_info = {"type": "REJECT", "action_id": target_id}
                    return CopilotResponse(
                        intent=intent.value,
                        response=reply_text,
                        state=updated_state,
                        action_taken=action_info,
                    )
                except ValueError as err:
                    reply_text = f"⚠️ Lỗi từ chối hành động: {err}"
                    return CopilotResponse(
                        intent=intent.value,
                        response=reply_text,
                        state=state,
                        action_taken={"error": str(err)},
                    )

            else:
                reply_text = "⚠️ Vui lòng chỉ định rõ mã hành động cần từ chối (Ví dụ: `từ chối ACT-001` hoặc `từ chối tất cả`)."
                return CopilotResponse(
                    intent=intent.value,
                    response=reply_text,
                    state=state,
                )

        # ---------------------------------------------------------------------
        # XỬ LÝ CÁC INTENT ĐIỀU TRA: EXPLAIN_RCA, LOOKUP_IOC, EXECUTIVE_SUMMARY, GENERAL_QUERY
        # ---------------------------------------------------------------------
        context_str = self.serialize_incident_context(state)

        # Xây dựng System Prompt chuyên sâu
        system_prompt = (
            "Bạn là Trợ lý SOC, chuyên gia an ninh mạng thông minh hỗ trợ Trung tâm điều hành an ninh SOC. "
            "Nhiệm vụ của bạn là giải đáp chi tiết, chính xác, có cơ sở kỹ thuật về sự cố an ninh đang diễn ra, "
            "dựa trên dữ liệu ngữ cảnh IncidentContext được cung cấp.\n"
            "Hãy trả lời bằng tiếng Việt chuyên ngành an ninh thông tin, logic rõ ràng, súc tích và có tính định hướng hành động."
        )

        # Ghép lịch sử hội thoại nếu có
        history_context = ""
        if chat_history:
            recent_turns = chat_history[-4:]
            formatted_turns = []
            for turn in recent_turns:
                role = turn.get("role", "user")
                content = turn.get("content", "")
                formatted_turns.append(f"{role.upper()}: {content}")
            history_context = "\nLịch sử trao đổi gần nhất:\n" + "\n".join(formatted_turns) + "\n"

        prompt = (
            f"{context_str}\n"
            f"{history_context}\n"
            f"Yêu cầu của Chuyên viên SOC ({intent.value}):\n"
            f"\"{user_message}\"\n\n"
            f"Hãy phân tích và trả lời theo ngữ cảnh trên:"
        )

        if stream:
            stream_gen = self.llm_provider.stream_response(
                prompt=prompt,
                system_prompt=system_prompt,
                incident_state=state,
            )
            return CopilotResponse(
                intent=intent.value,
                response="[Streaming...]",
                state=state,
                raw_stream=stream_gen,
            )
        else:
            response_text = self.llm_provider.generate_response(
                prompt=prompt,
                system_prompt=system_prompt,
                stream=False,
                incident_state=state,
            )
            return CopilotResponse(
                intent=intent.value,
                response=response_text,
                state=state,
            )
