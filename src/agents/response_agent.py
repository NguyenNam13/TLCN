# -*- coding: utf-8 -*-
"""
src/agents/response_agent.py
Response Recommendation Agent chuyên trách đề xuất kế hoạch phản ứng sự cố an ninh mạng.
Tuân thủ tiêu chuẩn NIST SP 800-61 (Computer Security Incident Handling Guide):
1. Khẩn cấp / Ngăn chặn tức thì (Containment - Priority 1):
   - ISOLATE_HOST: Cô lập máy trạm bị nhiễm mã độc khỏi mạng nội bộ.
   - BLOCK_IP: Chặn IP máy chủ điều khiển C2 hoặc IP tấn công bên ngoài trên Firewall/Proxy.
   - KILL_PROCESS: Tiêu diệt tiến trình độc hại đang chạy trên endpoint.
2. Xử lý tài khoản / Danh tính (Eradication - Priority 2):
   - REVOKE_USER: Thu hồi toàn bộ phiên đăng nhập của người dùng bị lộ lọt.
   - RESET_PASSWORD: Buộc đổi mật khẩu và tái thiết lập xác thực đa yếu tố (MFA).
3. Triệt tiêu / Khôi phục hệ thống (Recovery - Priority 3-4):
   - PATCH_SYSTEM: Vá lỗ hổng, cập nhật bản vá bảo mật và quét toàn diện hệ thống.
4. Wazuh Active Response:
   - Tích hợp WazuhClientTool thực thi các script phản ứng tự động trên agent:
     `firewall-drop`, `host-isolate`, `kill-process`.
5. Quản lý cờ phê duyệt chuyên viên (Human-In-The-Loop - HITL):
   - Các hành động rủi ro cao (ISOLATE_HOST, BLOCK_IP, WAZUH_ACTIVE_RESPONSE, RESET_PASSWORD)
     bắt buộc yêu cầu phê duyệt (require_human_approval = True).
   - Các hành động rủi ro thấp (KILL_PROCESS, REVOKE_USER, PATCH_SYSTEM) có thể tự động phê duyệt
     nếu được cấu hình (auto_approve_low_risk = True).
"""

import ipaddress
import logging
from typing import List, Dict, Any, Optional, Set, Tuple

from src.core.schemas import (
    ActionType,
    RecommendedAction,
    IncidentStatus,
    IncidentPhase,
)
from src.core.state import IncidentState
from src.agents.prompts import RESPONSE_AGENT_SYSTEM_PROMPT
from src.tools.playbooks import ResponsePlaybooks
from src.tools.wazuh_client import WazuhClientTool

try:
    from src.tools.rag_knowledge_base import RAGKnowledgeBaseTool
except Exception:
    RAGKnowledgeBaseTool = None

logger = logging.getLogger("ResponseAgent")


class ResponseAgent:
    """
    Response Recommendation Agent đóng vai trò Chỉ huy ứng phó sự cố (Incident Commander).
    Xây dựng kế hoạch ngăn chặn, triệt tiêu và khôi phục dựa trên dữ liệu điều tra
    từ Triage, Threat Intelligence và Root Cause Analysis (RCA).
    """

    # Danh mục hành động rủi ro cao (ảnh hưởng diện rộng hoặc gián đoạn dịch vụ)
    HIGH_RISK_ACTIONS: Set[ActionType] = {
        ActionType.ISOLATE_HOST,
        ActionType.BLOCK_IP,
        ActionType.WAZUH_ACTIVE_RESPONSE,
        ActionType.RESET_PASSWORD,
    }

    # Danh mục hành động rủi ro thấp / cục bộ
    LOW_RISK_ACTIONS: Set[ActionType] = {
        ActionType.KILL_PROCESS,
        ActionType.REVOKE_USER,
        ActionType.PATCH_SYSTEM,
    }

    # Tài khoản hệ thống mặc định (không áp dụng khóa tài khoản thông thường)
    SYSTEM_ACCOUNTS: Set[str] = {
        "system",
        "local service",
        "network service",
        "anonymous logon",
        "dwm-1",
        "umfd-1",
    }

    def __init__(
        self,
        require_approval_by_default: bool = True,
        auto_approve_low_risk: bool = False,
        enable_wazuh_active_response: bool = True,
        system_prompt: Optional[str] = None,
        playbooks: Optional[Any] = None,
        wazuh_client: Optional[Any] = None,
        rag_kb: Optional[Any] = None,
    ):
        """
        Khởi tạo ResponseAgent với cấu hình chính sách phê duyệt và công cụ.

        :param require_approval_by_default: Yêu cầu phê duyệt chuyên viên mặc định cho các hành động.
        :param auto_approve_low_risk: Tự động phê duyệt các hành động ít rủi ro (KILL_PROCESS, REVOKE_USER).
        :param enable_wazuh_active_response: Cho phép kích hoạt cơ chế Wazuh Active Response.
        :param system_prompt: System prompt định hướng vai trò Incident Commander.
        :param playbooks: Lớp chứa kịch bản mẫu (mặc định ResponsePlaybooks).
        :param wazuh_client: Client tích hợp Wazuh SIEM (mặc định WazuhClientTool).
        :param rag_kb: Công cụ truy vấn cơ sở tri thức RAG (mặc định RAGKnowledgeBaseTool).
        """
        self.require_approval_by_default = require_approval_by_default
        self.auto_approve_low_risk = auto_approve_low_risk
        self.enable_wazuh_active_response = enable_wazuh_active_response
        self.system_prompt = system_prompt or RESPONSE_AGENT_SYSTEM_PROMPT
        self.playbooks = playbooks or ResponsePlaybooks
        self.wazuh_client = wazuh_client or WazuhClientTool
        self.rag_kb = rag_kb
        if self.rag_kb is None and RAGKnowledgeBaseTool is not None:
            try:
                self.rag_kb = RAGKnowledgeBaseTool()
            except Exception as exc:
                logger.warning(f"Không thể khởi tạo RAGKnowledgeBaseTool: {exc}")
                self.rag_kb = None
        self._last_rag_info: Dict[str, Any] = {}

    # =====================================================================
    # 1. HELPER POLICY VÀ APPROVAL FLAG DETERMINATION
    # =====================================================================
    def determine_approval_requirement(self, action_type: ActionType) -> bool:
        """
        Xác định xem hành động có bắt buộc chuyên viên SOC phê duyệt hay không.
        - Hành động rủi ro cao: LUÔN LUÔN yêu cầu phê duyệt (True).
        - Hành động rủi ro thấp:
          + Nếu auto_approve_low_risk=True -> False.
          + Ngược lại theo require_approval_by_default.
        """
        if action_type in self.HIGH_RISK_ACTIONS:
            return True

        if self.auto_approve_low_risk:
            return False

        return self.require_approval_by_default

    def apply_approval_policy(self, action: RecommendedAction) -> RecommendedAction:
        """Áp dụng chính sách phê duyệt lên một hành động RecommendedAction."""
        action.require_human_approval = self.determine_approval_requirement(action.action_type)
        return action

    @staticmethod
    def is_private_ip(ip_str: Optional[str]) -> bool:
        """Kiểm tra một địa chỉ IP có phải IP Private (RFC 1918) hoặc loopback hay không."""
        if not ip_str:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    # =====================================================================
    # 1B. TRA CỨU TRI THỨC RAG (MITRE ATT&CK MITIGATIONS & WAZUH REMEDIATION)
    # =====================================================================
    def lookup_rag_remediation(self, state: IncidentState) -> Dict[str, Any]:
        """
        Truy vấn RAG Knowledge Base để thu thập TTPs, MITRE Mitigations và Wazuh Remediation
        phù hợp với ngữ cảnh sự cố hiện tại.
        """
        mitre_ids: List[str] = []
        rule_ids: List[str] = []

        if state.threat_intel and state.threat_intel.mitre_techniques:
            for tid in state.threat_intel.mitre_techniques:
                tid_str = str(tid).strip()
                if tid_str and tid_str not in mitre_ids:
                    mitre_ids.append(tid_str)

        for event in state.parsed_events:
            raw_attrs = event.raw_attributes or {}
            for key in ("wazuh_mitre_ids", "mitre_ids"):
                raw_m = raw_attrs.get(key, [])
                if isinstance(raw_m, str):
                    raw_m = [x.strip() for x in raw_m.split(",") if x.strip()]
                elif isinstance(raw_m, list):
                    raw_m = [str(x).strip() for x in raw_m if str(x).strip()]
                else:
                    raw_m = []
                for m_id in raw_m:
                    if m_id not in mitre_ids:
                        mitre_ids.append(m_id)

            r_id = raw_attrs.get("wazuh_rule_id")
            if r_id is not None:
                r_id_str = str(r_id).strip()
                if r_id_str and r_id_str not in rule_ids:
                    rule_ids.append(r_id_str)

        query_parts: List[str] = []
        if state.triage_result:
            if state.triage_result.attack_type:
                query_parts.append(str(state.triage_result.attack_type))
            if state.triage_result.summary:
                query_parts.append(str(state.triage_result.summary))
        if state.rca_result:
            if state.rca_result.confirmed_attack_type:
                query_parts.append(str(state.rca_result.confirmed_attack_type))
            if state.rca_result.initial_access_vector:
                query_parts.append(str(state.rca_result.initial_access_vector))

        query_text = " ".join(p.strip() for p in query_parts if p and p.strip())

        ttp_matches: List[Dict[str, Any]] = []
        rule_matches: List[Dict[str, Any]] = []
        mitigations: List[str] = []
        remediations: List[str] = []

        if self.rag_kb is None:
            return {
                "mitre_ids": mitre_ids,
                "rule_ids": rule_ids,
                "query_text": query_text,
                "ttp_matches": ttp_matches,
                "rule_matches": rule_matches,
                "mitigations": mitigations,
                "remediations": remediations,
            }

        seen_ttp_ids: Set[str] = set()
        seen_rule_ids: Set[str] = set()

        def _add_ttp_record(rec: Optional[Dict[str, Any]]) -> None:
            if not isinstance(rec, dict):
                return
            tid = str(rec.get("technique_id") or rec.get("id") or "").strip()
            if tid and tid in seen_ttp_ids:
                return
            if tid:
                seen_ttp_ids.add(tid)
            ttp_matches.append(rec)
            mit = str(rec.get("mitigations") or "").strip()
            if mit and mit not in mitigations:
                mitigations.append(mit)

        def _add_rule_record(rec: Optional[Dict[str, Any]]) -> None:
            if not isinstance(rec, dict):
                return
            rid = str(rec.get("rule_id") or rec.get("id") or "").strip()
            if rid and rid in seen_rule_ids:
                return
            if rid:
                seen_rule_ids.add(rid)
            rule_matches.append(rec)
            rem = str(rec.get("remediation") or "").strip()
            if rem and rem not in remediations:
                remediations.append(rem)

        try:
            if hasattr(self.rag_kb, "retrieve_incident_knowledge"):
                rag_res = self.rag_kb.retrieve_incident_knowledge(
                    query_text=query_text,
                    mitre_ids=mitre_ids,
                    rule_ids=rule_ids,
                )
                if isinstance(rag_res, dict):
                    tech_items = (
                        rag_res.get("matched_techniques")
                        or rag_res.get("mitre_techniques")
                        or rag_res.get("ttp_matches")
                        or []
                    )
                    for item in tech_items:
                        _add_ttp_record(item)
                    rule_items = (
                        rag_res.get("matched_rules")
                        or rag_res.get("wazuh_rules")
                        or rag_res.get("rule_matches")
                        or []
                    )
                    for item in rule_items:
                        _add_rule_record(item)
                    mit_items = (
                        rag_res.get("nist_mitigations")
                        or rag_res.get("mitigations")
                        or []
                    )
                    for m in mit_items:
                        if m and str(m).strip() not in mitigations:
                            mitigations.append(str(m).strip())
                    rem_items = (
                        rag_res.get("nist_remediations")
                        or rag_res.get("remediations")
                        or []
                    )
                    for r in rem_items:
                        if r and str(r).strip() not in remediations:
                            remediations.append(str(r).strip())
        except Exception as exc:
            logger.debug(f"retrieve_incident_knowledge fallback: {exc}")

        # Tra cứu trực tiếp theo từng MITRE ID và Rule ID
        try:
            for tid in mitre_ids:
                if hasattr(self.rag_kb, "get_mitre_technique"):
                    exact_ttp = self.rag_kb.get_mitre_technique(tid)
                    if exact_ttp:
                        _add_ttp_record(exact_ttp)
                        continue
                if hasattr(self.rag_kb, "query_mitre_technique"):
                    for item in self.rag_kb.query_mitre_technique(tid, n_results=1):
                        _add_ttp_record(item)

            for rid in rule_ids:
                if hasattr(self.rag_kb, "get_wazuh_rule"):
                    exact_rule = self.rag_kb.get_wazuh_rule(rid)
                    if exact_rule:
                        _add_rule_record(exact_rule)
                        continue
                if hasattr(self.rag_kb, "query_wazuh_rule"):
                    for item in self.rag_kb.query_wazuh_rule(rid, n_results=1):
                        _add_rule_record(item)

            # Truy vấn ngữ nghĩa theo query_text nếu có
            if query_text:
                if hasattr(self.rag_kb, "query_mitre_technique"):
                    for item in self.rag_kb.query_mitre_technique(query_text, n_results=2):
                        _add_ttp_record(item)
                if hasattr(self.rag_kb, "query_wazuh_rule"):
                    for item in self.rag_kb.query_wazuh_rule(query_text, n_results=2):
                        _add_rule_record(item)
        except Exception as exc:
            logger.debug(f"Lỗi khi truy vấn RAG Knowledge Base: {exc}")

        return {
            "mitre_ids": mitre_ids,
            "rule_ids": rule_ids,
            "query_text": query_text,
            "ttp_matches": ttp_matches,
            "rule_matches": rule_matches,
            "mitigations": mitigations,
            "remediations": remediations,
        }

    # =====================================================================
    # 2. SINH HÀNH ĐỘNG TỪ PLAYBOOK VÀ WAZUH ACTIVE RESPONSE
    # =====================================================================
    def generate_malware_response(
        self,
        host_name: str,
        malicious_ip: str,
        process_name: str,
    ) -> List[RecommendedAction]:
        """
        Sinh danh sách hành động ngăn chặn mã độc theo NIST SP 800-61.
        Bao gồm: Cô lập máy trạm, chặn IP C2, tiêu diệt tiến trình độc hại.
        """
        raw_actions = self.playbooks.malware_incident_playbook(
            host_name=host_name,
            malicious_ip=malicious_ip,
            process_name=process_name,
        )
        for act in raw_actions:
            self.apply_approval_policy(act)
        return raw_actions

    def generate_phishing_response(
        self,
        compromised_user: str,
        phishing_ip: str,
    ) -> List[RecommendedAction]:
        """
        Sinh danh sách hành động xử lý lừa đảo và đánh cắp danh tính.
        Bao gồm: Thu hồi phiên đăng nhập, đặt lại mật khẩu và chặn IP tấn công.
        """
        raw_actions = self.playbooks.phishing_credential_playbook(
            compromised_user=compromised_user,
            phishing_ip=phishing_ip,
        )
        for act in raw_actions:
            self.apply_approval_policy(act)
        return raw_actions

    def create_wazuh_active_response(
        self,
        agent_id: str,
        command: str,
        target_ip: Optional[str] = None,
        use_wazuh_action_type: bool = False,
    ) -> RecommendedAction:
        """
        Tạo hành động Wazuh Active Response tích hợp với WazuhClientTool.
        Hỗ trợ các lệnh chuẩn: 'firewall-drop', 'host-isolate', 'kill-process'.
        """
        target = target_ip if target_ip else f"Agent-{agent_id}"
        if use_wazuh_action_type:
            action = RecommendedAction(
                action_type=ActionType.WAZUH_ACTIVE_RESPONSE,
                target=target,
                description=f"Wazuh Active Response [{command}] trên Agent ID {agent_id} (Target: {target}).",
                priority=1,
                require_human_approval=True,
            )
        else:
            action = self.wazuh_client.execute_active_response(
                agent_id=agent_id,
                command=command,
                target_ip=target_ip,
            )

        if not action.script_bundle:
            action.phase = IncidentPhase.CONTAINMENT
            action.script_bundle = self.playbooks.create_bundle(
                action_id=action.action_id or f"ACT-WAZUH-{command}",
                action_type=action.action_type,
                target=target,
                phase=IncidentPhase.CONTAINMENT,
            )

        self.apply_approval_policy(action)
        return action

    # =====================================================================
    # 3. DEDUPLICATION VÀ PRIORITY SORTING
    # =====================================================================
    def deduplicate_and_sort_actions(
        self,
        actions: List[RecommendedAction],
    ) -> List[RecommendedAction]:
        """
        Loại bỏ các hành động trùng lặp (theo action_type và target đã chuẩn hóa).
        Khi trùng, giữ lại hành động có mức ưu tiên cao hơn (chỉ số priority nhỏ hơn).
        Sắp xếp danh sách hành động theo thứ tự ưu tiên tăng dần (Priority 1 -> 5).
        """
        dedup_map: Dict[Tuple[ActionType, str], RecommendedAction] = {}

        for act in actions:
            target_norm = act.target.strip().lower()
            key = (act.action_type, target_norm)

            if key not in dedup_map:
                dedup_map[key] = act
            else:
                existing = dedup_map[key]
                # Nếu hành động mới có độ ưu tiên cao hơn (priority nhỏ hơn) thì ghi đè
                if act.priority < existing.priority:
                    dedup_map[key] = act

        # Sắp xếp theo: 1. Priority tăng dần, 2. action_type, 3. target
        sorted_actions = sorted(
            dedup_map.values(),
            key=lambda a: (a.priority, a.action_type.value, a.target),
        )
        return sorted_actions

    # =====================================================================
    # 4. KHẢO SÁT VÀ BÓC TÁCH NGỮ CẢNH TỪ INCIDENT STATE
    # =====================================================================
    def _extract_context(self, state: IncidentState) -> Dict[str, Any]:
        """Trích xuất toàn bộ thông tin đối tượng mục tiêu từ IncidentState."""
        hosts: Set[str] = set()
        users: Set[str] = set()
        processes: Set[str] = set()
        external_ips: Set[str] = set()
        source_ips: Set[str] = set()
        wazuh_agents: List[Dict[str, str]] = []

        # 1. Trích xuất từ parsed_events
        for event in state.parsed_events:
            if event.host_name and event.host_name not in {"UNKNOWN-HOST", ""}:
                hosts.add(event.host_name)

            if event.user_name and event.user_name.lower() not in self.SYSTEM_ACCOUNTS:
                users.add(event.user_name)

            if event.process_name:
                processes.add(event.process_name)

            if event.dest_ip and not self.is_private_ip(event.dest_ip):
                external_ips.add(event.dest_ip)

            if event.source_ip:
                if not self.is_private_ip(event.source_ip):
                    external_ips.add(event.source_ip)
                elif event.source_ip.strip() not in {"127.0.0.1", "::1"}:
                    source_ips.add(event.source_ip.strip())

            # Wazuh Agent metadata
            agent_id = event.raw_attributes.get("wazuh_agent_id")
            if agent_id:
                wazuh_agents.append({
                    "id": str(agent_id),
                    "name": event.raw_attributes.get("wazuh_agent_name") or event.host_name or f"agent-{agent_id}",
                    "ip": event.source_ip or event.dest_ip,
                })

        # 2. Trích xuất từ threat_intel
        if state.threat_intel:
            for ioc in state.threat_intel.extracted_iocs:
                if ioc.ioc_type.upper() == "IP" and not self.is_private_ip(ioc.value):
                    external_ips.add(ioc.value)

        # 3. Trích xuất từ rca_result
        if state.rca_result and state.rca_result.process_tree:
            for node in state.rca_result.process_tree:
                if node.is_malicious_origin or node.process_name:
                    processes.add(node.process_name)

        return {
            "hosts": sorted(list(hosts)),
            "users": sorted(list(users)),
            "processes": sorted(list(processes)),
            "external_ips": sorted(list(external_ips)),
            "source_ips": sorted(list(source_ips)),
            "wazuh_agents": wazuh_agents,
        }

    # =====================================================================
    # 5. RECOMMENDACTION ENGINE (SUY LUẬN THEO NIST SP 800-61)
    # =====================================================================
    def _build_user_containment_actions(
        self,
        user: str,
        revoke_id: str,
        reset_id: str,
    ) -> List[RecommendedAction]:
        """Tạo cặp hành động REVOKE_USER và RESET_PASSWORD cho tài khoản bị lộ lọt."""
        return [
            self.apply_approval_policy(
                RecommendedAction(
                    action_id=revoke_id,
                    action_type=ActionType.REVOKE_USER,
                    target=user,
                    description=f"Thu hồi toàn bộ phiên đăng nhập đang hoạt động của người dùng {user}.",
                    priority=1,
                    require_human_approval=False,
                    phase=IncidentPhase.CONTAINMENT,
                    script_bundle=self.playbooks.create_bundle(
                        revoke_id, ActionType.REVOKE_USER, user, IncidentPhase.CONTAINMENT
                    ),
                )
            ),
            self.apply_approval_policy(
                RecommendedAction(
                    action_id=reset_id,
                    action_type=ActionType.RESET_PASSWORD,
                    target=user,
                    description=f"Buộc đặt lại mật khẩu và cấu hình lại xác thực đa yếu tố (MFA) cho {user}.",
                    priority=2,
                    require_human_approval=True,
                    phase=IncidentPhase.ERADICATION,
                    script_bundle=self.playbooks.create_bundle(
                        reset_id, ActionType.RESET_PASSWORD, user, IncidentPhase.ERADICATION
                    ),
                )
            ),
        ]

    def recommend_actions(self, state: IncidentState) -> List[RecommendedAction]:
        """
        Đề xuất danh sách các hành động ứng phó phù hợp dựa trên tình trạng sự cố.
        Phân loại theo NIST SP 800-61:
        - Priority 1: Ngăn chặn khẩn cấp (ISOLATE_HOST, BLOCK_IP, KILL_PROCESS, REVOKE_USER).
        - Priority 2: Triệt tiêu / Danh tính (RESET_PASSWORD, KILL_PROCESS).
        - Priority 3: Khôi phục hệ thống (PATCH_SYSTEM, Quét EDR).
        """
        # Nếu Triage đã kết luận là False Positive thì không đề xuất hành động ngăn chặn
        if state.triage_result and not state.triage_result.is_incident:
            logger.info(f"[{state.incident_id}] Sự cố được phân loại False Positive, không đề xuất hành động.")
            self._last_rag_info = {}
            return []

        context = self._extract_context(state)
        hosts = context["hosts"]
        users = context["users"]
        processes = context["processes"]
        external_ips = context["external_ips"]
        source_ips = context["source_ips"]
        wazuh_agents = context["wazuh_agents"]

        actions: List[RecommendedAction] = []

        # Nhận diện đặc tính sự cố từ RCA, Triage và Threat Intel
        rca = state.rca_result
        triage = state.triage_result
        cti = state.threat_intel

        triage_cat_str = ""
        if triage and triage.attack_category:
            triage_cat_str = str(
                triage.attack_category.value
                if hasattr(triage.attack_category, "value")
                else triage.attack_category
            ).upper()

        triage_type = (triage.attack_type.lower() if triage and triage.attack_type else "")
        rca_type = (rca.confirmed_attack_type.lower() if rca and rca.confirmed_attack_type else "")
        rca_vector = (rca.initial_access_vector.lower() if rca and rca.initial_access_vector else "")
        summary_text = (triage.summary.lower() if triage and triage.summary else "")
        combined_text = f"{triage_type} {rca_type} {rca_vector} {summary_text}"
        cmd_lines_text = " ".join((e.command_line or "").lower() for e in state.parsed_events)

        mitre_techniques = {m.lower() for m in (cti.mitre_techniques if cti else [])}
        for event in state.parsed_events:
            raw_m = (event.raw_attributes or {}).get("wazuh_mitre_ids", [])
            if isinstance(raw_m, list):
                mitre_techniques.update(str(m).lower() for m in raw_m)
            elif isinstance(raw_m, str):
                mitre_techniques.update(m.strip().lower() for m in raw_m.split(",") if m.strip())

        web_Server_procs = ("nginx", "apache", "httpd", "iis", "w3wp", "tomcat", "php")
        has_web_service = any(
            w in combined_text or any(w in p.lower() for p in processes) or any(w in (e.parent_process or "").lower() for e in state.parsed_events)
            for w in web_Server_procs
        )

        is_web_attack = (
            triage_cat_str == "WEB_ATTACK"
            or any(
                kw in combined_text
                for kw in (
                    "web_attack",
                    "web attack",
                    "sql injection",
                    "sqli",
                    "xss",
                    "cross-site scripting",
                    "webshell",
                    "web shell",
                    "exploit public-facing",
                )
            )
            or ("rce" in combined_text and has_web_service)
            or "t1190" in mitre_techniques
            or "t1505.003" in mitre_techniques
        )

        is_reconnaissance = (
            triage_cat_str == "RECONNAISSANCE"
            or any(
                kw in combined_text
                for kw in (
                    "reconnaissance",
                    "network scanning",
                    "port scan",
                    "icmp sweep",
                    "service discovery",
                    "syn scan",
                )
            )
            or "t1046" in mitre_techniques
            or "t1595" in mitre_techniques
        )

        is_ransomware = (
            any(
                kw in combined_text or kw in cmd_lines_text
                for kw in (
                    "ransomware",
                    "vssadmin",
                    "shadow copy",
                    "shadowcopy",
                    "data encrypted",
                )
            )
            or "t1486" in mitre_techniques
            or "t1490" in mitre_techniques
        )

        is_privilege_escalation = (
            triage_cat_str == "PRIVILEGE_ESCALATION"
            or any(
                kw in combined_text
                for kw in (
                    "privilege_escalation",
                    "privilege escalation",
                    "leo thang đặc quyền",
                    "sudo",
                )
            )
            or "t1548" in mitre_techniques
            or "t1068" in mitre_techniques
            or any(m.startswith("t1548.") for m in mitre_techniques)
        )

        is_specialized_scenario = (
            is_web_attack
            or is_reconnaissance
            or is_ransomware
            or is_privilege_escalation
        )

        if is_specialized_scenario:
            is_phishing_or_credential = (
                "phish" in combined_text
                or "credential" in combined_text
                or "brute" in combined_text
                or "t1110" in mitre_techniques
                or "t1566" in mitre_techniques
            )
            is_malware_or_c2 = False
        else:
            is_phishing_or_credential = (
                "phish" in rca_vector
                or "credential" in rca_vector
                or "brute" in rca_vector
                or "account" in rca_vector
                or "logon" in rca_vector
                or "rdp" in rca_vector
                or "t1078" in mitre_techniques
                or "t1110" in mitre_techniques
                or "t1003" in mitre_techniques
                or "t1566" in mitre_techniques
                or bool(users)
            )

            is_malware_or_c2 = (
                "malware" in rca_vector
                or "macro" in rca_vector
                or "exploit" in rca_vector
                or "powershell" in summary_text
                or "trojan" in summary_text
                or bool(processes)
                or bool(hosts)
                or not is_phishing_or_credential
            )

        # -------------------------------------------------------------
        # 0. CÁC TÌNH HUỐNG MỚI THEO CHUẨN NIST SP 800-61
        # -------------------------------------------------------------
        if is_web_attack:
            target_host = hosts[0] if hosts else "WEB-SERVER-01"
            attacker_ip = external_ips[0] if external_ips else (source_ips[0] if source_ips else "194.26.29.112")
            shell_names = {"cmd.exe", "powershell.exe", "bash", "sh", "nc", "php-cgi", "cmd", "powershell", "pwsh", "nc.exe", "netcat"}
            web_proc: Optional[str] = None
            for p in processes:
                p_base = p.strip().lower().split("/")[-1].split("\\")[-1]
                if p_base in shell_names:
                    web_proc = p
                    break
            if web_proc is None and processes:
                web_proc = processes[0]

            web_actions = self.playbooks.web_attack_playbook(
                host_name=target_host,
                attacker_ip=attacker_ip,
                web_process=web_proc,
            )
            for act in web_actions:
                self.apply_approval_policy(act)
            actions.extend(web_actions)

            for ip_val in external_ips[1:]:
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=f"ACT-WEB-BLOCK-{ip_val}",
                            action_type=ActionType.BLOCK_IP,
                            target=ip_val,
                            description=f"Chặn địa chỉ IP tấn công Web phụ trợ {ip_val} trên WAF/Firewall.",
                            priority=1,
                            require_human_approval=True,
                            phase=IncidentPhase.CONTAINMENT,
                            script_bundle=self.playbooks.create_bundle(f"ACT-WEB-BLOCK-{ip_val}", ActionType.BLOCK_IP, ip_val, IncidentPhase.CONTAINMENT),
                        )
                    )
                )

        if is_reconnaissance:
            attacker_ip = external_ips[0] if external_ips else (source_ips[0] if source_ips else "194.26.29.112")
            target_host = hosts[0] if hosts else None
            recon_actions = self.playbooks.reconnaissance_playbook(
                attacker_ip=attacker_ip,
                target_host=target_host,
            )
            for act in recon_actions:
                self.apply_approval_policy(act)
            actions.extend(recon_actions)

        if is_ransomware:
            target_host = hosts[0] if hosts else "WORKSTATION-01"
            target_proc = processes[0] if processes else None
            c2_ip = external_ips[0] if external_ips else None
            comp_user = users[0] if users else None
            ransom_actions = self.playbooks.ransomware_incident_playbook(
                host_name=target_host,
                process_name=target_proc,
                c2_ip=c2_ip,
                compromised_user=comp_user,
            )
            for act in ransom_actions:
                self.apply_approval_policy(act)
            actions.extend(ransom_actions)

        if is_privilege_escalation:
            target_host = hosts[0] if hosts else "WORKSTATION-01"
            comp_user = users[0] if users else None
            rogue_proc = processes[0] if processes else None
            privesc_actions = self.playbooks.privilege_escalation_playbook(
                host_name=target_host,
                compromised_user=comp_user,
                rogue_process=rogue_proc,
            )
            for act in privesc_actions:
                self.apply_approval_policy(act)
            actions.extend(privesc_actions)

        # -------------------------------------------------------------
        # 1. CONTAINMENT & ERADICATION: MALWARE / C2 INTRUSION
        # -------------------------------------------------------------
        if is_malware_or_c2:
            target_host = hosts[0] if hosts else "WORKSTATION-01"
            target_proc = processes[0] if processes else "powershell.exe"

            if external_ips or (not hosts and not processes):
                target_ip = external_ips[0] if external_ips else "194.26.29.112"
                malware_actions = self.generate_malware_response(
                    host_name=target_host,
                    malicious_ip=target_ip,
                    process_name=target_proc,
                )
                actions.extend(malware_actions)
            else:
                # Sự cố nội bộ không có IP C2 bên ngoài -> chỉ cô lập host và diệt tiến trình
                if hosts:
                    actions.append(
                        self.apply_approval_policy(
                            RecommendedAction(
                                action_id="ACT-MALW-ISOLATE",
                                action_type=ActionType.ISOLATE_HOST,
                                target=target_host,
                                description=f"Cô lập máy trạm {target_host} khỏi mạng nội bộ để ngăn chặn lây lan.",
                                priority=1,
                                require_human_approval=True,
                                phase=IncidentPhase.CONTAINMENT,
                                script_bundle=self.playbooks.create_bundle("ACT-MALW-ISOLATE", ActionType.ISOLATE_HOST, target_host, IncidentPhase.CONTAINMENT),
                            )
                        )
                    )
                if processes:
                    actions.append(
                        self.apply_approval_policy(
                            RecommendedAction(
                                action_id="ACT-MALW-KILL",
                                action_type=ActionType.KILL_PROCESS,
                                target=target_proc,
                                description=f"Tiêu diệt tiến trình độc hại {target_proc} đang chạy trên máy trạm.",
                                priority=2,
                                require_human_approval=False,
                                phase=IncidentPhase.CONTAINMENT,
                                script_bundle=self.playbooks.create_bundle("ACT-MALW-KILL", ActionType.KILL_PROCESS, target_proc, IncidentPhase.CONTAINMENT),
                            )
                        )
                    )

            # Bổ sung các host khác nếu có nhiều host bị ảnh hưởng
            for h in hosts[1:]:
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=f"ACT-MALW-ISOLATE-{h}",
                            action_type=ActionType.ISOLATE_HOST,
                            target=h,
                            description=f"Cô lập máy trạm {h} khỏi mạng nội bộ để ngăn chặn lây lan ngang.",
                            priority=1,
                            require_human_approval=True,
                            phase=IncidentPhase.CONTAINMENT,
                            script_bundle=self.playbooks.create_bundle(f"ACT-MALW-ISOLATE-{h}", ActionType.ISOLATE_HOST, h, IncidentPhase.CONTAINMENT),
                        )
                    )
                )

            # Bổ sung các tiến trình độc hại khác nếu phát hiện từ RCA tree
            if rca and rca.process_tree:
                for node in rca.process_tree:
                    if node.process_name and node.process_name.lower() != target_proc.lower():
                        actions.append(
                            self.apply_approval_policy(
                                RecommendedAction(
                                    action_id=f"ACT-KILL-{node.process_name}",
                                    action_type=ActionType.KILL_PROCESS,
                                    target=node.process_name,
                                    description=f"Tiêu diệt tiến trình độc hại liên quan {node.process_name} (PID: {node.process_id}).",
                                    priority=2,
                                    require_human_approval=False,
                                    phase=IncidentPhase.CONTAINMENT,
                                    script_bundle=self.playbooks.create_bundle(f"ACT-KILL-{node.process_name}", ActionType.KILL_PROCESS, node.process_name, IncidentPhase.CONTAINMENT),
                                )
                            )
                        )

            # Bổ sung các IP C2 khác nếu có
            for ip_val in external_ips[1:]:
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=f"ACT-BLOCK-{ip_val}",
                            action_type=ActionType.BLOCK_IP,
                            target=ip_val,
                            description=f"Chặn địa chỉ IP C2 phụ trợ {ip_val} trên Firewall và Web Proxy.",
                            priority=1,
                            require_human_approval=True,
                            phase=IncidentPhase.CONTAINMENT,
                            script_bundle=self.playbooks.create_bundle(f"ACT-BLOCK-{ip_val}", ActionType.BLOCK_IP, ip_val, IncidentPhase.CONTAINMENT),
                        )
                    )
                )

        # -------------------------------------------------------------
        # 2. CONTAINMENT & ERADICATION: PHISHING & CREDENTIAL COMPROMISE
        # -------------------------------------------------------------
        if is_phishing_or_credential:
            target_user = users[0] if users else "compromised_user"
            if external_ips or (not users and not hosts):
                target_ip = external_ips[0] if external_ips else "194.26.29.112"
                phishing_actions = self.generate_phishing_response(
                    compromised_user=target_user,
                    phishing_ip=target_ip,
                )
                actions.extend(phishing_actions)
            else:
                # Sự cố lộ tài khoản nội bộ không có IP ngoài
                act_revoke_id = "ACT-PHISH-REVOKE"
                act_reset_id = "ACT-PHISH-RESET"
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=act_revoke_id,
                            action_type=ActionType.REVOKE_USER,
                            target=target_user,
                            description=f"Thu hồi toàn bộ phiên đăng nhập đang hoạt động của người dùng {target_user}.",
                            priority=1,
                            require_human_approval=False,
                            phase=IncidentPhase.CONTAINMENT,
                            script_bundle=self.playbooks.create_bundle(act_revoke_id, ActionType.REVOKE_USER, target_user, IncidentPhase.CONTAINMENT),
                        )
                    )
                )
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=act_reset_id,
                            action_type=ActionType.RESET_PASSWORD,
                            target=target_user,
                            description=f"Buộc đặt lại mật khẩu và cấu hình lại xác thực đa yếu tố (MFA) cho {target_user}.",
                            priority=2,
                            require_human_approval=True,
                            phase=IncidentPhase.ERADICATION,
                            script_bundle=self.playbooks.create_bundle(act_reset_id, ActionType.RESET_PASSWORD, target_user, IncidentPhase.ERADICATION),
                        )
                    )
                )
                if source_ips:
                    act_block_id = "ACT-PHISH-BLOCK"
                    actions.append(
                        self.apply_approval_policy(
                            RecommendedAction(
                                action_id=act_block_id,
                                action_type=ActionType.BLOCK_IP,
                                target=source_ips[0],
                                description=f"Chặn IP {source_ips[0]} đã sử dụng tài khoản đăng nhập trái phép.",
                                priority=1,
                                require_human_approval=True,
                                phase=IncidentPhase.CONTAINMENT,
                                script_bundle=self.playbooks.create_bundle(act_block_id, ActionType.BLOCK_IP, source_ips[0], IncidentPhase.CONTAINMENT),
                            )
                        )
                    )

            # Bổ sung các tài khoản khác nếu có
            for u in users[1:]:
                act_revoke_u = f"ACT-PHISH-REVOKE-{u}"
                act_reset_u = f"ACT-PHISH-RESET-{u}"
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=act_revoke_u,
                            action_type=ActionType.REVOKE_USER,
                            target=u,
                            description=f"Thu hồi toàn bộ phiên đăng nhập đang hoạt động của người dùng {u}.",
                            priority=1,
                            require_human_approval=False,
                            phase=IncidentPhase.CONTAINMENT,
                            script_bundle=self.playbooks.create_bundle(act_revoke_u, ActionType.REVOKE_USER, u, IncidentPhase.CONTAINMENT),
                        )
                    )
                )
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=act_reset_u,
                            action_type=ActionType.RESET_PASSWORD,
                            target=u,
                            description=f"Buộc đặt lại mật khẩu và cấu hình lại xác thực đa yếu tố (MFA) cho {u}.",
                            priority=2,
                            require_human_approval=True,
                            phase=IncidentPhase.ERADICATION,
                            script_bundle=self.playbooks.create_bundle(act_reset_u, ActionType.RESET_PASSWORD, u, IncidentPhase.ERADICATION),
                        )
                    )
                )

        # -------------------------------------------------------------
        # 3. WAZUH ACTIVE RESPONSE (NẾU CÓ WAZUH AGENT LIÊN QUAN)
        # -------------------------------------------------------------
        if self.enable_wazuh_active_response and wazuh_agents:
            primary_agent = wazuh_agents[0]
            agent_id = primary_agent["id"]

            if external_ips:
                for ext_ip in external_ips[:2]:
                    actions.append(
                        self.create_wazuh_active_response(
                            agent_id=agent_id,
                            command="firewall-drop",
                            target_ip=ext_ip,
                        )
                    )

            if not (is_reconnaissance or is_web_attack or is_privilege_escalation):
                actions.append(
                    self.create_wazuh_active_response(
                        agent_id=agent_id,
                        command="host-isolate",
                        target_ip=None,
                    )
                )

        # -------------------------------------------------------------
        # 5. ADAPTIVE FEEDBACK HANDLING (XỬ LÝ CHỈ THỊ TỪ CHUYÊN VIÊN KHI QUAY LUI)
        # -------------------------------------------------------------
        if state.analyst_feedback:
            feedback_lower = state.analyst_feedback.lower()
            # Nếu chuyên viên từ chối cô lập host (hoặc máy chủ quan trọng Domain Controller / Database)
            if any(term in feedback_lower for term in ["không cô lập", "từ chối cô lập", "không isolate", "không ngắt kết nối", "domain controller", "dc-server"]):
                logger.info("Phát hiện chỉ thị từ chối cô lập host từ phản hồi của chuyên viên. Tự động loại bỏ hành động ISOLATE_HOST.")
                actions = [a for a in actions if a.action_type != ActionType.ISOLATE_HOST and "host-isolate" not in (getattr(a, "command", "") or "")]
                # Đảm bảo bổ sung hành động tiêu diệt tiến trình độc hại thay thế nếu chưa có
                if not any(a.action_type == ActionType.KILL_PROCESS for a in actions) and processes:
                    actions.append(
                        self.apply_approval_policy(
                            RecommendedAction(
                                action_type=ActionType.KILL_PROCESS,
                                target=processes[0],
                                description=f"Tiêu diệt tiến trình độc hại {processes[0]} thay thế cho phương án cô lập host.",
                                priority=1,
                                require_human_approval=False,
                            )
                        )
                    )

        # Loại bỏ trùng lặp và sắp xếp theo độ ưu tiên tăng dần (Priority 1 -> 5)
        final_actions = self.deduplicate_and_sort_actions(actions)

        # -------------------------------------------------------------
        # 6. ĐÍNH KÈM TRI THỨC RAG (MITRE MITIGATIONS & WAZUH REMEDIATION)
        # -------------------------------------------------------------
        rag_info = self.lookup_rag_remediation(state)
        self._last_rag_info = rag_info

        guidance_snippets: List[str] = []
        if rag_info.get("remediations"):
            guidance_snippets.append(f"Wazuh Remediation: {rag_info['remediations'][0]}")
        if rag_info.get("mitigations"):
            guidance_snippets.append(f"MITRE Mitigation: {rag_info['mitigations'][0]}")

        if guidance_snippets:
            rag_guidance_str = f"[NIST/MITRE RAG Guidance] {' | '.join(guidance_snippets)}"
            for act in final_actions:
                if act.script_bundle and "[NIST/MITRE RAG Guidance]" not in (act.script_bundle.instructions or ""):
                    base_inst = (act.script_bundle.instructions or "").strip()
                    act.script_bundle.instructions = f"{base_inst} {rag_guidance_str}".strip()

        return final_actions

    # =====================================================================
    # 6. PIPELINE & STATEGRAPH INTERACTION
    # =====================================================================
    def process_state(self, state: IncidentState) -> IncidentState:
        """
        Thực thi đề xuất hành động và cập nhật trực tiếp vào IncidentState của StateGraph.

        :param state: IncidentState hiện tại.
        :return: IncidentState đã cập nhật recommended_actions và lịch sử chuyển dịch.
        """
        logger.info(f"[{state.incident_id}] Bắt đầu quy trình đề xuất phản ứng sự cố...")

        actions = self.recommend_actions(state)
        state.recommended_actions = actions

        action_summary = [f"{a.action_type.value}({a.target})" for a in actions]
        rag_info = self._last_rag_info or self.lookup_rag_remediation(state)
        rag_ttp_matches = [
            t.get("technique_id") or t.get("id")
            for t in rag_info.get("ttp_matches", [])
            if isinstance(t, dict) and (t.get("technique_id") or t.get("id"))
        ]
        rag_remediations = list(rag_info.get("remediations", [])) + list(rag_info.get("mitigations", []))

        state.record_transition(
            node="response",
            to_status=IncidentStatus.INVESTIGATING,
            message=f"Đã đề xuất {len(actions)} hành động ứng phó theo chuẩn NIST SP 800-61.",
            metadata={
                "action_count": len(actions),
                "actions": [a.action_type.value for a in actions],
                "action_summary": action_summary,
                "high_priority_count": sum(1 for a in actions if a.priority == 1),
                "require_approval_count": sum(1 for a in actions if a.require_human_approval),
                "rag_ttp_matches": rag_ttp_matches,
                "rag_remediations": rag_remediations,
            },
        )

        logger.info(f"[{state.incident_id}] Đã sinh {len(actions)} hành động (HITL required: {sum(1 for a in actions if a.require_human_approval)}).")
        return state

    def analyze_state(self, state: IncidentState) -> IncidentState:
        """Bí danh tương thích cho process_state."""
        return self.process_state(state)

    def evaluate(self, state: IncidentState) -> List[RecommendedAction]:
        """Bí danh tương thích cho recommend_actions."""
        return self.recommend_actions(state)

