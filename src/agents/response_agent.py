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
    ParsedEvent,
    IoCItem,
    IncidentPhase,
)
from src.core.state import IncidentState
from src.agents.prompts import RESPONSE_AGENT_SYSTEM_PROMPT
from src.tools.playbooks import ResponsePlaybooks
from src.tools.wazuh_client import WazuhClientTool

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
    ):
        """
        Khởi tạo ResponseAgent với cấu hình chính sách phê duyệt và công cụ.

        :param require_approval_by_default: Yêu cầu phê duyệt chuyên viên mặc định cho các hành động.
        :param auto_approve_low_risk: Tự động phê duyệt các hành động ít rủi ro (KILL_PROCESS, REVOKE_USER).
        :param enable_wazuh_active_response: Cho phép kích hoạt cơ chế Wazuh Active Response.
        :param system_prompt: System prompt định hướng vai trò Incident Commander.
        :param playbooks: Lớp chứa kịch bản mẫu (mặc định ResponsePlaybooks).
        :param wazuh_client: Client tích hợp Wazuh SIEM (mặc định WazuhClientTool).
        """
        self.require_approval_by_default = require_approval_by_default
        self.auto_approve_low_risk = auto_approve_low_risk
        self.enable_wazuh_active_response = enable_wazuh_active_response
        self.system_prompt = system_prompt or RESPONSE_AGENT_SYSTEM_PROMPT
        self.playbooks = playbooks or ResponsePlaybooks
        self.wazuh_client = wazuh_client or WazuhClientTool

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

            if event.source_ip and not self.is_private_ip(event.source_ip):
                external_ips.add(event.source_ip)

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
            "wazuh_agents": wazuh_agents,
        }

    # =====================================================================
    # 5. RECOMMENDACTION ENGINE (SUY LUẬN THEO NIST SP 800-61)
    # =====================================================================
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
            return []

        context = self._extract_context(state)
        hosts = context["hosts"]
        users = context["users"]
        processes = context["processes"]
        external_ips = context["external_ips"]
        wazuh_agents = context["wazuh_agents"]

        actions: List[RecommendedAction] = []

        # Nhận diện đặc tính sự cố từ RCA, Triage và Threat Intel
        rca = state.rca_result
        triage = state.triage_result
        cti = state.threat_intel

        rca_vector = (rca.initial_access_vector.lower() if rca and rca.initial_access_vector else "")
        summary_text = (triage.summary.lower() if triage and triage.summary else "")
        mitre_techniques = set(cti.mitre_techniques if cti else [])

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
        # 1. CONTAINMENT & ERADICATION: MALWARE / C2 INTRUSION
        # -------------------------------------------------------------
        if is_malware_or_c2:
            target_host = hosts[0] if hosts else "WORKSTATION-01"
            target_ip = external_ips[0] if external_ips else "194.26.29.112"
            target_proc = processes[0] if processes else "powershell.exe"

            # Kích hoạt Playbook Malware tiêu chuẩn
            malware_actions = self.generate_malware_response(
                host_name=target_host,
                malicious_ip=target_ip,
                process_name=target_proc,
            )
            actions.extend(malware_actions)

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
            target_ip = external_ips[0] if external_ips else "194.26.29.112"

            # Kích hoạt Playbook Phishing & Credential Compromise
            phishing_actions = self.generate_phishing_response(
                compromised_user=target_user,
                phishing_ip=target_ip,
            )
            actions.extend(phishing_actions)

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

            actions.append(
                self.create_wazuh_active_response(
                    agent_id=agent_id,
                    command="host-isolate",
                    target_ip=None,
                )
            )

        # -------------------------------------------------------------
        # 4. RECOVERY: VÁ LỖ HỔNG & KHÔI PHỤC HỆ THỐNG (PRIORITY 3-4)
        # -------------------------------------------------------------
        remediation_target = hosts[0] if hosts else "All-Affected-Endpoints"
        patch_act_id = f"ACT-PATCH-{remediation_target}"
        patch_action = RecommendedAction(
            action_id=patch_act_id,
            action_type=ActionType.PATCH_SYSTEM,
            target=remediation_target,
            description=f"Cập nhật bản vá bảo mật hệ điều hành và quét toàn diện máy trạm {remediation_target}.",
            priority=3,
            require_human_approval=False,
            phase=IncidentPhase.RECOVERY,
            script_bundle=self.playbooks.create_bundle(patch_act_id, ActionType.PATCH_SYSTEM, remediation_target, IncidentPhase.RECOVERY),
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
        return self.deduplicate_and_sort_actions(actions)

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
