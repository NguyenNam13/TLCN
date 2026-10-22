# -*- coding: utf-8 -*-
"""
src/tools/playbooks.py
Kịch bản phản ứng mẫu (Response Playbooks) theo chuẩn NIST SP 800-61.
Cung cấp các hành động chuẩn hóa cho Response Recommendation Agent.
"""

from typing import List, Optional, Dict, Any
from src.core.schemas import RecommendedAction, ActionType, ActionScriptBundle, IncidentPhase


class ResponsePlaybooks:
    """Tập hợp Playbooks ứng phó sự cố theo từng loại sự cố."""

    @staticmethod
    def create_bundle(
        action_id: Any,
        action_type: Any = None,
        target: str = "",
        phase: IncidentPhase = IncidentPhase.CONTAINMENT,
    ) -> ActionScriptBundle:
        """Sinh ActionScriptBundle hoàn chỉnh chứa cả kịch bản can thiệp và kịch bản hoàn tác (Rollback)."""
        import uuid
        # Linh hoạt hỗ trợ cả create_bundle(ActionType, target) và create_bundle(action_id, ActionType, target)
        if isinstance(action_id, ActionType) or (isinstance(action_id, str) and action_id in ActionType._value2member_map_):
            actual_action_type = ActionType(action_id)
            actual_target = str(action_type) if action_type else ""
            actual_action_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        else:
            actual_action_id = str(action_id)
            actual_action_type = ActionType(action_type) if action_type else ActionType.ISOLATE_HOST
            actual_target = target

        action_type = actual_action_type
        target = actual_target
        action_id = actual_action_id

        ps_script: Optional[str] = None
        bash_script: Optional[str] = None
        wazuh_ar: Optional[Dict[str, Any]] = None
        rollback_script: Optional[str] = None
        instructions = f"Thực thi hoặc hoàn tác cho {action_type.value} trên mục tiêu {target}."

        if action_type == ActionType.ISOLATE_HOST:
            ps_script = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; New-NetFirewallRule -DisplayName 'BlockAllExceptWazuh' -Direction Outbound -Action Block"
            rollback_script = "Remove-NetFirewallRule -DisplayName 'BlockAllExceptWazuh'; Enable-NetAdapter -Name * -Confirm:$false"
            bash_script = "iptables -A OUTPUT -p tcp ! --dport 1514 -j DROP; iptables -A INPUT -p tcp ! --sport 1514 -j DROP"
            wazuh_ar = {"command": "host-isolate", "target": target}
            instructions = f"Cô lập máy trạm {target} khỏi mạng nội bộ (giữ kết nối Wazuh Manager). Rollback: gỡ luật cách ly và mở lại card mạng."

        elif action_type == ActionType.BLOCK_IP:
            ps_script = f"New-NetFirewallRule -DisplayName 'Block_{target}' -Direction Inbound -Action Block -RemoteAddress {target}"
            rollback_script = f"Remove-NetFirewallRule -DisplayName 'Block_{target}'"
            bash_script = f"iptables -I INPUT -s {target} -j DROP; iptables -I FORWARD -s {target} -j DROP"
            wazuh_ar = {"command": "firewall-drop", "target": target}
            instructions = f"Chặn địa chỉ IP độc hại {target} trên Firewall. Rollback: xóa luật chặn iptables/Windows Firewall."

        elif action_type == ActionType.KILL_PROCESS:
            ps_script = f"Stop-Process -Name '{target}' -Force -ErrorAction SilentlyContinue"
            bash_script = f"pkill -9 -f '{target}'"
            wazuh_ar = {"command": "kill-process", "target": target}
            rollback_script = None  # Tiến trình bị tiêu diệt không thể hoàn tác trực tiếp
            instructions = f"Tiêu diệt tiến trình độc hại {target}. Lưu ý: Hành động này không thể hoàn tác tự động (Irreversible)."

        elif action_type == ActionType.REVOKE_USER:
            ps_script = f"Revoke-AzureADUserAllRefreshToken -ObjectId '{target}'"
            bash_script = f"pkill -u '{target}'"
            rollback_script = None  # Phiên đã thu hồi cần người dùng đăng nhập lại
            instructions = f"Thu hồi toàn bộ phiên làm việc của người dùng {target}."

        elif action_type == ActionType.RESET_PASSWORD:
            ps_script = f"Set-ADUser -Identity '{target}' -ChangePasswordAtLogon $true; Disable-ADAccount -Identity '{target}'"
            rollback_script = f"Enable-ADAccount -Identity '{target}'"
            instructions = f"Vô hiệu hóa tài khoản và buộc đổi mật khẩu cho {target}. Rollback: mở khóa tài khoản (Enable-ADAccount)."

        elif action_type == ActionType.PATCH_SYSTEM:
            ps_script = "Install-WindowsUpdate -AcceptAll -AutoReboot:$false"
            bash_script = "apt-get update && apt-get upgrade -y"
            rollback_script = None
            instructions = f"Cập nhật bản vá bảo mật trên {target}."

        return ActionScriptBundle(
            action_id=action_id,
            phase=phase,
            target=target,
            powershell_script=ps_script,
            bash_script=bash_script,
            wazuh_active_response=wazuh_ar,
            rollback_script=rollback_script,
            instructions=instructions,
        )

    @classmethod
    def malware_incident_playbook(cls, host_name: str, malicious_ip: str, process_name: str) -> List[RecommendedAction]:
        """Playbook xử lý sự cố mã độc trên máy trạm (Endpoint Malware) có đính kèm kịch bản hoàn tác."""
        act_isolate_id = "ACT-MALW-ISOLATE"
        act_kill_id = "ACT-MALW-KILL"
        act_block_id = "ACT-MALW-BLOCK"

        return [
            RecommendedAction(
                action_id=act_isolate_id,
                action_type=ActionType.ISOLATE_HOST,
                target=host_name,
                description=f"Cô lập máy trạm {host_name} khỏi mạng nội bộ để ngăn chặn lây lan.",
                priority=1,
                require_human_approval=True,
                phase=IncidentPhase.CONTAINMENT,
                script_bundle=cls.create_bundle(act_isolate_id, ActionType.ISOLATE_HOST, host_name, IncidentPhase.CONTAINMENT),
            ),
            RecommendedAction(
                action_id=act_kill_id,
                action_type=ActionType.KILL_PROCESS,
                target=process_name,
                description=f"Tiêu diệt tiến trình độc hại {process_name} đang chạy trên máy trạm.",
                priority=2,
                require_human_approval=False,
                phase=IncidentPhase.CONTAINMENT,
                script_bundle=cls.create_bundle(act_kill_id, ActionType.KILL_PROCESS, process_name, IncidentPhase.CONTAINMENT),
            ),
            RecommendedAction(
                action_id=act_block_id,
                action_type=ActionType.BLOCK_IP,
                target=malicious_ip,
                description=f"Chặn địa chỉ IP C2 {malicious_ip} trên Firewall và Web Proxy.",
                priority=1,
                require_human_approval=True,
                phase=IncidentPhase.CONTAINMENT,
                script_bundle=cls.create_bundle(act_block_id, ActionType.BLOCK_IP, malicious_ip, IncidentPhase.CONTAINMENT),
            ),
        ]

    @classmethod
    def phishing_credential_playbook(cls, compromised_user: str, phishing_ip: str) -> List[RecommendedAction]:
        """Playbook xử lý sự cố lừa đảo đánh cắp danh tính (Phishing & Credential Compromise) có đính kèm kịch bản hoàn tác."""
        act_revoke_id = "ACT-PHISH-REVOKE"
        act_reset_id = "ACT-PHISH-RESET"
        act_block_id = "ACT-PHISH-BLOCK"

        return [
            RecommendedAction(
                action_id=act_revoke_id,
                action_type=ActionType.REVOKE_USER,
                target=compromised_user,
                description=f"Thu hồi toàn bộ phiên đăng nhập đang hoạt động của người dùng {compromised_user}.",
                priority=1,
                require_human_approval=False,
                phase=IncidentPhase.CONTAINMENT,
                script_bundle=cls.create_bundle(act_revoke_id, ActionType.REVOKE_USER, compromised_user, IncidentPhase.CONTAINMENT),
            ),
            RecommendedAction(
                action_id=act_reset_id,
                action_type=ActionType.RESET_PASSWORD,
                target=compromised_user,
                description=f"Buộc đặt lại mật khẩu và cấu hình lại xác thực đa yếu tố (MFA) cho {compromised_user}.",
                priority=2,
                require_human_approval=True,
                phase=IncidentPhase.ERADICATION,
                script_bundle=cls.create_bundle(act_reset_id, ActionType.RESET_PASSWORD, compromised_user, IncidentPhase.ERADICATION),
            ),
            RecommendedAction(
                action_id=act_block_id,
                action_type=ActionType.BLOCK_IP,
                target=phishing_ip,
                description=f"Chặn IP lạ {phishing_ip} đã sử dụng tài khoản đăng nhập trái phép.",
                priority=1,
                require_human_approval=True,
                phase=IncidentPhase.CONTAINMENT,
                script_bundle=cls.create_bundle(act_block_id, ActionType.BLOCK_IP, phishing_ip, IncidentPhase.CONTAINMENT),
            ),
        ]


# Alias tiện ích cấp module phục vụ kiểm thử và gọi nhanh
create_bundle = ResponsePlaybooks.create_bundle

