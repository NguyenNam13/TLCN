# -*- coding: utf-8 -*-
"""
src/tools/playbooks.py
Kịch bản phản ứng mẫu (Response Playbooks) theo chuẩn NIST SP 800-61.
Cung cấp các hành động chuẩn hóa cho Response Recommendation Agent.
"""

import re
import uuid
from typing import List, Optional, Dict, Any, Set
from src.core.schemas import RecommendedAction, ActionType, ActionScriptBundle, IncidentPhase

# Danh sách tiến trình hệ thống quan trọng cần bảo vệ (System Process Whitelist)
CRITICAL_SYSTEM_PROCESSES: Set[str] = {
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "explorer.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
}


def is_critical_system_process(process_name: str) -> bool:
    """Kiểm tra tên tiến trình có thuộc danh mục tiến trình hệ thống trọng yếu (CRITICAL_SYSTEM_PROCESSES) hay không."""
    if not process_name:
        return False
    clean = str(process_name).strip().lower().split("/")[-1].split("\\")[-1].strip("'\" ")
    if not clean:
        return False
    if clean in CRITICAL_SYSTEM_PROCESSES:
        return True
    if f"{clean}.exe" in CRITICAL_SYSTEM_PROCESSES:
        return True
    return False


class ResponsePlaybooks:
    """Tập hợp Playbooks ứng phó sự cố theo từng loại sự cố."""

    CRITICAL_SYSTEM_PROCESSES = CRITICAL_SYSTEM_PROCESSES
    is_critical_system_process = staticmethod(is_critical_system_process)

    @staticmethod
    def _sanitize_target(target: str, is_ip: bool = False) -> str:
        """Làm sạch mục tiêu nhằm ngăn chặn triệt để Command Injection."""
        if not target:
            return ""
        # Cắt bỏ mọi ký tự phân cách shell nguy hiểm (; | & ` $ < > ' ") và khoảng trắng
        cleaned = re.split(r"[;\s|&`$<>'\"\\]", str(target).strip())[0]
        if is_ip:
            # Chỉ cho phép ký tự hợp lệ cho IPv4 / IPv6 / CIDR
            return re.sub(r"[^\w\.\:\/]", "", cleaned)
        # Loại bỏ các ký tự shell / powershell nguy hiểm
        return re.sub(r"[^\w\.\-\@\:]", "", cleaned)

    @classmethod
    def create_bundle(
        cls,
        action_id: Any,
        action_type: Any = None,
        target: str = "",
        phase: IncidentPhase = IncidentPhase.CONTAINMENT,
    ) -> ActionScriptBundle:
        """Sinh ActionScriptBundle hoàn chỉnh chứa cả kịch bản can thiệp và kịch bản hoàn tác (Rollback)."""
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
        # Làm sạch target chống Command / Script Injection
        is_ip_action = (action_type == ActionType.BLOCK_IP)
        target = cls._sanitize_target(actual_target, is_ip=is_ip_action)
        action_id = actual_action_id

        ps_script: Optional[str] = None
        bash_script: Optional[str] = None
        wazuh_ar: Optional[Dict[str, Any]] = None
        rollback_script: Optional[str] = None
        instructions = f"Thực thi hoặc hoàn tác cho {action_type.value} trên mục tiêu {target}."
        is_critical = False
        warning_msg: Optional[str] = None
        evidence_snapshot_included = False

        # Lệnh thu thập chứng cứ Pre-response Snapshot (mạng & tiến trình) vào data/evidence/
        # Lưu ý: Tuyệt đối không dùng ký tự pipe '|' trong PowerShell để đảm bảo tính an toàn chống injection
        ps_evidence_cmd = (
            "New-Item -ItemType Directory -Force -Path 'data/evidence'; "
            "Get-NetTCPConnection -ErrorAction SilentlyContinue > data/evidence/network_connections.txt; "
            "Get-Process -ErrorAction SilentlyContinue > data/evidence/process_snapshot.txt;"
        )
        bash_evidence_cmd = (
            "mkdir -p data/evidence && "
            "ss -tlpn > data/evidence/network_connections.txt && "
            "ps aux > data/evidence/process_snapshot.txt;"
        )

        if action_type == ActionType.ISOLATE_HOST:
            evidence_snapshot_included = True
            ps_script = (
                f"{ps_evidence_cmd} "
                "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; "
                "New-NetFirewallRule -DisplayName 'BlockAllExceptWazuh' -Direction Outbound -Action Block"
            )
            rollback_script = "Remove-NetFirewallRule -DisplayName 'BlockAllExceptWazuh'; Enable-NetAdapter -Name * -Confirm:$false"
            bash_script = (
                f"{bash_evidence_cmd} "
                "iptables -A OUTPUT -p tcp ! --dport 1514 -j DROP; "
                "iptables -A INPUT -p tcp ! --sport 1514 -j DROP"
            )
            wazuh_ar = {"command": "host-isolate", "target": target}
            instructions = (
                f"Cô lập máy trạm {target} khỏi mạng nội bộ (giữ kết nối Wazuh Manager). "
                f"Đã kích hoạt Pre-response Snapshot bảo toàn chứng cứ số vào data/evidence/. "
                f"Rollback: gỡ luật cách ly và mở lại card mạng."
            )

        elif action_type == ActionType.BLOCK_IP:
            ps_script = f"New-NetFirewallRule -DisplayName 'Block_{target}' -Direction Inbound -Action Block -RemoteAddress {target}"
            rollback_script = f"Remove-NetFirewallRule -DisplayName 'Block_{target}'"
            bash_script = f"iptables -I INPUT -s {target} -j DROP; iptables -I FORWARD -s {target} -j DROP"
            wazuh_ar = {"command": "firewall-drop", "target": target}
            instructions = f"Chặn địa chỉ IP độc hại {target} trên Firewall. Rollback: xóa luật chặn iptables/Windows Firewall."

        elif action_type == ActionType.KILL_PROCESS:
            evidence_snapshot_included = True
            if cls.is_critical_system_process(target):
                is_critical = True
                warning_msg = (
                    f"CẢNH BÁO NGUYÊM TRỌNG: Tiến trình '{target}' là tiến trình hệ thống trọng yếu (CRITICAL_SYSTEM_PROCESSES). "
                    f"Tiêu diệt tiến trình này có thể gây sập hệ điều hành (BSOD/Kernel Panic). "
                    f"Kịch bản đã tự động đề xuất chuyển sang cô lập máy trạm (ISOLATE_HOST) và bảo toàn chứng cứ số thay vì tiêu diệt."
                )
                instructions = warning_msg
                ps_script = (
                    f"{ps_evidence_cmd} "
                    f"Write-Warning 'CẢNH BÁO NGUYÊM TRỌNG: Không tiêu diệt tiến trình hệ thống {target}. Đề xuất cô lập máy trạm:'; "
                    "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; "
                    "New-NetFirewallRule -DisplayName 'BlockAllExceptWazuh' -Direction Outbound -Action Block"
                )
                bash_script = (
                    f"{bash_evidence_cmd} "
                    f"echo 'CẢNH BÁO NGUYÊM TRỌNG: Không tiêu diệt tiến trình hệ thống {target}. Đề xuất cô lập:'; "
                    "iptables -A OUTPUT -p tcp ! --dport 1514 -j DROP; "
                    "iptables -A INPUT -p tcp ! --sport 1514 -j DROP"
                )
                wazuh_ar = {"command": "host-isolate", "target": target, "warning": "critical_system_process"}
                rollback_script = "Remove-NetFirewallRule -DisplayName 'BlockAllExceptWazuh'; Enable-NetAdapter -Name * -Confirm:$false"
            else:
                ps_script = f"{ps_evidence_cmd} Stop-Process -Name '{target}' -Force -ErrorAction SilentlyContinue"
                bash_script = f"{bash_evidence_cmd} pkill -9 -f '{target}'"
                wazuh_ar = {"command": "kill-process", "target": target}
                rollback_script = None  # Tiến trình bị tiêu diệt không thể hoàn tác trực tiếp
                instructions = (
                    f"Tiêu diệt tiến trình độc hại {target}. "
                    f"Đã kích hoạt Pre-response Snapshot bảo toàn chứng cứ mạng và tiến trình vào data/evidence/. "
                    f"Lưu ý: Hành động này không thể hoàn tác tự động (Irreversible)."
                )

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
            is_critical_process=is_critical,
            warning_message=warning_msg,
            evidence_snapshot_included=evidence_snapshot_included,
        )

    @classmethod
    def malware_incident_playbook(cls, host_name: str, malicious_ip: str, process_name: str) -> List[RecommendedAction]:
        """Playbook xử lý sự cố mã độc trên máy trạm (Endpoint Malware) có đính kèm kịch bản hoàn tác."""
        act_isolate_id = "ACT-MALW-ISOLATE"
        act_kill_id = "ACT-MALW-KILL"
        act_block_id = "ACT-MALW-BLOCK"

        is_crit = cls.is_critical_system_process(process_name)
        kill_desc = (
            f"CẢNH BÁO: Tiến trình {process_name} là tiến trình hệ thống trọng yếu. Đề xuất cô lập máy trạm thay vì tiêu diệt."
            if is_crit
            else f"Tiêu diệt tiến trình độc hại {process_name} đang chạy trên máy trạm."
        )

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
                description=kill_desc,
                priority=1 if is_crit else 2,
                require_human_approval=True if is_crit else False,
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

    @classmethod
    def web_attack_playbook(
        cls,
        host_name: str,
        attacker_ip: str,
        web_process: Optional[str] = None,
    ) -> List[RecommendedAction]:
        """Playbook xử lý tấn công ứng dụng Web (SQLi, XSS, Web Shell, RCE) theo chuẩn NIST SP 800-61."""
        act_block_id = "ACT-WEB-BLOCK"
        act_kill_id = "ACT-WEB-KILL"
        act_patch_id = "ACT-WEB-PATCH"

        actions: List[RecommendedAction] = [
            RecommendedAction(
                action_id=act_block_id,
                action_type=ActionType.BLOCK_IP,
                target=attacker_ip,
                description=f"Chặn địa chỉ IP tấn công Web {attacker_ip} trên WAF/Firewall biên.",
                priority=1,
                require_human_approval=True,
                phase=IncidentPhase.CONTAINMENT,
                script_bundle=cls.create_bundle(act_block_id, ActionType.BLOCK_IP, attacker_ip, IncidentPhase.CONTAINMENT),
            )
        ]

        malicious_shells = {"cmd.exe", "powershell.exe", "bash", "sh", "nc", "php-cgi", "cmd", "powershell", "pwsh", "nc.exe", "netcat"}
        if web_process:
            proc_clean = web_process.strip().lower().split("/")[-1].split("\\")[-1]
            if proc_clean in malicious_shells:
                actions.append(
                    RecommendedAction(
                        action_id=act_kill_id,
                        action_type=ActionType.KILL_PROCESS,
                        target=web_process,
                        description=f"Tiêu diệt tiến trình shell độc hại {web_process} sinh ra từ dịch vụ Web trên {host_name}.",
                        priority=2,
                        require_human_approval=False,
                        phase=IncidentPhase.ERADICATION,
                        script_bundle=cls.create_bundle(act_kill_id, ActionType.KILL_PROCESS, web_process, IncidentPhase.ERADICATION),
                    )
                )

        actions.append(
            RecommendedAction(
                action_id=act_patch_id,
                action_type=ActionType.PATCH_SYSTEM,
                target=host_name,
                description=f"Vá lỗ hổng ứng dụng Web (SQLi/RCE/XSS) và rà soát Web Shell trên máy chủ {host_name}.",
                priority=3,
                require_human_approval=False,
                phase=IncidentPhase.RECOVERY,
                script_bundle=cls.create_bundle(act_patch_id, ActionType.PATCH_SYSTEM, host_name, IncidentPhase.RECOVERY),
            )
        )
        return actions

    @classmethod
    def reconnaissance_playbook(
        cls,
        attacker_ip: str,
        target_host: Optional[str] = None,
    ) -> List[RecommendedAction]:
        """Playbook xử lý sự cố dò quét mạng (Reconnaissance / Port Scan / SYN Scan / ICMP Sweep) theo chuẩn NIST SP 800-61."""
        act_block_id = "ACT-RECON-BLOCK"
        act_harden_id = "ACT-RECON-HARDEN"

        actions: List[RecommendedAction] = [
            RecommendedAction(
                action_id=act_block_id,
                action_type=ActionType.BLOCK_IP,
                target=attacker_ip,
                description=f"Chặn địa chỉ IP {attacker_ip} thực hiện dò quét cổng / SYN scan / ICMP sweep trên Firewall.",
                priority=1,
                require_human_approval=True,
                phase=IncidentPhase.CONTAINMENT,
                script_bundle=cls.create_bundle(act_block_id, ActionType.BLOCK_IP, attacker_ip, IncidentPhase.CONTAINMENT),
            )
        ]

        if target_host:
            actions.append(
                RecommendedAction(
                    action_id=act_harden_id,
                    action_type=ActionType.PATCH_SYSTEM,
                    target=target_host,
                    description=f"Đóng các cổng dịch vụ không cần thiết và rà soát cấu hình Firewall trên {target_host}.",
                    priority=3,
                    require_human_approval=False,
                    phase=IncidentPhase.RECOVERY,
                    script_bundle=cls.create_bundle(act_harden_id, ActionType.PATCH_SYSTEM, target_host, IncidentPhase.RECOVERY),
                )
            )

        return actions

    @classmethod
    def privilege_escalation_playbook(
        cls,
        host_name: str,
        compromised_user: Optional[str] = None,
        rogue_process: Optional[str] = None,
    ) -> List[RecommendedAction]:
        """Playbook xử lý sự cố leo thang đặc quyền (Privilege Escalation) theo chuẩn NIST SP 800-61."""
        act_revoke_id = "ACT-PRIVESC-REVOKE"
        act_kill_id = "ACT-PRIVESC-KILL"
        act_reset_id = "ACT-PRIVESC-RESET"
        act_patch_id = "ACT-PRIVESC-PATCH"

        actions: List[RecommendedAction] = []

        if compromised_user:
            actions.append(
                RecommendedAction(
                    action_id=act_revoke_id,
                    action_type=ActionType.REVOKE_USER,
                    target=compromised_user,
                    description=f"Thu hồi khẩn cấp toàn bộ phiên làm việc của tài khoản leo quyền {compromised_user}.",
                    priority=1,
                    require_human_approval=False,
                    phase=IncidentPhase.CONTAINMENT,
                    script_bundle=cls.create_bundle(act_revoke_id, ActionType.REVOKE_USER, compromised_user, IncidentPhase.CONTAINMENT),
                )
            )

        if rogue_process:
            is_crit = cls.is_critical_system_process(rogue_process)
            actions.append(
                RecommendedAction(
                    action_id=act_kill_id,
                    action_type=ActionType.KILL_PROCESS,
                    target=rogue_process,
                    description=(
                        f"CẢNH BÁO: Tiến trình {rogue_process} là tiến trình hệ thống trọng yếu. Đề xuất cô lập thay vì tiêu diệt."
                        if is_crit
                        else f"Tiêu diệt tiến trình leo thang đặc quyền {rogue_process} trên {host_name}."
                    ),
                    priority=1,
                    require_human_approval=True if is_crit else False,
                    phase=IncidentPhase.CONTAINMENT,
                    script_bundle=cls.create_bundle(act_kill_id, ActionType.KILL_PROCESS, rogue_process, IncidentPhase.CONTAINMENT),
                )
            )

        if compromised_user:
            actions.append(
                RecommendedAction(
                    action_id=act_reset_id,
                    action_type=ActionType.RESET_PASSWORD,
                    target=compromised_user,
                    description=f"Đặt lại mật khẩu và thu hồi quyền sudo/admin trái phép của tài khoản {compromised_user}.",
                    priority=2,
                    require_human_approval=True,
                    phase=IncidentPhase.ERADICATION,
                    script_bundle=cls.create_bundle(act_reset_id, ActionType.RESET_PASSWORD, compromised_user, IncidentPhase.ERADICATION),
                )
            )

        actions.append(
            RecommendedAction(
                action_id=act_patch_id,
                action_type=ActionType.PATCH_SYSTEM,
                target=host_name,
                description=f"Vá lỗ hổng leo thang đặc quyền và kiểm toán cấu hình phân quyền trên {host_name}.",
                priority=3,
                require_human_approval=False,
                phase=IncidentPhase.RECOVERY,
                script_bundle=cls.create_bundle(act_patch_id, ActionType.PATCH_SYSTEM, host_name, IncidentPhase.RECOVERY),
            )
        )
        return actions

    @classmethod
    def ransomware_incident_playbook(
        cls,
        host_name: str,
        process_name: Optional[str] = None,
        c2_ip: Optional[str] = None,
        compromised_user: Optional[str] = None,
    ) -> List[RecommendedAction]:
        """Playbook xử lý sự cố mã độc tống tiền (Ransomware) theo chuẩn NIST SP 800-61."""
        act_isolate_id = "ACT-RANSOM-ISOLATE"
        act_kill_id = "ACT-RANSOM-KILL"
        act_block_id = "ACT-RANSOM-BLOCK"
        act_revoke_id = "ACT-RANSOM-REVOKE"
        act_recover_id = "ACT-RANSOM-RECOVER"

        actions: List[RecommendedAction] = [
            RecommendedAction(
                action_id=act_isolate_id,
                action_type=ActionType.ISOLATE_HOST,
                target=host_name,
                description=f"Cô lập khẩn cấp máy trạm/máy chủ {host_name} để chặn đứng mã hóa dữ liệu lan rộng qua SMB/Network.",
                priority=1,
                require_human_approval=True,
                phase=IncidentPhase.CONTAINMENT,
                script_bundle=cls.create_bundle(act_isolate_id, ActionType.ISOLATE_HOST, host_name, IncidentPhase.CONTAINMENT),
            )
        ]

        if process_name:
            is_crit = cls.is_critical_system_process(process_name)
            actions.append(
                RecommendedAction(
                    action_id=act_kill_id,
                    action_type=ActionType.KILL_PROCESS,
                    target=process_name,
                    description=(
                        f"CẢNH BÁO: Tiến trình {process_name} là tiến trình hệ thống trọng yếu. Đề xuất cô lập thay vì tiêu diệt."
                        if is_crit
                        else f"Tiêu diệt tức thì tiến trình mã hóa / xóa Shadow Copy {process_name} trên {host_name}."
                    ),
                    priority=1,
                    require_human_approval=True if is_crit else False,
                    phase=IncidentPhase.CONTAINMENT,
                    script_bundle=cls.create_bundle(act_kill_id, ActionType.KILL_PROCESS, process_name, IncidentPhase.CONTAINMENT),
                )
            )

        if c2_ip:
            actions.append(
                RecommendedAction(
                    action_id=act_block_id,
                    action_type=ActionType.BLOCK_IP,
                    target=c2_ip,
                    description=f"Chặn địa chỉ IP máy chủ C2 trao đổi khóa mã hóa {c2_ip} trên Firewall.",
                    priority=1,
                    require_human_approval=True,
                    phase=IncidentPhase.CONTAINMENT,
                    script_bundle=cls.create_bundle(act_block_id, ActionType.BLOCK_IP, c2_ip, IncidentPhase.CONTAINMENT),
                )
            )

        if compromised_user:
            actions.append(
                RecommendedAction(
                    action_id=act_revoke_id,
                    action_type=ActionType.REVOKE_USER,
                    target=compromised_user,
                    description=f"Thu hồi toàn bộ phiên đăng nhập của tài khoản {compromised_user} nhằm ngăn lây lan Ransomware.",
                    priority=1,
                    require_human_approval=False,
                    phase=IncidentPhase.CONTAINMENT,
                    script_bundle=cls.create_bundle(act_revoke_id, ActionType.REVOKE_USER, compromised_user, IncidentPhase.CONTAINMENT),
                )
            )

        actions.append(
            RecommendedAction(
                action_id=act_recover_id,
                action_type=ActionType.PATCH_SYSTEM,
                target=host_name,
                description=f"Khôi phục dữ liệu từ bản sao lưu sạch (Offline Backup) và vá hệ thống trên {host_name}.",
                priority=3,
                require_human_approval=False,
                phase=IncidentPhase.RECOVERY,
                script_bundle=cls.create_bundle(act_recover_id, ActionType.PATCH_SYSTEM, host_name, IncidentPhase.RECOVERY),
            )
        )
        return actions


# Alias tiện ích cấp module phục vụ kiểm thử và gọi nhanh
create_bundle = ResponsePlaybooks.create_bundle


