# -*- coding: utf-8 -*-
"""
src/tools/playbooks.py
Kịch bản phản ứng mẫu (Response Playbooks) theo chuẩn NIST SP 800-61.
Cung cấp các hành động chuẩn hóa cho Response Recommendation Agent.
"""

from typing import List
from src.core.schemas import RecommendedAction, ActionType


class ResponsePlaybooks:
    """Tập hợp Playbooks ứng phó sự cố theo từng loại sự cố."""

    @staticmethod
    def malware_incident_playbook(host_name: str, malicious_ip: str, process_name: str) -> List[RecommendedAction]:
        """Playbook xử lý sự cố mã độc trên máy trạm (Endpoint Malware)."""
        return [
            RecommendedAction(
                action_type=ActionType.ISOLATE_HOST,
                target=host_name,
                description=f"Cô lập máy trạm {host_name} khỏi mạng nội bộ để ngăn chặn lây lan.",
                priority=1,
                require_human_approval=True
            ),
            RecommendedAction(
                action_type=ActionType.KILL_PROCESS,
                target=process_name,
                description=f"Tiêu diệt tiến trình độc hại {process_name} đang chạy trên máy trạm.",
                priority=2,
                require_human_approval=False
            ),
            RecommendedAction(
                action_type=ActionType.BLOCK_IP,
                target=malicious_ip,
                description=f"Chặn địa chỉ IP C2 {malicious_ip} trên Firewall và Web Proxy.",
                priority=1,
                require_human_approval=True
            )
        ]

    @staticmethod
    def phishing_credential_playbook(compromised_user: str, phishing_ip: str) -> List[RecommendedAction]:
        """Playbook xử lý sự cố lừa đảo đánh cắp danh tính (Phishing & Credential Compromise)."""
        return [
            RecommendedAction(
                action_type=ActionType.REVOKE_USER,
                target=compromised_user,
                description=f"Thu hồi toàn bộ phiên đăng nhập đang hoạt động của người dùng {compromised_user}.",
                priority=1,
                require_human_approval=False
            ),
            RecommendedAction(
                action_type=ActionType.RESET_PASSWORD,
                target=compromised_user,
                description=f"Buộc đặt lại mật khẩu và cấu hình lại xác thực đa yếu tố (MFA) cho {compromised_user}.",
                priority=2,
                require_human_approval=True
            ),
            RecommendedAction(
                action_type=ActionType.BLOCK_IP,
                target=phishing_ip,
                description=f"Chặn IP lạ {phishing_ip} đã sử dụng tài khoản đăng nhập trái phép.",
                priority=1,
                require_human_approval=True
            )
        ]
