# -*- coding: utf-8 -*-
"""
src/core/rbac.py
Module phân quyền RBAC (Role-Based Access Control) và bảo vệ tiến trình hệ thống trọng yếu
(Protected OS Process Whitelist Guard) thuần Python (KHÔNG phụ thuộc Streamlit).
Dùng chung cho SOC Dashboard UI, SOC Copilot Engine, HITL Manager và Webhook API.
"""

import os
import re
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from src.core.schemas import ActionType

# =====================================================================
# 1. VAI TRÒ VẬN HÀNH & HẰNG SỐ PHÂN QUYỀN (ALIGNED WITH UI & HITL)
# =====================================================================
ROLE_SOC_ANALYST = "SOC Analyst (Tier 1/2)"
ROLE_TIER1 = ROLE_SOC_ANALYST
ROLE_SOC_MANAGER = "SOC Manager (Incident Commander)"
USER_ROLES: List[str] = [ROLE_SOC_ANALYST, ROLE_SOC_MANAGER]

HIGH_RISK_ACTION_TYPES: FrozenSet[str] = frozenset({"ISOLATE_HOST", "KILL_PROCESS"})
LOW_MEDIUM_ACTION_TYPES: FrozenSet[str] = frozenset(
    {"BLOCK_IP", "REVOKE_USER", "RESET_PASSWORD", "PATCH_SYSTEM", "WAZUH_ACTIVE_RESPONSE"}
)

DANGEROUS_ACTIONS: Set[Any] = {
    ActionType.ISOLATE_HOST,
    ActionType.KILL_PROCESS,
    "ISOLATE_HOST",
    "KILL_PROCESS",
}

PROTECTED_PROCESSES: FrozenSet[str] = frozenset(
    {
        "svchost.exe",
        "lsass.exe",
        "explorer.exe",
        "csrss.exe",
        "smss.exe",
        "services.exe",
        "wininit.exe",
        "winlogon.exe",
        "spoolsv.exe",
        "system",
    }
)
# Alias tương thích ngược với src/ui/components.py
SYSTEM_CRITICAL_PROCESSES: Set[str] = set(PROTECTED_PROCESSES)

# Ma trận phân quyền chuẩn theo vai trò
PERMISSION_MATRIX: Dict[str, FrozenSet[str]] = {
    ROLE_SOC_ANALYST: frozenset(
        {
            "VIEW_INCIDENT",
            "INVESTIGATE",
            "REJECT_ACTION",
            "EDIT_ACTION",
            "APPROVE_LOW_RISK",
            "BLOCK_IP",
            "REVOKE_USER",
            "RESET_PASSWORD",
            "PATCH_SYSTEM",
            "WAZUH_ACTIVE_RESPONSE",
        }
    ),
    ROLE_SOC_MANAGER: frozenset(
        {
            "VIEW_INCIDENT",
            "INVESTIGATE",
            "REJECT_ACTION",
            "EDIT_ACTION",
            "APPROVE_LOW_RISK",
            "APPROVE_HIGH_RISK",
            "APPROVE_ALL",
            "ROLLBACK_ACTION",
            "BLOCK_IP",
            "REVOKE_USER",
            "RESET_PASSWORD",
            "PATCH_SYSTEM",
            "WAZUH_ACTIVE_RESPONSE",
            "ISOLATE_HOST",
            "KILL_PROCESS",
        }
    ),
}

_PROTECTED_EXE_NAMES: Tuple[str, ...] = tuple(
    p for p in sorted(PROTECTED_PROCESSES) if p.endswith(".exe")
)


# =====================================================================
# 2. CHUẨN HÓA VAI TRÒ & KIỂM TRA HÀNH ĐỘNG / TIẾN TRÌNH
# =====================================================================
def normalize_role(user_role: Optional[str]) -> Optional[str]:
    """Chuẩn hóa chuỗi vai trò về ROLE_SOC_MANAGER hoặc ROLE_SOC_ANALYST (fail-closed)."""
    if user_role is None:
        return None
    role_str = str(user_role).strip().lower()
    if not role_str:
        return ROLE_SOC_ANALYST
    if any(tok in role_str for tok in ("manager", "commander", "incident_commander", "admin")):
        return ROLE_SOC_MANAGER
    return ROLE_SOC_ANALYST


def extract_action_type_str(action: Any) -> str:
    """Trích xuất tên loại hành động dạng chữ hoa từ RecommendedAction, ActionType hoặc str."""
    if action is None:
        return ""
    act_type = getattr(action, "action_type", action)
    val = act_type.value if hasattr(act_type, "value") else str(act_type or "")
    return str(val).strip().upper()


def is_dangerous_action(action: Any) -> bool:
    """Xác định hành động có thuộc danh mục rủi ro cao (ISOLATE_HOST, KILL_PROCESS) hay không."""
    return extract_action_type_str(action) in HIGH_RISK_ACTION_TYPES


def is_protected_process(target: Optional[str]) -> bool:
    """Kiểm tra mục tiêu có phải tiến trình hệ thống trọng yếu cần bảo vệ hay không."""
    if not target:
        return False
    target_clean = str(target).strip().lower()
    if not target_clean:
        return False

    norm_name = os.path.basename(target_clean.replace("\\", "/")).strip("'\" ")
    if norm_name in PROTECTED_PROCESSES or f"{norm_name}.exe" in PROTECTED_PROCESSES:
        return True

    for proc in _PROTECTED_EXE_NAMES:
        if re.search(rf"(?<![a-z0-9_]){re.escape(proc)}(?![a-z0-9_])", target_clean):
            return True

    if re.fullmatch(r"(?:pid\s*[:=]?\s*)?system(?:\.exe)?", target_clean):
        return True

    return False


# Alias tương thích ngược với src/ui/components.py
is_critical_system_process = is_protected_process


# =====================================================================
# 3. KIỂM TRA QUYỀN & TẠO PAYLOAD TỪ CHỐI CHUẨN HÓA
# =====================================================================
def has_permission(
    user_role: Optional[str],
    permission: str,
    allow_unset_role: bool = False,
) -> bool:
    """Kiểm tra vai trò có quyền thực hiện `permission` theo PERMISSION_MATRIX hay không."""
    if user_role is None:
        if allow_unset_role:
            return True
        effective_role = ROLE_SOC_ANALYST
    else:
        effective_role = normalize_role(user_role) or ROLE_SOC_ANALYST

    perm_key = str(permission or "").strip().upper()
    if not perm_key:
        return False
    return perm_key in PERMISSION_MATRIX.get(effective_role, frozenset())


def can_user_approve_action(user_role: Optional[str], action: Any) -> bool:
    """Kiểm tra quyền phê duyệt hành động theo Simple RBAC.

    - Giữ tương thích ngược với caller nội bộ/unit test cũ khi `user_role is None`.
    - Chuỗi rỗng hoặc vai trò Tier 1/2 bị khóa đối với ISOLATE_HOST & KILL_PROCESS.
    """
    if user_role is None:
        return True
    effective_role = normalize_role(user_role) or ROLE_SOC_ANALYST
    if effective_role == ROLE_SOC_MANAGER:
        return True
    if is_dangerous_action(action):
        return False
    return True


def get_action_rbac_warning(user_role: Optional[str], action: Any) -> Optional[str]:
    """Trả về cảnh báo nghiệp vụ nếu vai trò người dùng không đủ quyền phê duyệt hành động."""
    if not can_user_approve_action(user_role, action):
        return "⚠️ Yêu cầu vai trò SOC Manager để phê duyệt hành động có rủi ro cao (Cô lập máy / Diệt tiến trình)"
    return None


def get_whitelist_guard_warning(target: Optional[str]) -> Optional[str]:
    """Trả về cảnh báo Process Whitelist Guard nếu mục tiêu là tiến trình hệ thống trọng yếu."""
    if is_protected_process(target):
        return (
            f"🛡️ Process Whitelist Guard: Cảnh báo: Mục tiêu '{target}' là tiến trình hệ thống quan trọng "
            "(như svchost.exe, lsass.exe, explorer.exe). "
            "Can thiệp hoặc diệt tiến trình này có thể gây mất ổn định hoặc sập hệ điều hành (BSOD / System Crash)!"
        )
    return None


def check_action_permission(
    user_role: Optional[str],
    action: Any,
    target: Optional[str] = None,
    allow_unset_role: bool = False,
) -> Dict[str, Any]:
    """Đánh giá chi tiết quyền thực thi và cảnh báo an toàn cho một hành động."""
    effective_role = (
        None if (user_role is None and allow_unset_role) else (normalize_role(user_role) or ROLE_SOC_ANALYST)
    )
    act_type_str = extract_action_type_str(action)
    effective_target = target if target is not None else getattr(action, "target", None)
    dangerous = act_type_str in HIGH_RISK_ACTION_TYPES
    protected = is_protected_process(effective_target)

    if user_role is None and allow_unset_role:
        allowed = True
    else:
        allowed = (effective_role == ROLE_SOC_MANAGER) or (not dangerous)

    required_role = ROLE_SOC_MANAGER if dangerous else ROLE_SOC_ANALYST
    warning = (
        None
        if allowed
        else "⚠️ Yêu cầu vai trò SOC Manager để phê duyệt hành động có rủi ro cao (Cô lập máy / Diệt tiến trình)"
    )

    return {
        "allowed": allowed,
        "user_role": effective_role,
        "action_type": act_type_str,
        "target": effective_target,
        "is_dangerous": dangerous,
        "is_protected_process": protected,
        "required_role": required_role,
        "warning": warning,
        "whitelist_warning": get_whitelist_guard_warning(effective_target) if protected else None,
    }


def build_rbac_denied_payload(
    action_type: str = "APPROVE_ACTION",
    target: Optional[str] = None,
    blocked_action_ids: Optional[List[str]] = None,
    allowed_action_ids: Optional[List[str]] = None,
    message: Optional[str] = None,
    user_role: Optional[str] = None,
    required_role: str = ROLE_SOC_MANAGER,
    is_protected: bool = False,
) -> Dict[str, Any]:
    """Tạo payload từ chối RBAC chuẩn hóa dùng chung cho Copilot, UI và API."""
    blocked_ids = list(blocked_action_ids or [])
    allowed_ids = list(allowed_action_ids or [])
    default_msg = (
        f"⛔ Từ chối quyền (RBAC): Vai trò '{user_role or ROLE_SOC_ANALYST}' không được phép phê duyệt "
        f"hành động rủi ro cao ({action_type}). Yêu cầu vai trò '{required_role}'."
    )
    if blocked_ids:
        default_msg += f" Hành động bị chặn: {', '.join(blocked_ids)}."

    return {
        "allowed": False,
        "type": "RBAC_DENIED",
        "rbac_denied": True,
        "blocked": True,
        "status": "RBAC_DENIED",
        "user_role": user_role,
        "action_type": action_type,
        "target": target,
        "required_role": required_role,
        "blocked_action_ids": blocked_ids,
        "allowed_action_ids": allowed_ids,
        "is_protected_process": is_protected,
        "message": message or default_msg,
    }


def enforce_hitl_rbac(
    user_role: Optional[str],
    action_type: Any = None,
    target: Optional[str] = None,
    action_ids: Optional[List[str]] = None,
    *,
    actions: Optional[List[Any]] = None,
    allow_unset_role: bool = False,
) -> Dict[str, Any]:
    """Kiểm tra và cưỡng chế RBAC chuẩn hóa (Fail-Closed / Atomic Deny cho batch).

    - Khi truyền `actions` (ví dụ `APPROVE_ALL`), kiểm tra toàn bộ danh sách hành động:
      nếu có bất kỳ hành động rủi ro cao nào bị chặn, trả về payload `RBAC_DENIED`
      kèm `blocked_action_ids` và `allowed_action_ids`.
    - Khi truyền `action_type` đơn lẻ, kiểm tra hành động đó và trả về payload chuẩn.
    """
    effective_role = (
        None if (user_role is None and allow_unset_role) else (normalize_role(user_role) or ROLE_SOC_ANALYST)
    )

    if actions is not None:
        blocked_ids: List[str] = []
        allowed_ids: List[str] = []
        first_blocked_type: Optional[str] = None
        first_blocked_target: Optional[str] = None
        any_protected = False

        for idx, act in enumerate(actions):
            aid = getattr(act, "action_id", None) or f"ACT-{idx + 1:03d}"
            perm = check_action_permission(
                user_role,
                act,
                allow_unset_role=allow_unset_role,
            )
            if perm["is_protected_process"]:
                any_protected = True
            if perm["allowed"]:
                allowed_ids.append(aid)
            else:
                blocked_ids.append(aid)
                if first_blocked_type is None:
                    first_blocked_type = perm["action_type"]
                    first_blocked_target = perm["target"]

        if blocked_ids:
            return build_rbac_denied_payload(
                action_type=first_blocked_type or extract_action_type_str(action_type) or "APPROVE_ALL",
                target=target or first_blocked_target,
                blocked_action_ids=blocked_ids,
                allowed_action_ids=allowed_ids,
                user_role=effective_role,
                required_role=ROLE_SOC_MANAGER,
                is_protected=any_protected,
            )

        return {
            "allowed": True,
            "type": "RBAC_ALLOWED",
            "rbac_denied": False,
            "blocked": False,
            "status": "ALLOWED",
            "user_role": effective_role,
            "action_type": extract_action_type_str(action_type) or "APPROVE_ALL",
            "target": target,
            "required_role": ROLE_SOC_ANALYST,
            "blocked_action_ids": [],
            "allowed_action_ids": allowed_ids,
            "is_protected_process": any_protected,
            "message": "Được phép thực thi theo chính sách RBAC.",
        }

    perm = check_action_permission(
        user_role,
        action_type,
        target=target,
        allow_unset_role=allow_unset_role,
    )
    resolved_ids = (
        list(action_ids)
        if action_ids is not None
        else ([getattr(action_type, "action_id")] if getattr(action_type, "action_id", None) else [])
    )

    if not perm["allowed"]:
        return build_rbac_denied_payload(
            action_type=perm["action_type"] or "APPROVE_ACTION",
            target=perm["target"],
            blocked_action_ids=resolved_ids,
            allowed_action_ids=[],
            user_role=effective_role,
            required_role=perm["required_role"],
            is_protected=perm["is_protected_process"],
        )

    return {
        "allowed": True,
        "type": "RBAC_ALLOWED",
        "rbac_denied": False,
        "blocked": False,
        "status": "ALLOWED",
        "user_role": effective_role,
        "action_type": perm["action_type"],
        "target": perm["target"],
        "required_role": perm["required_role"],
        "blocked_action_ids": [],
        "allowed_action_ids": resolved_ids,
        "is_protected_process": perm["is_protected_process"],
        "message": "Được phép thực thi theo chính sách RBAC.",
    }


__all__ = [
    "ROLE_SOC_ANALYST",
    "ROLE_TIER1",
    "ROLE_SOC_MANAGER",
    "USER_ROLES",
    "HIGH_RISK_ACTION_TYPES",
    "LOW_MEDIUM_ACTION_TYPES",
    "DANGEROUS_ACTIONS",
    "PROTECTED_PROCESSES",
    "SYSTEM_CRITICAL_PROCESSES",
    "PERMISSION_MATRIX",
    "normalize_role",
    "extract_action_type_str",
    "is_dangerous_action",
    "is_protected_process",
    "is_critical_system_process",
    "has_permission",
    "can_user_approve_action",
    "check_action_permission",
    "get_action_rbac_warning",
    "get_whitelist_guard_warning",
    "build_rbac_denied_payload",
    "enforce_hitl_rbac",
]
