# -*- coding: utf-8 -*-
"""
src/core/schemas.py
Bộ Schema Input/Output chuẩn hóa cho Hệ thống Multi-Agent điều tra sự cố an ninh mạng.
Được thiết kế dựa trên Pydantic v2 nhằm đảm bảo Type Safety, Validation nghiêm ngặt
và tương thích hoàn toàn với LangGraph StateGraph.
"""

from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    CLOSED_FALSE_POSITIVE = "CLOSED_FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class ActionType(str, Enum):
    ISOLATE_HOST = "ISOLATE_HOST"
    BLOCK_IP = "BLOCK_IP"
    KILL_PROCESS = "KILL_PROCESS"
    REVOKE_USER = "REVOKE_USER"
    RESET_PASSWORD = "RESET_PASSWORD"
    PATCH_SYSTEM = "PATCH_SYSTEM"


# =====================================================================
# 1. SCHEMAS CHO DATA INGESTION AGENT
# =====================================================================
class RawLogInput(BaseModel):
    """Mô hình dữ liệu log thô đầu vào trước khi tiền xử lý."""
    log_source: str = Field(..., description="Nguồn log: Sysmon, Zeek, EVTX, Firewall, EDR")
    raw_payload: str = Field(..., description="Dữ liệu thô (chuỗi JSON, XML, Syslog line)")
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Thời điểm tiếp nhận log")


class ParsedEvent(BaseModel):
    """Sự kiện log đã được bóc tách và chuẩn hóa các trường thông tin."""
    event_id: str = Field(..., description="ID sự kiện (ví dụ: Sysmon 1, EVTX 4624)")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Thời gian xảy ra sự kiện")
    source_type: str = Field(..., description="Loại log: Sysmon, Zeek, WindowsSecurity")
    host_name: Optional[str] = Field(None, description="Tên máy trạm / máy chủ ghi nhận")
    user_name: Optional[str] = Field(None, description="Tài khoản người dùng liên quan")
    process_name: Optional[str] = Field(None, description="Tên tiến trình (ví dụ: powershell.exe)")
    process_path: Optional[str] = Field(None, description="Đường dẫn file thực thi")
    command_line: Optional[str] = Field(None, description="Toàn bộ câu lệnh thực thi kèm tham số")
    parent_process: Optional[str] = Field(None, description="Tiến trình cha (Parent Process)")
    parent_command_line: Optional[str] = Field(None, description="Câu lệnh tiến trình cha")
    source_ip: Optional[str] = Field(None, description="Địa chỉ IP nguồn")
    source_port: Optional[int] = Field(None, description="Cổng nguồn")
    dest_ip: Optional[str] = Field(None, description="Địa chỉ IP đích")
    dest_port: Optional[int] = Field(None, description="Cổng đích")
    file_hash: Optional[str] = Field(None, description="Hash tệp tin (MD5, SHA256)")
    raw_attributes: Dict[str, Any] = Field(default_factory=dict, description="Các thuộc tính mở rộng khác")


# =====================================================================
# 2. SCHEMAS CHO DETECTION & TRIAGE AGENT
# =====================================================================
class TriageOutput(BaseModel):
    """Kết quả phân loại và đánh giá rủi ro sơ bộ từ Triage Agent."""
    is_incident: bool = Field(..., description="True nếu là sự cố an ninh thực sự, False nếu là False Positive")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Độ tin cậy của nhận định (0.0 đến 1.0)")
    severity: SeverityLevel = Field(..., description="Mức độ nghiêm trọng sơ bộ")
    summary: str = Field(..., description="Tóm tắt nhận định ban đầu và lý do phân loại")
    rule_or_model: str = Field("LLM-Triage-Engine", description="Tên quy tắc hoặc mô hình đưa ra phán đoán")


# =====================================================================
# 3. SCHEMAS CHO THREAT INTELLIGENCE (CTI) AGENT
# =====================================================================
class IoCItem(BaseModel):
    """Chỉ số nhận diện xâm phạm (IoC)."""
    ioc_type: str = Field(..., description="Loại IoC: IP, DOMAIN, MD5, SHA256, URL")
    value: str = Field(..., description="Giá trị chỉ số")
    reputation_score: Optional[int] = Field(None, ge=0, le=100, description="Điểm đánh giá độc hại (0-100)")
    is_malicious: bool = Field(False, description="Đã xác nhận độc hại từ CTI feeds hay chưa")
    threat_actor: Optional[str] = Field(None, description="Nhóm tấn công liên quan nếu có")
    details: Dict[str, Any] = Field(default_factory=dict, description="Dữ liệu chi tiết từ VirusTotal, AbuseIPDB...")


class ThreatIntelEnrichment(BaseModel):
    """Dữ liệu ngữ cảnh tình báo mối đe dọa được làm giàu."""
    extracted_iocs: List[IoCItem] = Field(default_factory=list, description="Danh sách IoC bóc tách được")
    related_threat_actors: List[str] = Field(default_factory=list, description="Các nhóm tấn công (APTs)")
    mitre_techniques: List[str] = Field(default_factory=list, description="Các mã kỹ thuật MITRE ATT&CK (ví dụ: T1059.001)")
    enrichment_summary: str = Field(..., description="Tóm tắt kết quả tra cứu và làm giàu thông tin")


# =====================================================================
# 4. SCHEMAS CHO ROOT CAUSE ANALYSIS (RCA) AGENT
# =====================================================================
class ProcessNode(BaseModel):
    """Nút trong cây tiến trình (Process Lineage)."""
    process_id: str = Field(..., description="PID hoặc định danh duy nhất của tiến trình")
    process_name: str = Field(..., description="Tên tiến trình")
    command_line: str = Field(..., description="Dòng lệnh thực thi")
    parent_id: Optional[str] = Field(None, description="PID của tiến trình cha")
    is_malicious_origin: bool = Field(False, description="Có phải điểm bắt đầu của mã độc/tấn công không")


class RootCauseAnalysis(BaseModel):
    """Kết quả phân tích nguyên nhân gốc rễ và chuỗi tấn công."""
    initial_access_vector: str = Field(..., description="Phương thức xâm nhập ban đầu (Phishing, Exploit, v.v.)")
    attack_timeline: List[str] = Field(default_factory=list, description="Dòng thời gian các bước tấn công")
    process_tree: List[ProcessNode] = Field(default_factory=list, description="Cây tiến trình tái hiện")
    mitre_tactics: List[str] = Field(default_factory=list, description="Các chiến thuật ATT&CK đã phát hiện")
    root_cause_summary: str = Field(..., description="Báo cáo phân tích nguyên nhân gốc rễ chi tiết")


# =====================================================================
# 5. SCHEMAS CHO RESPONSE RECOMMENDATION AGENT
# =====================================================================
class RecommendedAction(BaseModel):
    """Hành động ngăn chặn / phản ứng được đề xuất."""
    action_type: ActionType = Field(..., description="Loại hành động")
    target: str = Field(..., description="Đối tượng thực thi (IP, Hostname, Process PID, Username)")
    description: str = Field(..., description="Giải thích chi tiết lý do và cách thức thực hiện")
    priority: int = Field(..., ge=1, le=5, description="Mức độ ưu tiên (1: Khẩn cấp nhất, 5: Thấp nhất)")
    require_human_approval: bool = Field(True, description="Có cần chuyên viên duyệt (HITL) hay không")
    is_approved: Optional[bool] = Field(None, description="Trạng thái phê duyệt: True/False/None")


# =====================================================================
# 6. SCHEMAS CHO REPORTING AGENT
# =====================================================================
class IncidentReport(BaseModel):
    """Báo cáo điều tra sự cố toàn diện cuối cùng."""
    report_id: str = Field(..., description="Mã định danh báo cáo")
    incident_title: str = Field(..., description="Tiêu đề sự cố")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Thời gian xuất báo cáo")
    executive_summary: str = Field(..., description="Tóm lược điều hành cho cấp quản lý")
    detailed_findings: str = Field(..., description="Phân tích kỹ thuật chi tiết")
    mitre_attack_matrix_mapping: List[str] = Field(default_factory=list, description="Danh sách kỹ thuật ATT&CK")
    ioc_table: List[IoCItem] = Field(default_factory=list, description="Bảng IoC phát hiện được")
    action_plan: List[RecommendedAction] = Field(default_factory=list, description="Kế hoạch phản ứng và khắc phục")
