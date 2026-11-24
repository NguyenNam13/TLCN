# -*- coding: utf-8 -*-
"""
src/core/schemas.py
Bộ Schema Input/Output chuẩn hóa cho Hệ thống Multi-Agent điều tra sự cố an ninh mạng.
Được thiết kế dựa trên Pydantic v2 nhằm đảm bảo Type Safety, Validation nghiêm ngặt
và tương thích hoàn toàn với LangGraph StateGraph.
"""

import uuid
from enum import Enum
from typing import List, Dict, Optional, Any, Union, Literal
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict, AliasChoices, model_validator


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
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
    WAZUH_ACTIVE_RESPONSE = "WAZUH_ACTIVE_RESPONSE"


class IncidentPhase(str, Enum):
    """Các giai đoạn phản ứng và xử lý sự cố theo chuẩn NIST SP 800-61."""
    CONTAINMENT = "CONTAINMENT"
    ERADICATION = "ERADICATION"
    RECOVERY = "RECOVERY"
    POST_INCIDENT = "POST_INCIDENT"



class AttackCategory(str, Enum):
    MALWARE = "MALWARE"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    RECONNAISSANCE = "RECONNAISSANCE"
    WEB_ATTACK = "WEB_ATTACK"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


# =====================================================================
# 0. SCHEMAS CHO WAZUH SIEM INTEGRATION
# =====================================================================
class WazuhMitreInfo(BaseModel):
    """Thông tin MITRE ATT&CK trích xuất từ Wazuh Rule."""
    id: List[str] = Field(default_factory=list, description="Danh sách mã kỹ thuật (Txxxx)")
    tactic: List[str] = Field(default_factory=list, description="Danh sách chiến thuật")
    technique: List[str] = Field(default_factory=list, description="Danh sách tên kỹ thuật")


class WazuhRuleInfo(BaseModel):
    """Cấu trúc Rule của cảnh báo Wazuh."""
    id: str = Field(..., description="ID của luật phát hiện Wazuh")
    level: int = Field(..., ge=0, le=15, description="Mức độ nghiêm trọng của Rule (0-15)")
    description: str = Field(..., description="Mô tả luật")
    groups: List[str] = Field(default_factory=list, description="Nhóm phân loại luật (windows, sysmon, web, etc.)")
    mitre: Optional[WazuhMitreInfo] = None


class WazuhAgentInfo(BaseModel):
    """Thông tin máy trạm (Agent) ghi nhận cảnh báo trên Wazuh."""
    id: str = Field(..., description="ID Agent trong Wazuh")
    name: str = Field(..., description="Tên định danh máy trạm")
    ip: Optional[str] = Field(None, description="Địa chỉ IP của Agent")


class WazuhAlert(BaseModel):
    """Mô hình dữ liệu cảnh báo hoàn chỉnh từ Wazuh SIEM."""
    id: str = Field(..., description="Mã định danh duy nhất của cảnh báo Wazuh")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rule: WazuhRuleInfo = Field(..., description="Thông tin luật bị kích hoạt")
    agent: WazuhAgentInfo = Field(..., description="Thông tin Agent nguồn")
    full_log: Optional[str] = Field(None, description="Dòng log thô ban đầu")
    data: Dict[str, Any] = Field(default_factory=dict, description="Dữ liệu chi tiết đã giải mã (Win/Sysmon/Zeek)")



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
    attack_category: Optional[AttackCategory] = Field(default=None, description="Phân loại nhóm tấn công chính")
    attack_type: Optional[str] = Field(default=None, description="Định danh cụ thể loại tấn công")
    primary_mitre_tactics: List[str] = Field(default_factory=list, description="Danh sách chiến thuật MITRE chính")


class TriageCoTSteps(BaseModel):
    """4 bước suy luận Chain-of-Thought của Triage Agent."""
    observation: str = Field(..., description="Bước 1: Quan sát các hành vi đáng ngờ có trong bằng chứng")
    contextualization: str = Field(..., description="Bước 2: Phân tích bối cảnh (công cụ hợp lệ hay bất thường)")
    risk_scoring: str = Field(..., description="Bước 3: Lý giải điểm rủi ro và mức độ nghiêm trọng")
    conclusion: str = Field(..., description="Bước 4: Kết luận True Positive / False Positive")


class TriageLLMResult(BaseModel):
    """Schema thống nhất cho đầu ra structured của LLM Triage (CoT + phân loại tấn công)."""
    is_incident: bool = Field(..., description="True nếu là sự cố thực sự")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Độ tin cậy (0.0 - 1.0)")
    severity: SeverityLevel = Field(..., description="Mức độ nghiêm trọng")
    score: float = Field(..., ge=0.0, le=100.0, description="Điểm rủi ro 0-100")
    attack_category: AttackCategory = Field(..., description="Nhóm tấn công chính")
    attack_type: str = Field(..., description="Định danh cụ thể loại tấn công")
    primary_mitre_tactics: List[str] = Field(default_factory=list, description="Chiến thuật MITRE chính")
    cot_steps: TriageCoTSteps = Field(..., description="Các bước suy luận CoT")
    rationale: str = Field(..., description="Giải thích ngắn gọn căn cứ phân loại")


# =====================================================================
# 3. SCHEMAS CHO THREAT INTELLIGENCE (CTI) AGENT
# =====================================================================
class MultiDimensionalCTIScore(BaseModel):
    """Điểm đánh giá tình báo mối đe dọa (CTI) đa chiều tổng hợp."""
    abuseipdb_score: Optional[int] = Field(None, ge=0, le=100, description="Tỷ lệ phần trăm độc hại AbuseIPDB (0-100%)")
    virustotal_ratio: Optional[str] = Field(None, description="Tỉ lệ phát hiện VirusTotal (ví dụ: '45/72')")
    virustotal_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="Điểm chuẩn hóa VirusTotal (0.0 - 1.0)")
    otx_pulses: Optional[int] = Field(None, ge=0, description="Số lượng AlienVault OTX Pulses liên quan")
    threat_actor_tags: List[str] = Field(default_factory=list, description="Thẻ định danh nhóm APT / Threat Actor")
    composite_score: float = Field(0.0, ge=0.0, le=100.0, description="Điểm rủi ro tổng hợp đa chiều CTI (0.0 - 100.0)")


class IoCItem(BaseModel):
    """Chỉ số nhận diện xâm phạm (IoC) đa chiều mở rộng."""
    ioc_type: str = Field(..., description="Loại IoC: IP, DOMAIN, MD5, SHA256, URL")
    value: str = Field(..., description="Giá trị chỉ số")
    reputation_score: Optional[int] = Field(None, ge=0, le=100, description="Điểm đánh giá độc hại (0-100)")
    is_malicious: bool = Field(False, description="Đã xác nhận độc hại từ CTI feeds hay chưa")
    threat_actor: Optional[str] = Field(None, description="Nhóm tấn công liên quan nếu có")
    details: Dict[str, Any] = Field(default_factory=dict, description="Dữ liệu chi tiết từ VirusTotal, AbuseIPDB...")
    # Các trường mở rộng bổ sung giữ tương thích ngược 100%
    cti_score: Optional[MultiDimensionalCTIScore] = Field(None, description="Điểm CTI đa chiều chi tiết")
    first_seen: Optional[datetime] = Field(None, description="Thời điểm phát hiện đầu tiên")
    last_seen: Optional[datetime] = Field(None, description="Thời điểm phát hiện gần nhất")
    mitre_tactics: List[str] = Field(default_factory=list, description="Chiến thuật MITRE liên quan")
    is_public: Optional[bool] = Field(None, description="IP công khai (True) hay IP nội bộ (False)")
    context_source: Optional[str] = Field(None, description="Nguồn trích xuất: CommandLine, Network, FileHash, Deobfuscator")


# Alias tương thích ngược cho EnhancedIoCItem
EnhancedIoCItem = IoCItem



class ThreatIntelEnrichment(BaseModel):
    """Dữ liệu ngữ cảnh tình báo mối đe dọa được làm giàu."""
    extracted_iocs: List[IoCItem] = Field(default_factory=list, description="Danh sách IoC bóc tách được")
    indicators: Optional[List[IoCItem]] = Field(default=None, description="Danh sách IoC tương thích mở rộng")
    related_threat_actors: List[str] = Field(default_factory=list, description="Các nhóm tấn công (APTs)")
    mitre_techniques: List[str] = Field(default_factory=list, description="Các mã kỹ thuật MITRE ATT&CK (ví dụ: T1059.001)")
    enrichment_summary: str = Field(default="", description="Tóm tắt kết quả tra cứu và làm giàu thông tin")
    rag_mitre_context: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Ngữ cảnh kỹ thuật MITRE ATT&CK bổ sung từ RAG Knowledge Base",
    )

    def model_post_init(self, __context: Any) -> None:
        if self.indicators and not self.extracted_iocs:
            self.extracted_iocs = self.indicators
        elif self.extracted_iocs and not self.indicators:
            self.indicators = self.extracted_iocs


class ThreatIntelLLMAnalysis(BaseModel):
    """Kết quả phân tích CTI & ánh xạ MITRE ATT&CK structured từ LLM (IoCs và điểm CTI giữ 100% deterministic)."""
    mitre_techniques: List[str] = Field(
        default_factory=list,
        description="Danh sách mã kỹ thuật MITRE ATT&CK hợp lệ (định dạng Txxxx hoặc Txxxx.xxx)",
    )
    mitre_rationale: str = Field(
        default="",
        description="Lý giải ngắn gọn cơ sở ánh xạ các mã kỹ thuật MITRE ATT&CK từ bằng chứng và RAG",
    )
    threat_assessment_summary: str = Field(
        default="",
        description="Tóm tắt đánh giá tình báo mối đe dọa ngắn gọn, bám sát bằng chứng đã cung cấp",
    )
    evidence_citations: List[str] = Field(
        default_factory=list,
        description="Danh sách trích dẫn bằng chứng cụ thể từ sự kiện và ngữ cảnh RAG",
    )


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
    host_name: Optional[str] = Field(default=None, description="Tên máy chủ thực thi tiến trình")


class HighFidelityProcessNode(ProcessNode):
    """Nút tiến trình độ chính xác cao phục vụ tái hiện cây tiến trình millisecond."""
    timestamp_ms: Optional[int] = Field(None, description="Dấu thời gian theo mili-giây (Unix Epoch ms)")
    iso_timestamp: Optional[str] = Field(None, description="Thời gian định dạng ISO 8601 chuẩn xác")
    user: Optional[str] = Field(None, description="Tài khoản người dùng thực thi (User/SID)")
    integrity_level: Optional[str] = Field(None, description="Mức độ toàn vẹn (System, High, Medium, Low)")
    file_hashes: Dict[str, str] = Field(default_factory=dict, description="Bảng hash file (MD5, SHA1, SHA256, IMPHASH)")
    parent_process_name: Optional[str] = Field(None, description="Tên tiến trình cha")
    child_process_ids: List[str] = Field(default_factory=list, description="Danh sách PID tiến trình con")
    network_connections: List[Dict[str, Any]] = Field(default_factory=list, description="Các kết nối mạng được khởi tạo")
    deobfuscated_command: Optional[str] = Field(None, description="Câu lệnh đã qua giải mã deobfuscation")
    mitre_techniques: List[str] = Field(default_factory=list, description="Mã kỹ thuật MITRE ATT&CK phát hiện được")
    risk_score: Optional[float] = Field(None, ge=0.0, le=100.0, description="Điểm rủi ro của tiến trình (0-100)")


class RootCauseAnalysis(BaseModel):
    """Kết quả phân tích nguyên nhân gốc rễ và chuỗi tấn công."""
    initial_access_vector: str = Field(..., description="Phương thức xâm nhập ban đầu (Phishing, Exploit, v.v.)")
    attack_timeline: List[str] = Field(default_factory=list, description="Dòng thời gian các bước tấn công")
    process_tree: List[ProcessNode] = Field(default_factory=list, description="Cây tiến trình tái hiện")
    high_fidelity_tree: List[HighFidelityProcessNode] = Field(default_factory=list, description="Cây tiến trình chi tiết millisecond")
    mitre_tactics: List[str] = Field(default_factory=list, description="Các chiến thuật ATT&CK đã phát hiện")
    root_cause_summary: str = Field(..., description="Báo cáo phân tích nguyên nhân gốc rễ chi tiết")
    confirmed_attack_type: Optional[str] = Field(default=None, description="Định danh loại tấn công đã xác nhận qua RCA")
    attack_scope: Optional[str] = Field(default=None, description="Phạm vi ảnh hưởng của tấn công")


class RCALLMAnalysis(BaseModel):
    """Kết quả structured của LLM cho RCA Agent (phân tích nhận thức, bám sát bằng chứng)."""
    defense_evasion_techniques: List[str] = Field(default_factory=list)
    child_process_purposes: List[str] = Field(default_factory=list)
    attacker_objective: str = Field(..., description="Mục tiêu / động cơ của kẻ tấn công")
    refined_initial_access_vector: Optional[str] = None
    refined_attack_type: Optional[str] = None
    mitre_tactics_inferred: List[str] = Field(default_factory=list)
    analyst_feedback_addressed: Optional[str] = None
    cognitive_narrative: str = Field(..., description="Diễn giải nhận thức bám sát bằng chứng")
    evidence_citations: List[str] = Field(default_factory=list)


# =====================================================================
# 5. SCHEMAS CHO RESPONSE RECOMMENDATION AGENT
# =====================================================================
class ActionScriptBundle(BaseModel):
    """Gói kịch bản thực thi phản ứng theo từng giai đoạn NIST SP 800-61."""
    bundle_id: str = Field(default_factory=lambda: f"BUNDLE-{uuid.uuid4().hex[:8].upper()}", description="Mã gói kịch bản")
    action_id: str = Field(..., description="ID hành động tương ứng")
    phase: IncidentPhase = Field(..., description="Giai đoạn ứng phó sự cố (CONTAINMENT, ERADICATION, RECOVERY...)")
    target: str = Field(..., description="Mục tiêu thực thi (IP, Hostname, Process PID...)")
    powershell_script: Optional[str] = Field(None, description="Kịch bản PowerShell remediate trên Windows")
    bash_script: Optional[str] = Field(None, description="Kịch bản Bash iptables/kill trên Linux")
    wazuh_active_response: Optional[Dict[str, Any]] = Field(None, description="Lệnh Wazuh Active Response API/Agent")
    rollback_script: Optional[str] = Field(None, description="Kịch bản hoàn tác (Rollback)")
    instructions: str = Field("", description="Hướng dẫn vận hành cho SOC Analyst")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Thời điểm khởi tạo bundle")
    is_critical_process: bool = Field(default=False, description="Cờ cảnh báo tiến trình hệ thống trọng yếu")
    warning_message: Optional[str] = Field(default=None, description="Thông điệp cảnh báo an toàn hệ thống")
    evidence_snapshot_included: bool = Field(default=False, description="Cờ đánh dấu kịch bản đã tích hợp Pre-response Snapshot bảo toàn chứng cứ")


class RecommendedAction(BaseModel):
    """Hành động ngăn chặn / phản ứng được đề xuất."""
    action_id: Optional[str] = Field(default_factory=lambda: f"ACT-{uuid.uuid4().hex[:8].upper()}", description="Định danh duy nhất của hành động")
    action_type: ActionType = Field(..., description="Loại hành động")
    target: str = Field(..., description="Đối tượng thực thi (IP, Hostname, Process PID, Username)")
    description: str = Field(..., description="Giải thích chi tiết lý do và cách thức thực hiện")
    priority: int = Field(..., ge=1, le=5, description="Mức độ ưu tiên (1: Khẩn cấp nhất, 5: Thấp nhất)")
    require_human_approval: bool = Field(True, description="Có cần chuyên viên duyệt (HITL) hay không")
    is_approved: Optional[bool] = Field(None, description="Trạng thái phê duyệt: True/False/None")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Các tham số thực thi chi tiết")
    phase: Optional[IncidentPhase] = Field(None, description="Giai đoạn ứng phó sự cố NIST SP 800-61")
    script_bundle: Optional[ActionScriptBundle] = Field(None, description="Gói kịch bản thực thi tự động")


class ActionAdjustment(BaseModel):
    """Điều chỉnh do LLM đề xuất lên một hành động ứng phó xác định (deterministic) hiện có."""
    action_id: Optional[str] = None
    action_type: ActionType
    target: str
    operation: Literal["KEEP", "REPRIORITIZE", "CUSTOMIZE_RATIONALE", "SUPPRESS_PER_FEEDBACK"]
    new_priority: Optional[int] = Field(default=None, ge=1, le=5)
    custom_description: Optional[str] = None
    reason: str


class ResponseLLMStrategy(BaseModel):
    """Chiến lược ứng phó structured do LLM sinh ra cho Response Agent."""
    rationale: str
    containment_guidance: str
    eradication_recovery_guidance: str
    operational_safety_notes: str
    analyst_feedback_addressed: Optional[str] = None
    action_adjustments: List[ActionAdjustment] = Field(default_factory=list)
    rag_citations: List[str] = Field(default_factory=list)
    strategy_summary: str


# =====================================================================
# 6. SCHEMAS CHO REPORTING AGENT (GROUNDED TELEMETRY & STRUCTURED REPORT)
# =====================================================================
class OperationalMetrics(BaseModel):
    """Chỉ số vận hành ứng cứu sự cố thực đo từ IncidentState."""
    mtta_display: str = "N/A (Chưa đo)"
    mttc_display: str = "N/A (Chưa đo)"
    mttr_display: str = "N/A (Chưa đo)"
    mtta_seconds: Optional[float] = None
    mttc_seconds: Optional[float] = None
    mttr_seconds: Optional[float] = None
    sla_status: str = "Chưa đánh giá"


class CIADimension(BaseModel):
    """Đánh giá một chiều trong bộ ba an toàn thông tin (CIA Triad)."""
    level: str = Field(default="Không (None)", description="Mức độ tác động: Không/Thấp/Trung bình/Cao")
    assessment: str = Field(default="", description="Đánh giá gắn với bằng chứng thực tế trong IncidentState")


class ImpactAssessment(BaseModel):
    """Đánh giá tác động toàn diện CIA, vận hành, tài chính và tuân thủ pháp lý."""
    confidentiality: CIADimension = Field(default_factory=CIADimension)
    integrity: CIADimension = Field(default_factory=CIADimension)
    availability: CIADimension = Field(default_factory=CIADimension)
    operational_sla_note: str = ""
    financial_impact_note: str = ""
    compliance_note: str = ""


class DeepRCABreakdown(BaseModel):
    """Phân tích nguyên nhân gốc rễ chuyên sâu (3 tầng, 5 Whys, Ishikawa)."""
    applicable: bool = True
    proximate_cause: str = ""
    contributing_factors: str = ""
    root_cause: str = ""
    five_whys: List[str] = Field(default_factory=list)
    ishikawa_factors: List[Dict[str, str]] = Field(default_factory=list)


class VerificationGateItem(BaseModel):
    """Hạng mục kiểm định an toàn trước khi khôi phục hệ thống (Integrity Gate)."""
    label: str
    checked: bool = False
    detail: str = ""


class CAPAItem(BaseModel):
    """Hạng mục trong kế hoạch khắc phục và phòng ngừa dài hạn (CAPA)."""
    code: str
    item: str
    category: str = "Công nghệ"
    priority: str = "P2"
    raci: str = ""
    timeline: str = ""
    kpi: str = ""


class ReportingLLMSynthesis(BaseModel):
    """Kết quả tổng hợp structured của LLM cho Reporting Agent (grounded vào IncidentState)."""
    executive_advisory: str
    business_impact_assessment: str = ""
    cia_rationale: Optional[Dict[str, str]] = None
    five_whys: List[str] = Field(default_factory=list)
    ishikawa_factors: List[Dict[str, str]] = Field(default_factory=list)
    strategic_lessons_learned: List[str] = Field(default_factory=list)
    capa_recommendations: List[CAPAItem] = Field(default_factory=list)
    evidence_citations: List[str] = Field(default_factory=list)


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
    attack_type: Optional[str] = Field(default=None, description="Loại tấn công chính được xác định")
    attack_category: Optional[str] = Field(default=None, description="Nhóm phân loại tấn công")
    confidence_level: Optional[float] = Field(default=None, description="Độ tin cậy tổng thể của phán đoán (0.0 - 1.0)")
    # Các trường mở rộng grounded telemetry & báo cáo chuyên sâu (tương thích ngược 100%)
    severity: Optional[str] = Field(default=None, description="Mức độ nghiêm trọng thực tế của sự cố")
    incident_status: Optional[str] = Field(default=None, description="Trạng thái xử lý sự cố tại thời điểm xuất báo cáo")
    is_incident: Optional[bool] = Field(default=None, description="True nếu là sự cố thực sự, False nếu False Positive")
    organization_name: Optional[str] = Field(default=None, description="Tên cơ quan/tổ chức điều tra")
    response_strategy_summary: Optional[str] = Field(default=None, description="Tóm tắt chiến lược phản ứng từ RAG & LLM")
    llm_grounded: bool = Field(default=False, description="Cờ đánh dấu báo cáo đã qua kiểm chứng grounding thực thể")
    operational_metrics: Optional[Union[OperationalMetrics, Dict[str, Any]]] = Field(
        default=None,
        description="Chỉ số vận hành IR thực đo từ timeline sự cố (MTTA, MTTC, MTTR, SLA)",
    )
    impact_assessment: Optional[Union[ImpactAssessment, Dict[str, Any]]] = Field(
        default=None,
        description="Đánh giá mức độ ảnh hưởng CIA, vận hành và tuân thủ pháp lý",
    )
    deep_rca_breakdown: Optional[Union[DeepRCABreakdown, Dict[str, Any]]] = Field(
        default=None,
        description="Phân tích nguyên nhân gốc rễ chuyên sâu (3 tầng, 5 Whys, Ishikawa)",
    )
    verification_checklist: Optional[List[Union[VerificationGateItem, Dict[str, Any]]]] = Field(
        default=None,
        description="Danh sách kiểm định an toàn trước khi khôi phục (Integrity Verification Gate)",
    )
    verification_gate: List[Union[VerificationGateItem, Dict[str, Any]]] = Field(
        default_factory=list,
        description="Danh sách cổng kiểm định an toàn (đồng bộ với verification_checklist)",
    )
    capa_plan: Optional[Union[List[Union[CAPAItem, Dict[str, Any]]], Dict[str, Any]]] = Field(
        default=None,
        description="Kế hoạch hành động khắc phục & phòng ngừa dài hạn (CAPA)",
    )

    def model_post_init(self, __context: Any) -> None:
        if self.verification_checklist is not None and not self.verification_gate:
            self.verification_gate = list(self.verification_checklist)
        elif self.verification_gate and self.verification_checklist is None:
            self.verification_checklist = list(self.verification_gate)


# =====================================================================
# 7. SCHEMAS CHO LLM HEALTH & TELEMETRY OBSERVABILITY
# =====================================================================
class LLMHealthStatus(BaseModel):
    """Trạng thái kiểm tra sức khỏe kết nối LLM Gateway thực tế."""
    connected: bool = False
    active_provider: str = "deterministic"
    configured_mode: str = "auto"
    endpoint: str = ""
    model: str = ""
    latency_ms: Optional[float] = None
    using_dummy_key: bool = False
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detail: str = ""
    error: Optional[str] = None


class LLMCallTelemetry(BaseModel):
    """Bản ghi đo lường chi tiết từng lượt gọi LLM trong pipeline và Copilot."""
    model_config = ConfigDict(populate_by_name=True)

    call_id: str = Field(default_factory=lambda: f"LLM-{uuid.uuid4().hex[:8].upper()}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_name: str = Field(
        default="Unknown",
        validation_alias=AliasChoices("agent_name", "agent"),
        description="Tên Agent hoặc thành phần gọi LLM",
    )
    node: Optional[str] = Field(default=None, description="Tên node thực thi trong StateGraph")
    model_tier: str = Field(default="default", description="Tầng model: fast, reasoning, default")
    provider_used: str = Field(
        default="deterministic",
        validation_alias=AliasChoices("provider_used", "provider"),
        description="Provider thực tế: omnirouter, openrouter, ollama, deterministic, skipped_tiered",
    )
    model: str = Field(default="", description="Tên model được sử dụng")
    latency_ms: float = Field(default=0.0, ge=0.0, description="Độ trễ thực thi (ms)")
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    usage_estimated: bool = Field(default=False, description="True nếu token được ước lượng khi thiếu usage từ API")
    structured_attempts: int = Field(default=1, ge=0)
    self_corrected: bool = Field(default=False)
    schema_valid: bool = Field(default=True)
    schema_name: Optional[str] = Field(default=None)
    tool_calls_count: int = Field(default=0, ge=0)
    success: bool = Field(default=True)
    fallback_reason: Optional[str] = Field(default=None)

    @model_validator(mode="before")
    @classmethod
    def _normalize_legacy_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            normalized = dict(data)
            if "structured_attempts" not in normalized and "self_correction_attempts" in normalized:
                try:
                    normalized["structured_attempts"] = 1 + max(0, int(normalized["self_correction_attempts"]))
                except (TypeError, ValueError):
                    pass
            return normalized
        return data

    def model_post_init(self, __context: Any) -> None:
        if self.total_tokens == 0 and (self.prompt_tokens > 0 or self.completion_tokens > 0):
            self.total_tokens = self.prompt_tokens + self.completion_tokens
        if self.structured_attempts > 1 and not self.self_corrected:
            self.self_corrected = True

    @property
    def agent(self) -> str:
        return self.agent_name

    @property
    def provider(self) -> str:
        return self.provider_used

    @property
    def self_correction_attempts(self) -> int:
        return max(0, self.structured_attempts - 1)


class LLMCompletionResult(BaseModel):
    """Kết quả trả về từ lời gọi Chat Completion có hỗ trợ Tool Calling chuẩn OpenAI."""
    content: str = ""
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    finish_reason: Optional[str] = None
    provider_used: Optional[str] = None
    model: Optional[str] = None
    telemetry: Optional[LLMCallTelemetry] = None

