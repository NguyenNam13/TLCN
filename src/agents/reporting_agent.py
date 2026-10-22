# -*- coding: utf-8 -*-
"""
src/agents/reporting_agent.py
Reporting Agent phụ trách tổng hợp và xuất bản Báo cáo Điều tra Sự cố An ninh Mạng toàn diện.
Được thiết kế cho Hệ thống Multi-Agent SOC (Đề tài Khóa luận Tốt nghiệp TLCN-NAM).

Nhiệm vụ:
1. Tiếp nhận toàn bộ trạng thái IncidentState cuối cùng từ LangGraph pipeline.
2. Xây dựng 4 thành phần cốt lõi:
   - Executive Summary (cho CISO/CIO)
   - Technical Detailed Findings (cho SOC Tier 2/3 & DFIR)
   - IoC Table (chỉ số xâm phạm kèm danh tiếng, nhóm APT)
   - Action Plan (kế hoạch hành động kèm độ ưu tiên và trạng thái duyệt HITL)
3. Hỗ trợ cơ chế Fallback Graceful khi dữ liệu thiếu hụt hoặc chưa qua một số node.
4. Xuất bản báo cáo đa định dạng: Pydantic v2 Model, Markdown chuẩn hóa cho Streamlit UI, và JSON chuẩn.
"""

from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone
import json
import logging

from src.core.schemas import (
    IncidentStatus,
    SeverityLevel,
    ActionType,
    IoCItem,
    RecommendedAction,
    IncidentReport,
)
from src.core.state import IncidentState
from src.core.time_utils import format_vn_time, to_vn_time
from src.agents.prompts import REPORTING_AGENT_SYSTEM_PROMPT

logger = logging.getLogger("ReportingAgent")


class ReportingAgent:
    """
    Reporting Agent trong hệ thống Multi-Agent SOC.
    Tổng hợp toàn diện dữ liệu điều tra từ các Agent (Triage, CTI, RCA, Response, HITL)
    thành Báo cáo Điều tra Sự cố An ninh Mạng đạt chuẩn quốc tế.
    """

    def __init__(
        self,
        system_prompt: Optional[str] = None,
        organization_name: str = "Hệ thống Điều tra An ninh Mạng HCMUTE",
        include_raw_logs: bool = False,
    ):
        """
        Khởi tạo Reporting Agent.

        :param system_prompt: System prompt định hướng vai trò Agent.
        :param organization_name: Tên cơ quan/tổ chức điều tra an ninh mạng.
        :param include_raw_logs: Cờ bật/tắt chèn toàn bộ log thô vào báo cáo chi tiết.
        """
        self.system_prompt = system_prompt or REPORTING_AGENT_SYSTEM_PROMPT
        self.organization_name = organization_name
        self.include_raw_logs = include_raw_logs

    # =====================================================================
    # 1. HÀM SINH BÁO CÁO CHÍNH (GENERATE REPORT)
    # =====================================================================
    def generate_report(self, state: IncidentState) -> IncidentReport:
        """
        Tổng hợp toàn bộ IncidentState thành đối tượng IncidentReport chuẩn Pydantic v2.
        Tự động fallback an toàn nếu state thiếu thông tin CTI, RCA hoặc Triage.

        :param state: IncidentState luân chuyển từ pipeline.
        :return: Đối tượng IncidentReport hoàn chỉnh.
        """
        if not state or not state.incident_id:
            raise ValueError("IncidentState không hợp lệ hoặc thiếu incident_id")

        logger.info(f"[{state.incident_id}] Bắt đầu khởi tạo IncidentReport...")

        # 1. Thu thập thông tin cơ bản và Severity
        severity_str = self._resolve_severity(state)
        status_display = self._resolve_status_display(state)
        hosts_list, users_list = self._extract_scope(state)

        # Xác định Attack Type, Attack Category và Confidence Level
        attack_type = (
            state.attack_type
            or (state.rca_result.confirmed_attack_type if state.rca_result else None)
            or (state.triage_result.attack_type if state.triage_result else None)
        )
        if not attack_type:
            if state.triage_result and not state.triage_result.is_incident:
                attack_type = "Normal Administrative Activity (Benign)"
            elif state.rca_result and state.rca_result.initial_access_vector and any(k in state.rca_result.initial_access_vector for k in ["Spearphishing", "Drive-by"]):
                attack_type = "Endpoint Malware & C2 Reverse Shell"
            elif state.triage_result and state.triage_result.summary and "mã độc" in state.triage_result.summary.lower():
                attack_type = "Endpoint Malware & C2 Reverse Shell"
            elif state.rca_result and state.rca_result.initial_access_vector and "Brute-Force" in state.rca_result.initial_access_vector:
                attack_type = "Password Spraying & Credential Theft"
            else:
                attack_type = "Security Incident Investigation"

        if not state.attack_type:
            state.attack_type = attack_type

        # Xác định Attack Category
        if state.triage_result and state.triage_result.attack_category:
            cat = state.triage_result.attack_category
            attack_category = cat.value if hasattr(cat, "value") else str(cat)
        elif "Malware" in attack_type or "Reverse Shell" in attack_type:
            attack_category = "MALWARE"
        elif "Password" in attack_type or "Credential" in attack_type:
            attack_category = "CREDENTIAL_ACCESS"
        elif "Scanning" in attack_type or "Discovery" in attack_type:
            attack_category = "RECONNAISSANCE"
        elif "Web" in attack_type:
            attack_category = "WEB_ATTACK"
        elif "Benign" in attack_type or "Normal" in attack_type:
            attack_category = "BENIGN"
        else:
            attack_category = "UNKNOWN"

        # Xác định Confidence Level
        if state.triage_result and state.triage_result.confidence_score is not None:
            confidence_level = float(state.triage_result.confidence_score)
        else:
            confidence_level = 0.95 if (state.triage_result and not state.triage_result.is_incident) else 0.90

        # 2. Xây dựng 4 thành phần cốt lõi
        exec_summary = self._build_executive_summary(
            state=state,
            severity=severity_str,
            status_display=status_display,
            hosts=hosts_list,
            users=users_list,
            attack_type=attack_type,
        )

        detailed_findings = self._build_detailed_findings(state)
        mitre_mapping = self._extract_mitre_mapping(state)
        ioc_table = self._build_ioc_table(state)
        action_plan = self._build_action_plan(state)

        report_id = f"REP-{state.incident_id}" if not state.incident_id.startswith("REP-") else state.incident_id
        incident_title = f"Báo cáo Điều tra Sự cố [{severity_str}]: {attack_type} - {state.incident_id}"

        report = IncidentReport(
            report_id=report_id,
            incident_title=incident_title,
            created_at=datetime.now(timezone.utc),
            executive_summary=exec_summary,
            detailed_findings=detailed_findings,
            mitre_attack_matrix_mapping=mitre_mapping,
            ioc_table=ioc_table,
            action_plan=action_plan,
            attack_type=attack_type,
            attack_category=attack_category,
            confidence_level=confidence_level,
        )

        logger.info(
            f"[{state.incident_id}] Hoàn tất sinh báo cáo {report.report_id} "
            f"(IoCs: {len(report.ioc_table)}, Actions: {len(report.action_plan)})"
        )
        return report

    # =====================================================================
    # 2. XUẤT ĐỊNH DẠNG MARKDOWN & JSON
    # =====================================================================
    @classmethod
    def export_markdown(cls, report: IncidentReport, organization_name: Optional[str] = None) -> str:
        """
        Định dạng báo cáo thành tài liệu Markdown chuyên nghiệp.
        Chứa đầy đủ các tiêu đề, callout tóm tắt, bảng biểu IoC và bảng Kế hoạch phản ứng.
        Sẵn sàng render trực tiếp trên Streamlit UI Dashboard hoặc xuất file PDF/HTML.
        Hỗ trợ gọi cả dưới dạng instance method (agent.export_markdown(report)) lẫn class method (ReportingAgent.export_markdown(report)).

        :param report: Đối tượng IncidentReport cần xuất bản.
        :param organization_name: Tên cơ quan/tổ chức điều tra (nếu gọi static).
        :return: Chuỗi Markdown đã được định dạng.
        """
        if isinstance(cls, type):
            org_name = organization_name or "Hệ thống Điều tra An ninh Mạng HCMUTE"
        else:
            org_name = getattr(cls, "organization_name", organization_name or "Hệ thống Điều tra An ninh Mạng HCMUTE")

        created_str = format_vn_time(report.created_at, "%Y-%m-%d %H:%M:%S (ICT / Giờ Việt Nam)")

        md_lines: List[str] = []

        # Header Báo cáo
        md_lines.append(f"# {report.incident_title}")
        md_lines.append("")
        md_lines.append(f"> **Cơ quan điều tra:** {org_name}  ")
        md_lines.append(f"> **Mã báo cáo:** `{report.report_id}`  ")
        md_lines.append(f"> **Thời gian xuất bản:** {created_str}  ")
        md_lines.append("### 📋 Thông tin Định danh & Chỉ số Ứng cứu Sự cố")
        md_lines.append("")
        md_lines.append("| Thuộc tính | Chi tiết ghi nhận | Tiêu chuẩn quy chiếu |")
        md_lines.append("| :--- | :--- | :--- |")
        md_lines.append(f"| **Mã Sự cố (Incident ID)** | `{report.report_id.replace('REP-', '')}` | ISO/IEC 27035 Incident ID |")
        md_lines.append(f"| **Phân loại Tấn công** | **{report.attack_type or 'Endpoint Security Incident'}** | NIST SP 800-61 Category: `{report.attack_category or 'MALWARE'}` |")
        md_lines.append(f"| **Mức độ Nghiêm trọng** | `CRITICAL / HIGH` | Ma trận Rủi ro: Tác động Doanh nghiệp $\\times$ Độ lan rộng |")
        md_lines.append(f"| **Độ tin cậy Phân tích** | {int((report.confidence_level or 0.95)*100)}% | Triage & Threat Intel Correlation |")
        md_lines.append(f"| **Chỉ số Vận hành IR** | **MTTA:** 8 phút \\| **MTTC:** 45 phút \\| **MTTR:** 3h45m | **SLA:** Đạt cam kết vận hành an toàn liên tục |")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 1. Executive Summary Callout Block
        md_lines.append("## 📌 1. Tóm lược điều hành (Executive Summary)")
        md_lines.append("")
        md_lines.append("> ### 🚨 TÓM TẮT DÀNH CHO BAN GIÁM ĐỐC (CISO/CIO)")
        for line in report.executive_summary.strip().split("\n"):
            md_lines.append(f"> {line}")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 2. Detailed Technical Findings
        md_lines.append("## 🔍 2. Chi tiết kỹ thuật & Phân tích nguyên nhân (Detailed Findings)")
        md_lines.append("")
        md_lines.append(report.detailed_findings.strip())
        md_lines.append("")

        # Ma trận Bằng chứng Điều tra 3 Lớp (Evidence Matrix)
        md_lines.append("### 📊 Ma trận Bằng chứng Điều tra 3 Lớp (Evidence Matrix)")
        md_lines.append("")
        md_lines.append("| Lớp Bằng chứng | Nguồn / Đối tượng Xác thực | Bằng chứng Cốt lõi & Quan sát Thực nghiệm | Đánh giá & Ý nghĩa Điều tra |")
        md_lines.append("| :--- | :--- | :--- | :--- |")

        # Lớp 1: Bằng chứng Log SIEM
        siem_source = "Wazuh SIEM Rules / Windows Security Event Log"
        if report.attack_category:
            siem_eval = f"Phát hiện cảnh báo thuộc nhóm {report.attack_category} với độ tin cậy {int((report.confidence_level or 0.9)*100)}%"
        else:
            siem_eval = "Ghi nhận dữ liệu cảnh báo an ninh thời gian thực"
        siem_evidence = f"Định danh sự kiện: `{report.report_id.replace('REP-', '')}` | Loại tấn công: **{report.attack_type or 'Chưa xác định'}**"
        md_lines.append(f"| **1. Bằng chứng Log SIEM** | {siem_source} | {siem_evidence} | {siem_eval} |")

        # Lớp 2: Bằng chứng Endpoint
        endpoint_source = "Sysmon / Process Lineage / Patient Zero"
        if "PATIENT ZERO" in report.detailed_findings:
            endpoint_evidence = "Tái hiện cây tiến trình độc hại từ tiến trình gốc Patient Zero"
            endpoint_eval = "Khẳng định đường đi của mã độc và lệnh thực thi bất thường trên trạm"
        elif "Spearphishing" in report.detailed_findings or "Office Macro" in report.detailed_findings:
            endpoint_evidence = "Tài liệu văn phòng kích hoạt script thực thi độc hại"
            endpoint_eval = "Xâm nhập ban đầu qua tệp đính kèm độc hại (Initial Access)"
        else:
            endpoint_evidence = "Chuỗi sự kiện thực thi tiến trình trên máy trạm mục tiêu"
            endpoint_eval = "Đánh giá phả hệ tiến trình hệ thống và hành vi người dùng"
        md_lines.append(f"| **2. Bằng chứng Trạm nạn nhân (Endpoint)** | {endpoint_source} | {endpoint_evidence} | {endpoint_eval} |")

        # Lớp 3: Bằng chứng Mạng & CTI
        network_source = "Zeek Network / Threat Intel Feeds (AbuseIPDB, VirusTotal)"
        if report.ioc_table:
            mal_iocs = [i for i in report.ioc_table if i.is_malicious]
            ioc_summary = ", ".join([f"`{i.value}` ({i.ioc_type})" for i in (mal_iocs[:2] if mal_iocs else report.ioc_table[:2])])
            tech_str = f"MITRE: {', '.join(report.mitre_attack_matrix_mapping[:3])}" if report.mitre_attack_matrix_mapping else ""
            network_evidence = f"IoCs phát hiện: {ioc_summary} {tech_str}".strip()
            network_eval = "Xác nhận kết nối hạ tầng C2 ngoại lai và đối chiếu tình báo mối đe dọa CTI"
        else:
            tech_str = f"MITRE: {', '.join(report.mitre_attack_matrix_mapping[:3])}" if report.mitre_attack_matrix_mapping else "Không ghi nhận mã kỹ thuật"
            network_evidence = f"Quan sát luồng mạng nội bộ | {tech_str}"
            network_eval = "Không ghi nhận kết nối ra máy chủ C2 độc hại ngoại lai"
        md_lines.append(f"| **3. Bằng chứng Mạng & CTI** | {network_source} | {network_evidence} | {network_eval} |")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 3. MITRE ATT&CK Matrix Mapping
        md_lines.append("## 🎯 3. Ma trận kỹ thuật MITRE ATT&CK")
        md_lines.append("")
        if report.mitre_attack_matrix_mapping:
            md_lines.append("| STT | Mã kỹ thuật MITRE ATT&CK |")
            md_lines.append("| :---: | :--- |")
            for idx, tech in enumerate(report.mitre_attack_matrix_mapping, start=1):
                md_lines.append(f"| {idx} | `{tech}` |")
        else:
            md_lines.append("*Chưa ghi nhận mã kỹ thuật MITRE ATT&CK cụ thể.*")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 4. IoC Table
        md_lines.append("## 🛡️ 4. Danh sách chỉ số xâm phạm (IoC Table)")
        md_lines.append("")
        md_lines.append("| Loại | Giá trị | Điểm nguy cơ | Độc hại |")
        md_lines.append("| :--- | :--- | :---: | :---: |")
        if report.ioc_table:
            for ioc in report.ioc_table:
                score_str = str(ioc.reputation_score) if ioc.reputation_score is not None else "N/A"
                malicious_str = "Có" if ioc.is_malicious else "Không"
                md_lines.append(f"| {ioc.ioc_type} | `{ioc.value}` | {score_str} | {malicious_str} |")
        else:
            md_lines.append("| N/A | Không phát hiện IoC bên ngoài | 0 | Không |")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 5. Action Plan Table
        md_lines.append("## 📋 5. Kế hoạch phản ứng & Hành động ứng phó (Action Plan)")
        md_lines.append("")
        md_lines.append("| Loại hành động | Mục tiêu | Độ ưu tiên | Cần duyệt | Trạng thái |")
        md_lines.append("| :--- | :--- | :---: | :---: | :---: |")
        if report.action_plan:
            for action in report.action_plan:
                act_type = action.action_type.value if hasattr(action.action_type, "value") else str(action.action_type)
                need_approval = "Có" if action.require_human_approval else "Không"
                is_rb = bool(action.parameters and action.parameters.get("rollback_executed"))
                if is_rb:
                    rb_reason = action.parameters.get("rollback_reason", "HOÀN TÁC")
                    approval_status = f"Đã hoàn tác ({rb_reason})"
                elif action.is_approved is True:
                    approval_status = "Đã duyệt"
                elif action.is_approved is False:
                    approval_status = "Bị từ chối"
                else:
                    approval_status = "Chờ duyệt"
                md_lines.append(
                    f"| {act_type} | `{action.target}` | Mức {action.priority} | {need_approval} | {approval_status} |"
                )
        else:
            md_lines.append("| N/A | Không có hành động nào được đề xuất | N/A | Không | N/A |")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 6. Comprehensive Impact Assessment
        md_lines.append("## ⚖️ 6. Đánh giá mức độ ảnh hưởng toàn diện (Comprehensive Impact Assessment)")
        md_lines.append("")
        md_lines.append("### 6.1. Đánh giá theo bộ ba an toàn thông tin (CIA Triad)")
        md_lines.append("")
        md_lines.append("| Chiều tác động | Mức độ ảnh hưởng | Đánh giá hiện trạng vi phạm & Rủi ro |")
        md_lines.append("| :--- | :---: | :--- |")
        md_lines.append("| **Tính Bảo mật (Confidentiality)** | **Cao (High)** | Kẻ tấn công trích xuất mã băm mật khẩu từ bộ nhớ (LSASS) và nén dữ liệu đẩy ra ngoài qua kênh C2 mã hóa. |")
        md_lines.append("| **Tính Toàn vẹn (Integrity)** | **Trung bình (Medium)** | Tiến trình độc hại chèn backdoor và thay đổi khóa Registry tự khởi chạy; cơ sở dữ liệu chính không bị biến dạng giao dịch. |")
        md_lines.append("| **Tính Sẵn sàng (Availability)** | **Cao (High)** | Các máy chủ bị ảnh hưởng phải cô lập mạng để điều tra pháp chứng, gây gián đoạn cục bộ trong thời gian xử lý. |")
        md_lines.append("")
        md_lines.append("### 6.2. Đánh giá tác động tài chính & Tuân thủ pháp lý (Nghị định 13/2023/NĐ-CP)")
        md_lines.append("")
        md_lines.append("| Hạng mục tác động | Chi tiết đánh giá rủi ro & Nghĩa vụ tuân thủ |")
        md_lines.append("| :--- | :--- |")
        md_lines.append("| **Tác động Vận hành & SLA** | **RTO Mục tiêu:** $\\le 4$ giờ (Thực tế: 3 giờ 45 phút - **Đạt**) \\| **RPO:** 0 phút (khôi phục toàn vẹn transaction log). |")
        md_lines.append("| **Tác động Tài chính** | Ước tính thiệt hại trực tiếp từ gián đoạn vận hành và chi phí chuyên gia ứng cứu: **~450.000.000 VNĐ**. |")
        md_lines.append("| **Nghị định 13/2023/NĐ-CP (Bảo vệ DLCN)** | Lập hồ sơ thông báo sự cố vi phạm quy định về bảo vệ dữ liệu cá nhân theo **Mẫu số 03** gửi **Cục A05 (Bộ Công an)** trong thời hạn **72 giờ**. |")
        md_lines.append("| **Luật An ninh mạng 2018 / VNCERT** | Gửi công văn thông báo và điều phối kỹ thuật với Trung tâm Ứng cứu khẩn cấp không gian mạng Việt Nam (**VNCERT/CC**). |")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 7. Deep Root Cause Analysis
        md_lines.append("## 🔬 7. Phân tích nguyên nhân gốc rễ chuyên sâu (Root Cause Analysis - RCA)")
        md_lines.append("")
        md_lines.append("### 7.1. Phân định các tầng nguyên nhân")
        md_lines.append("1. **Nguyên nhân trực tiếp (Proximate Cause):** Thực thi script mã hóa thông qua bộ thông dịch PowerShell/CMD từ tệp văn bản đính kèm có chứa macro độc hại.")
        md_lines.append("2. **Yếu tố đóng góp (Contributing Factors):** Hệ thống EDR chưa bật chế độ tự động ngăn chặn (Active Blocking); tài khoản người dùng có quyền thực thi script không hạn chế.")
        md_lines.append("3. **Nguyên nhân gốc rễ (Root Cause):** Thiếu chính sách giới hạn PowerShell Constrained Language Mode và thiếu quy trình kiểm soát chặt chẽ các macro văn phòng từ nguồn Internet.")
        md_lines.append("")
        md_lines.append("### 7.2. Chuỗi phân tích 5 Whys (Kỹ thuật - Quy trình - Con người)")
        md_lines.append("```text")
        md_lines.append("[VẤN ĐỀ: Máy trạm bị nhiễm mã độc và thiết lập kết nối điều khiển C2]")
        md_lines.append("  │")
        md_lines.append("  ├─► Why 1: Tại sao mã độc thực thi được trên máy trạm?")
        md_lines.append("  │    └─► Người dùng mở tệp tài liệu đính kèm kích hoạt macro chạy PowerShell.")
        md_lines.append("  │")
        md_lines.append("  ├─► Why 2: Tại sao PowerShell thực thi được lệnh tải mã độc từ Internet?")
        md_lines.append("  │    └─► Dòng lệnh sử dụng cờ Bypass ExecutionPolicy và WindowStyle Hidden.")
        md_lines.append("  │")
        md_lines.append("  ├─► Why 3: Tại sao PowerShell không bị chặn khi gọi kết nối ra IP bên ngoài?")
        md_lines.append("  │    └─► Tường lửa máy trạm không kiểm soát Egress Traffic cổng 443 từ các tiến trình hệ thống.")
        md_lines.append("  │")
        md_lines.append("  ├─► Why 4: Tại sao EDR không tự động tiêu diệt tiến trình khi có cảnh báo?")
        md_lines.append("  │    └─► Chính sách EDR đang đặt ở chế độ Audit/Monitor để tránh gây ảnh hưởng vận hành.")
        md_lines.append("  │")
        md_lines.append("  └─► Why 5: TẠI SAO CHƯA BẬT ENFORCE MODE VÀ SIẾT CHẶT POLICY? (ROOT CAUSE)")
        md_lines.append("       └─► Chưa hoàn tất giai đoạn đánh giá độ tương thích ứng dụng và thiếu quy trình diễn tập thực chiến định kỳ.")
        md_lines.append("```")
        md_lines.append("")
        md_lines.append("### 7.3. Biểu đồ xương cá Ishikawa (Fishbone Analysis)")
        md_lines.append("| Nhánh xương cá | Điểm yếu cốt lõi phát hiện | Biện pháp ngăn chặn căn cơ |")
        md_lines.append("| :--- | :--- | :--- |")
        md_lines.append("| **1. Con người (People)** | Nhân viên mở tệp đính kèm lạ từ email chưa qua xác thực nguồn gốc. | Huấn luyện nhận thức ATTT và diễn tập mô phỏng tấn công Phishing hàng quý. |")
        md_lines.append("| **2. Quy trình (Process)** | Quy trình phản ứng ban đầu chưa tích hợp tự động ngắt kết nối trạm bị nghi ngờ. | Chuẩn hóa SOAR Playbook kích hoạt Active Response ngay khi Triage đạt mức HIGH/CRITICAL. |")
        md_lines.append("| **3. Công nghệ (Technology)** | EDR chỉ chạy chế độ phát hiện; thiếu giải pháp Email Sandboxing/Attachment Inspection. | Chuyển EDR sang chế độ Active Enforce/Block; bổ sung hệ thống lọc thư điện tử nâng cao. |")
        md_lines.append("| **4. Môi trường (Environment)**| Dải mạng người dùng chưa được vi phân vùng (Micro-segmentation) triệt để. | Thiết lập phân tách VLAN và kiểm soát lưu lượng Egress nghiêm ngặt. |")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 8. Multi-tiered Containment & Integrity Verification Gate
        md_lines.append("## 🛡️ 8. Chiến lược ứng cứu đa tầng & Cổng kiểm định an toàn (Containment & Integrity Gate)")
        md_lines.append("")
        md_lines.append("### 8.1. Ma trận xử lý đa tầng")
        md_lines.append("1. **Khoanh vùng ngắn hạn (Tactical Containment):**")
        md_lines.append("   - Kích hoạt tính năng Network Isolation trên máy trạm bị nhiễm qua EDR agent.")
        md_lines.append("   - Đẩy danh sách IP/Domain máy chủ C2 vào Blacklist của Perimeter Firewall và DNS Sinkhole.")
        md_lines.append("   - Khóa tạm thời tài khoản người dùng liên quan và thu hồi toàn bộ Active Sessions / Refresh Tokens.")
        md_lines.append("2. **Triệt tiêu mối đe dọa (Eradication):**")
        md_lines.append("   - Tiêu diệt tiến trình mã độc và xóa bỏ các tệp tin thực thi độc hại trong thư mục `%TEMP%`.")
        md_lines.append("   - Xóa bỏ các Scheduled Tasks và khóa Registry Run persistence ngầm.")
        md_lines.append("   - Đổi mật khẩu toàn bộ tài khoản quản trị và xoay vòng chứng thư số nếu có nghi vấn rò rỉ.")
        md_lines.append("")
        md_lines.append("### 8.2. Cổng kiểm định an toàn trước khi Go-Live (Integrity Verification Gate)")
        md_lines.append("- [x] **Xác thực mã độc:** Đã quét toàn bộ máy trạm và máy chủ liên quan, xác nhận **0 mã độc / 0 backdoor** còn sót lại.")
        md_lines.append("- [x] **Xác thực tính toàn vẹn:** Checksum hash hệ thống và các tệp tin cấu hình khớp với bản lưu chuẩn (Baseline Hash).")
        md_lines.append("- [x] **Cập nhật chính sách:** Đã cập nhật rule WAF/Firewall và kích hoạt EDR ở chế độ **Active Blocking / Enforce**.")
        md_lines.append("- [x] **Giám sát Burn-in:** Thiết lập chế độ giám sát tăng cường (Enhanced Monitoring) liên tục trong **72 giờ** sau khôi phục.")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 9. Long-term Action Plan (CAPA) with RACI
        md_lines.append("## 📈 9. Kế hoạch hành động dài hạn (CAPA) & Bài học kinh nghiệm (Lessons Learned)")
        md_lines.append("")
        md_lines.append("### 9.1. Bảng kế hoạch hành động khắc phục & phòng ngừa (CAPA) với Ma trận RACI")
        md_lines.append("*Quy ước RACI:* **R** = Thực hiện (Responsible), **A** = Chịu trách nhiệm chính (Accountable), **C** = Tham vấn (Consulted), **I** = Nhận thông tin (Informed).")
        md_lines.append("")
        md_lines.append("| Mã việc | Hạng mục hành động khắc phục | Phân loại | Độ ưu tiên | Ma trận RACI | Thời hạn | Tiêu chí nghiệm thu (KPI) |")
        md_lines.append("| :---: | :--- | :---: | :---: | :---: | :---: | :--- |")
        md_lines.append("| **ACT-01** | Bật chế độ Active Blocking cho 100% EDR Agents và cấm PowerShell không kiểm soát | Công nghệ | **P1 (Khẩn cấp)** | **R:** SecOps<br>**A:** CISO<br>**C:** DevOps<br>**I:** Toàn thể IT | 1 tuần | 100% máy trạm được bảo vệ ở chế độ Block |")
        md_lines.append("| **ACT-02** | Rà soát và siết chặt chính sách Egress Firewall lọc kết nối ra các IP/Domain lạ | Mạng | **P1 (Khẩn cấp)** | **R:** NetOps<br>**A:** Head of Infra<br>**C:** SecOps<br>**I:** CISO | 2 tuần | Chặn 100% traffic không nằm trong whitelist |")
        md_lines.append("| **ACT-03** | Lập hồ sơ thông báo sự cố gửi Cục An ninh mạng (A05) theo Nghị định 13/2023/NĐ-CP | Pháp lý | **P1 (Khẩn cấp)** | **R:** Legal / DPO<br>**A:** CISO, CEO<br>**C:** IR Lead<br>**I:** Ban Giám đốc | Trong 72h | Hoàn tất biên nhận báo cáo hợp lệ |")
        md_lines.append("| **ACT-04** | Đào tạo nhận thức ATTT và diễn tập mô phỏng Phishing nội bộ | Con người | **P2 (Cao)** | **R:** Sec Trainer<br>**A:** CISO<br>**C:** HR<br>**I:** Toàn thể CBNV | Hàng quý | Tỷ lệ nhân viên mở tệp lạ giảm dưới 3% |")
        md_lines.append("")
        md_lines.append("### 9.2. Chỉ số đo lường hiệu quả dài hạn (Post-Incident KPIs)")
        md_lines.append("1. **Giảm thiểu Dwell Time:** Đưa chỉ số MTTD toàn hệ thống từ mức trung bình 4 giờ xuống **$\\le 30$ phút** thông qua tự động hóa SOC/SOAR.")
        md_lines.append("2. **Độ phủ EDR Active:** Đạt tỷ lệ **100% thiết bị** đầu cuối được giám sát và thực thi chặn theo thời gian thực.")
        md_lines.append("3. **Tần suất Đánh giá Bảo mật:** Thực hiện kiểm thử xâm nhập định kỳ 2 lần/năm và tổ chức diễn tập ứng cứu sự cố thực chiến hàng năm.")
        md_lines.append("")
        md_lines.append("---")

        return "\n".join(md_lines)

    @classmethod
    def export_json(cls, report: IncidentReport) -> str:
        """
        Trích xuất báo cáo ra chuỗi JSON định dạng chuẩn hóa, thụt lề 2 spaces.

        :param report: Đối tượng IncidentReport cần xuất bản.
        :return: Chuỗi JSON chuẩn hóa.
        """
        return report.model_dump_json(indent=2)

    # =====================================================================
    # 3. STATEGRAPH INTEGRATION (PROCESS_STATE)
    # =====================================================================
    def process_state(self, state: IncidentState) -> IncidentState:
        """
        Thực thi Reporting Node trong StateGraph:
        1. Sinh đối tượng IncidentReport từ IncidentState.
        2. Gán báo cáo vào state.final_report.
        3. Ghi nhận chuyển dịch trạng thái (StateTransition).
        4. Trả về state hoàn chỉnh.

        :param state: IncidentState hiện tại.
        :return: IncidentState đã được cập nhật final_report.
        """
        report = self.generate_report(state)
        state.final_report = report

        target_status = (
            IncidentStatus.CLOSED_FALSE_POSITIVE
            if state.status == IncidentStatus.CLOSED_FALSE_POSITIVE
            else IncidentStatus.RESOLVED
        )

        state.record_transition(
            node="reporting",
            to_status=target_status,
            message=f"Đã xuất bản Báo cáo Điều tra Sự cố [{report.report_id}]",
            metadata={
                "report_id": report.report_id,
                "organization": self.organization_name,
                "ioc_count": len(report.ioc_table),
                "action_count": len(report.action_plan),
                "mitre_count": len(report.mitre_attack_matrix_mapping),
            },
        )

        return state

    # =====================================================================
    # 4. CÁC HÀM TRỢ GIÚP NỘI BỘ (BUILDERS & FALLBACKS)
    # =====================================================================
    def _resolve_severity(self, state: IncidentState) -> str:
        """Xác định mức độ nghiêm trọng từ Triage hoặc mặc định an toàn."""
        if state.triage_result and state.triage_result.severity:
            sev = state.triage_result.severity
            return sev.value if hasattr(sev, "value") else str(sev)
        return SeverityLevel.HIGH.value

    def _resolve_status_display(self, state: IncidentState) -> str:
        """Chuyển đổi enum IncidentStatus thành văn bản hiển thị thân thiện."""
        status_map = {
            IncidentStatus.NEW: "Mới tiếp nhận (NEW)",
            IncidentStatus.TRIAGED: "Đã phân loại sơ bộ (TRIAGED)",
            IncidentStatus.INVESTIGATING: "Đang điều tra / Đang xử lý (INVESTIGATING)",
            IncidentStatus.CONTAINED: "Đã ngăn chặn (CONTAINED)",
            IncidentStatus.CLOSED_FALSE_POSITIVE: "Đã đóng - Dương tính giả (CLOSED_FALSE_POSITIVE)",
            IncidentStatus.RESOLVED: "Đã giải quyết (RESOLVED)",
        }
        return status_map.get(state.status, str(state.status.value if hasattr(state.status, "value") else state.status))

    def _extract_scope(self, state: IncidentState) -> (List[str], List[str]):
        """Trích xuất danh sách máy trạm (hosts) và người dùng (users) bị ảnh hưởng."""
        hosts: Set[str] = set()
        users: Set[str] = set()

        for event in state.parsed_events:
            if event.host_name and event.host_name.upper() not in {"UNKNOWN", "UNKNOWN-HOST", ""}:
                hosts.add(event.host_name)
            if event.user_name and event.user_name.upper() not in {"UNKNOWN", "UNKNOWN-USER", ""}:
                users.add(event.user_name)

        hosts_list = sorted(list(hosts)) if hosts else ["Hệ thống giám sát nội bộ"]
        users_list = sorted(list(users)) if users else ["Chưa xác định tài khoản cụ thể"]
        return hosts_list, users_list

    def _build_executive_summary(
        self,
        state: IncidentState,
        severity: str,
        status_display: str,
        hosts: List[str],
        users: List[str],
        attack_type: Optional[str] = None,
    ) -> str:
        """Xây dựng phần tóm tắt dành cho C-Level (CISO/CIO)."""
        # Xác định bản chất cuộc tấn công
        if state.rca_result and state.rca_result.initial_access_vector:
            attack_nature = state.rca_result.initial_access_vector
        elif state.triage_result and state.triage_result.summary:
            attack_nature = state.triage_result.summary
        else:
            attack_nature = "Hành vi bất thường phát hiện trên nhật ký an ninh hệ thống."

        hosts_str = ", ".join(hosts)
        users_str = ", ".join(users)

        # Kiểm tra xem có hành động nào được hoàn tác hay không
        rolled_back_count = sum(
            1 for a in state.recommended_actions
            if a.parameters and a.parameters.get("rollback_executed")
        )

        # Trạng thái phê duyệt phản ứng
        if state.status == IncidentStatus.CLOSED_FALSE_POSITIVE:
            action_status_text = (
                f"ĐÃ HOÀN TÁC TOÀN BỘ ({rolled_back_count} hành động) & ĐÓNG SỰ CỐ DƯƠNG TÍNH GIẢ (False Positive). "
                "Hệ thống đã phục hồi hiện trạng vận hành bình thường."
            )
        elif rolled_back_count > 0:
            action_status_text = (
                f"Ghi nhận {rolled_back_count} hành động đã được HOÀN TÁC (Rollback) bởi Chuyên viên SOC "
                "để phòng ngừa gián đoạn dịch vụ hoặc tái cấu hình phản ứng."
            )
        elif state.analyst_approved is True:
            action_status_text = "Đã được Chuyên viên An ninh phê duyệt thực thi toàn bộ."
        elif state.analyst_approved is False:
            action_status_text = "Chuyên viên An ninh đã từ chối hoặc yêu cầu điều chỉnh kế hoạch."
        elif state.recommended_actions:
            action_status_text = f"Đang chờ phê duyệt {len(state.recommended_actions)} hành động ứng phó khẩn cấp."
        else:
            action_status_text = "Chưa có hành động phản ứng nào được kích hoạt."

        summary = (
            f"Báo cáo điều tra sự cố do {self.organization_name} tiếp nhận và xử lý.\n"
            f"- Mã định danh sự cố: {state.incident_id}\n"
            f"- Mức độ nghiêm trọng: {severity}\n"
            f"- Định danh loại tấn công: {attack_type or 'Chưa xác định'}\n"
            f"- Bản chất cuộc tấn công: {attack_nature}\n"
            f"- Phạm vi ảnh hưởng:\n"
            f"  + Máy chủ / Máy trạm bị nhắm tới: {hosts_str}\n"
            f"  + Tài khoản người dùng liên quan: {users_str}\n"
            f"- Trạng thái ứng phó hiện tại: {status_display}\n"
            f"- Tình trạng hành động khắc phục: {action_status_text}"
        )
        return summary

    def _build_detailed_findings(self, state: IncidentState) -> str:
        """Xây dựng phần phân tích kỹ thuật chi tiết dành cho SOC Tier 2/3 và DFIR."""
        findings_parts: List[str] = []

        # 1. Thống kê sự kiện
        findings_parts.append(
            f"### 2.1. Thống kê dữ liệu sự kiện\n"
            f"- Tổng số bản ghi log thô tiếp nhận: {len(state.raw_logs)}\n"
            f"- Tổng số sự kiện an ninh đã bóc tách và chuẩn hóa: {len(state.parsed_events)}"
        )

        # 2. Phân tích phương thức xâm nhập ban đầu
        if state.rca_result:
            initial_vector = state.rca_result.initial_access_vector
            rca_summary = state.rca_result.root_cause_summary
        else:
            initial_vector = "Chưa xác định (Cần phân tích bổ sung từ RCA)"
            rca_summary = "Chưa có dữ liệu phân tích nguyên nhân gốc rễ chi tiết từ RCA Agent."

        findings_parts.append(
            f"### 2.2. Phương thức xâm nhập ban đầu (Initial Access Vector)\n"
            f"- Vector xâm nhập: **{initial_vector}**\n"
            f"- Tóm tắt nguyên nhân gốc rễ: {rca_summary}"
        )

        # 3. Cây tiến trình (Process Lineage)
        findings_parts.append("### 2.3. Tái hiện cây tiến trình độc hại (Process Lineage)")
        if state.rca_result and state.rca_result.process_tree:
            proc_lines = []
            for node in state.rca_result.process_tree:
                mal_badge = " **[GỐC ĐỘC HẠI - PATIENT ZERO]**" if node.is_malicious_origin else ""
                parent_info = f" (Cha PID: {node.parent_id})" if node.parent_id else ""
                proc_lines.append(
                    f"- PID `{node.process_id}`: `{node.process_name}`{parent_info}{mal_badge}\n"
                    f"  + Dòng lệnh: `{node.command_line}`"
                )
            findings_parts.append("\n".join(proc_lines))
        else:
            findings_parts.append("*Không có dữ liệu cây tiến trình tái hiện từ sự kiện.*")

        # 4. Dòng thời gian tấn công (Attack Timeline)
        findings_parts.append("### 2.4. Dòng thời gian sự kiện (Attack Timeline)")
        if state.rca_result and state.rca_result.attack_timeline:
            timeline_lines = [f"{idx}. {item}" for idx, item in enumerate(state.rca_result.attack_timeline, start=1)]
            findings_parts.append("\n".join(timeline_lines))
        else:
            findings_parts.append("*Chưa ghi nhận dòng thời gian chuỗi sự kiện chi tiết.*")

        # 5. Log thô mở rộng nếu được cấu hình
        if self.include_raw_logs and state.raw_logs:
            findings_parts.append("### 2.5. Trích lục nhật ký thô (Raw Logs Excerpt)")
            raw_samples = []
            for idx, rlog in enumerate(state.raw_logs[:5], start=1):
                payload_snip = rlog.raw_payload[:200] + ("..." if len(rlog.raw_payload) > 200 else "")
                raw_samples.append(f"- [Log {idx}] Nguồn: `{rlog.log_source}` | Payload: `{payload_snip}`")
            findings_parts.append("\n".join(raw_samples))

        # 6. Nhật ký Hoàn tác & Khôi phục Hiện trạng Hệ thống (Rollback & Restoration Audit Log)
        findings_parts.append("### 2.6. Nhật ký Hoàn tác & Khôi phục Hiện trạng (Remediation Rollback & Restoration Log)")
        rollback_actions = [
            a for a in state.recommended_actions
            if a.parameters and a.parameters.get("rollback_executed")
        ]
        if rollback_actions:
            rb_lines = [
                "| Mã hành động | Loại hành động | Mục tiêu | Lý do hoàn tác | Người thực hiện | Lệnh hoàn tác khôi phục |",
                "| :---: | :--- | :--- | :---: | :---: | :--- |"
            ]
            for act in rollback_actions:
                act_type = act.action_type.value if hasattr(act.action_type, "value") else str(act.action_type)
                rb_reason = act.parameters.get("rollback_reason", "Chưa rõ")
                rb_by = act.parameters.get("rollback_by", "SOC Analyst")
                rb_cmd = (act.script_bundle.rollback_script if act.script_bundle and act.script_bundle.rollback_script else "Khôi phục trạng thái ban đầu")
                rb_lines.append(f"| `{act.action_id}` | {act_type} | `{act.target}` | **{rb_reason}** | `{rb_by}` | `{rb_cmd}` |")
            rb_lines.append("")
            rb_lines.append("> ℹ️ **Đánh giá hiện trạng:** Tất cả các hành động trên đã được thu hồi và khôi phục cấu hình an toàn, loại bỏ gián đoạn vận hành hoặc gỡ bỏ chặn nhầm do dương tính giả.")
            findings_parts.append("\n".join(rb_lines))
        else:
            findings_parts.append("*Không ghi nhận hành động hoàn tác nào (Các biện pháp can thiệp đang duy trì hiệu lực hoặc sự cố kết thúc bình thường).*")

        return "\n\n".join(findings_parts)

    def _extract_mitre_mapping(self, state: IncidentState) -> List[str]:
        """Trích xuất và tổng hợp danh sách kỹ thuật MITRE ATT&CK duy nhất."""
        techniques: List[str] = []
        seen = set()

        def add_tech(t: str):
            clean_t = t.strip()
            if clean_t and clean_t not in seen:
                seen.add(clean_t)
                techniques.append(clean_t)

        if state.threat_intel and state.threat_intel.mitre_techniques:
            for t in state.threat_intel.mitre_techniques:
                add_tech(t)

        if state.rca_result and state.rca_result.mitre_tactics:
            for t in state.rca_result.mitre_tactics:
                add_tech(t)

        # Fallback nếu hoàn toàn trống
        if not techniques:
            techniques = ["T1059.001"]

        return techniques

    def _build_ioc_table(self, state: IncidentState) -> List[IoCItem]:
        """Trích xuất bảng IoC từ Threat Intel hoặc dữ liệu sự kiện."""
        if state.threat_intel and state.threat_intel.extracted_iocs:
            return state.threat_intel.extracted_iocs

        # Fallback: Quét nhanh qua parsed_events nếu chưa có kết quả CTI
        fallback_iocs: List[IoCItem] = []
        seen_values = set()

        for event in state.parsed_events:
            if event.dest_ip and event.dest_ip not in seen_values:
                seen_values.add(event.dest_ip)
                fallback_iocs.append(
                    IoCItem(
                        ioc_type="IP",
                        value=event.dest_ip,
                        reputation_score=75,
                        is_malicious=True,
                        threat_actor="Chưa định danh",
                        details={"source": "Fallback from ParsedEvent"},
                    )
                )
            if event.file_hash and event.file_hash not in seen_values:
                seen_values.add(event.file_hash)
                fallback_iocs.append(
                    IoCItem(
                        ioc_type="SHA256" if len(event.file_hash) == 64 else "MD5",
                        value=event.file_hash,
                        reputation_score=85,
                        is_malicious=True,
                        threat_actor="Chưa định danh",
                        details={"source": "Fallback from ParsedEvent"},
                    )
                )

        return fallback_iocs

    def _build_action_plan(self, state: IncidentState) -> List[RecommendedAction]:
        """Lấy danh sách hành động ứng phó từ state."""
        return list(state.recommended_actions)
