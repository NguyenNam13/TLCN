# -*- coding: utf-8 -*-
"""
generate_week5_report.py
Tạo tài liệu Word (.docx) nộp báo cáo kết quả Tuần 5:
BẢN ĐẶC TẢ CHI TIẾT PROMPTS, SCHEMAS VÀ TOOLS CỦA 6 AGENT
"""

import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=140, right=140):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(f'''
        <w:tcMar {nsdecls("w")}>
            <w:top w:w="{top}" w:type="dxa"/>
            <w:bottom w:w="{bottom}" w:type="dxa"/>
            <w:left w:w="{left}" w:type="dxa"/>
            <w:right w:w="{right}" w:type="dxa"/>
        </w:tcMar>
    ''')
    tcPr.append(tcMar)

def set_table_borders(table, color="D0D7DE", sz="4"):
    tblPr = table._tbl.tblPr
    borders = parse_xml(f'''
        <w:tblBorders {nsdecls("w")}>
            <w:top w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>
            <w:left w:val="none"/>
            <w:bottom w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>
            <w:right w:val="none"/>
            <w:insideH w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>
            <w:insideV w:val="none"/>
        </w:tblBorders>
    ''')
    tblPr.append(borders)

def set_code_borders(table, border_color="CBD5E1"):
    tblPr = table._tbl.tblPr
    borders = parse_xml(f'''
        <w:tblBorders {nsdecls("w")}>
            <w:top w:val="single" w:sz="6" w:space="0" w:color="{border_color}"/>
            <w:left w:val="single" w:sz="6" w:space="0" w:color="{border_color}"/>
            <w:bottom w:val="single" w:sz="6" w:space="0" w:color="{border_color}"/>
            <w:right w:val="single" w:sz="6" w:space="0" w:color="{border_color}"/>
            <w:insideH w:val="none"/>
            <w:insideV w:val="none"/>
        </w:tblBorders>
    ''')
    tblPr.append(borders)

def build_week5_docx():
    doc = docx.Document()
    for section in doc.sections:
        section.page_width = Inches(8.27)
        section.page_height = Inches(11.69)
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    COLOR_PRIMARY = RGBColor(27, 54, 93)     # Deep Navy #1B365D
    COLOR_SECONDARY = RGBColor(43, 94, 138)  # Slate Blue #2B5E8A
    COLOR_DARK = RGBColor(34, 34, 34)        # Charcoal #222222
    COLOR_MUTED = RGBColor(100, 116, 139)

    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Times New Roman'
    normal_style.font.size = Pt(12)
    normal_style.font.color.rgb = COLOR_DARK
    normal_style.paragraph_format.line_spacing = 1.25
    normal_style.paragraph_format.space_after = Pt(4)

    def add_h1(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(16)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)
        r.font.name = 'Times New Roman'
        r.font.size = Pt(15)
        r.font.bold = True
        r.font.color.rgb = COLOR_PRIMARY
        return p

    def add_h2(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(12)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)
        r.font.name = 'Times New Roman'
        r.font.size = Pt(13)
        r.font.bold = True
        r.font.color.rgb = COLOR_SECONDARY
        return p

    def add_body(text, bold_prefix=None):
        p = doc.add_paragraph()
        if bold_prefix:
            rb = p.add_run(bold_prefix)
            rb.font.name = 'Times New Roman'
            rb.font.bold = True
        r = p.add_run(text)
        r.font.name = 'Times New Roman'
        return p

    def add_bullet(text, bold_prefix=None):
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.line_spacing = 1.2
        if bold_prefix:
            rb = p.add_run(bold_prefix)
            rb.font.name = 'Times New Roman'
            rb.font.bold = True
        r = p.add_run(text)
        r.font.name = 'Times New Roman'
        return p

    def add_code(code_text):
        tbl = doc.add_table(rows=1, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = tbl.cell(0, 0)
        cell.width = Inches(6.27)
        set_cell_background(cell, "F8FAFC")
        set_cell_margins(cell, top=120, bottom=120, left=160, right=140)
        set_code_borders(tbl, "CBD5E1")
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.15
        lines = code_text.strip().split('\n')
        for i, l in enumerate(lines):
            r = p.add_run(l + ('\n' if i < len(lines)-1 else ''))
            r.font.name = 'Consolas'
            r.font.size = Pt(9.5)
            r.font.color.rgb = RGBColor(30, 41, 59)
        doc.add_paragraph()

    # Bìa
    p_hdr = doc.add_paragraph()
    p_hdr.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_hdr = p_hdr.add_run("TRƯỜNG ĐẠI HỌC SƯ PHẠM KỸ THUẬT TP.HCM\nKHOA CÔNG NGHỆ THÔNG TIN - BỘ MÔN ATTT\n")
    r_hdr.font.name = 'Times New Roman'
    r_hdr.font.size = Pt(12)
    r_hdr.font.bold = True
    r_hdr.font.color.rgb = COLOR_PRIMARY

    p_line = doc.add_paragraph()
    p_line.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_line.paragraph_format.space_after = Pt(24)
    p_line.add_run("═════════════════════════════════════").font.color.rgb = COLOR_MUTED

    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_after = Pt(10)
    r_t = p_title.add_run("BẢN ĐẶC TẢ CHI TIẾT PROMPTS, SCHEMAS VÀ TOOLS\nCỦA HỆ THỐNG 6 AGENT ĐIỀU TRA SỰ CỐ SOC\n(Sản phẩm bàn giao trọng tâm Tuần 5)\n")
    r_t.font.name = 'Times New Roman'
    r_t.font.size = Pt(17)
    r_t.font.bold = True
    r_t.font.color.rgb = COLOR_PRIMARY

    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_after = Pt(20)
    r_s = p_sub.add_run("Đề tài: Xây dựng hệ thống Multi-Agent ứng dụng LLM hỗ trợ điều tra sự cố an ninh mạng\nSinh viên: Phan Trường Đô (23162020) & Nguyễn Phạm Hoài Nam (23162059)\nGVHD: ThS. Đinh Công Đoan")
    r_s.font.name = 'Times New Roman'
    r_s.font.size = Pt(12)
    r_s.font.italic = True

    doc.add_page_break()

    # Nội dung
    add_h1("1. TỔNG QUAN PHÂN CÔNG THIẾT KẾ CHI TIẾT (TUẦN 5: 18/10 - 24/10)")
    add_body("Trong giai đoạn Tuần 5, nhóm sinh viên chia đôi lực lượng thực hiện song song việc thiết kế chi tiết từng tác tử (Prompts, Schemas, Tools):")
    add_bullet("Cụm Agent tiếp nhận, phát hiện và tình báo (Nguyễn Phạm Hoài Nam phụ trách): Ingestion Agent, Detection & Triage Agent, Threat Intelligence Agent.")
    add_bullet("Cụm Agent phân tích chuyên sâu, phản ứng và báo cáo (Phan Trường Đô phụ trách): Root Cause Analysis (RCA) Agent, Response Recommendation Agent, Reporting Agent.")

    add_h1("2. ĐẶC TẢ CHI TIẾT CỤM AGENT ĐẦU VÀO (NGUYỄN PHẠM HOÀI NAM)")
    
    add_h2("2.1. Data Ingestion Agent")
    add_body("Vai trò: Tiếp nhận log thô đa nguồn, làm sạch và chuẩn hóa sang đối tượng ParsedEvent.", bold_prefix="• ")
    add_body("Tools tích hợp: LogParserTool (parse_sysmon, parse_zeek_conn, parse_windows_evtx, regex bóc tách base64).", bold_prefix="• ")
    add_body("System Prompt chuẩn hóa:", bold_prefix="• ")
    add_code(
"""Bạn là Data Ingestion Agent, một chuyên gia bóc tách và chuẩn hóa log an ninh mạng.
Nhiệm vụ: Chuyển đổi dữ liệu log thô (Sysmon, Zeek, EVTX) thành cấu trúc ParsedEvent.
Quy tắc:
1. Trích xuất chính xác: event_id, timestamp, source_type, host_name, user_name, process_name, command_line, IPs, ports, file_hash.
2. Nếu gặp PowerShell mã hóa (-enc), tự động trích xuất chuỗi Base64 và đưa vào raw_attributes.
3. Đầu ra bắt buộc tuân thủ schema ParsedEvent."""
    )

    add_h2("2.2. Detection & Triage Agent")
    add_body("Vai trò: Chuyên viên SOC Tier 1 lọc nhiễu cảnh báo, phát hiện bất thường và tính toán điểm rủi ro.", bold_prefix="• ")
    add_body("Cơ chế suy luận: Chain-of-Thought (Observation -> Context -> Risk Score -> Conclusion).", bold_prefix="• ")
    add_body("System Prompt & Schema:", bold_prefix="• ")
    add_code(
"""Bạn là Detection & Triage Agent, đóng vai trò chuyên viên phân tích SOC Tier 1 cao cấp.
Nhiệm vụ: Thẩm định sự kiện, phân loại True Positive vs False Positive, xác định Severity (LOW/MED/HIGH/CRITICAL).
Đầu ra tuân thủ TriageOutput:
{
  "is_incident": true/false,
  "confidence_score": float (0.0-1.0),
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "summary": "Tóm tắt căn cứ phán đoán...",
  "rule_or_model": "LLM-Triage-Engine"
}"""
    )

    add_h2("2.3. Threat Intelligence (CTI) Agent")
    add_body("Vai trò: Tra cứu uy tín IoC (IP, Domain, File Hash) và ánh xạ sang khung MITRE ATT&CK.", bold_prefix="• ")
    add_body("Tools tích hợp: ThreatIntelTools (lookup_ip, match_mitre_technique).", bold_prefix="• ")
    add_body("System Prompt:", bold_prefix="• ")
    add_code(
"""Bạn là Threat Intelligence (CTI) Agent.
Nhiệm vụ:
1. Bóc tách toàn bộ IoC từ sự cố, lọc bỏ IP nội bộ (Private IPs).
2. Tra cứu điểm độc hại (Reputation Score) qua VirusTotal/AbuseIPDB feeds.
3. Ánh xạ các hành vi sang mã kỹ thuật MITRE ATT&CK (ví dụ: T1059.001, T1046).
4. Xuất dữ liệu theo ThreatIntelEnrichment schema."""
    )

    add_h1("3. ĐẶC TẢ CHI TIẾT CỤM AGENT CHUYÊN SÂU & ĐẦU RA (PHAN TRƯỜNG ĐÔ)")

    add_h2("3.1. Root Cause Analysis (RCA) Agent")
    add_body("Vai trò: Chuyên viên điều tra số SOC Tier 3 tái hiện phả hệ tiến trình và truy vết vector xâm nhập.", bold_prefix="• ")
    add_body("System Prompt:", bold_prefix="• ")
    add_code(
"""Bạn là Root Cause Analysis (RCA) Agent, chuyên gia điều tra số DFIR.
Nhiệm vụ:
1. Tái hiện cây tiến trình (Process Lineage): Lần ngược ParentImage tìm tiến trình gốc.
2. Xây dựng Attack Timeline theo trình tự thời gian.
3. Xác định vector tấn công ban đầu (Initial Access: Phishing, Exploit, etc.).
4. Xuất dữ liệu theo RootCauseAnalysis schema."""
    )

    add_h2("3.2. Response Recommendation Agent")
    add_body("Vai trò: Chỉ huy ứng phó sự cố đề xuất kế hoạch ngăn chặn theo chuẩn NIST SP 800-61.", bold_prefix="• ")
    add_body("Tools tích hợp: ResponsePlaybooks (malware_incident_playbook, phishing_credential_playbook).", bold_prefix="• ")
    add_body("System Prompt:", bold_prefix="• ")
    add_code(
"""Bạn là Response Recommendation Agent.
Nhiệm vụ: Xây dựng danh sách hành động ngăn chặn (ISOLATE_HOST, KILL_PROCESS, BLOCK_IP, REVOKE_USER).
Quy tắc:
- Mọi hành động có mức độ ảnh hưởng lớn đều bắt buộc gán require_human_approval = True.
- Ưu tiên cô lập nguồn lây nhiễm trước, thu hồi phiên người dùng và tiêu diệt tiến trình.
- Xuất danh sách theo List[RecommendedAction]."""
    )

    add_h2("3.3. Reporting Agent")
    add_body("Vai trò: Tổng hợp toàn bộ hồ sơ sự cố sinh báo cáo chuyên nghiệp hoàn chỉnh.", bold_prefix="• ")
    add_body("System Prompt:", bold_prefix="• ")
    add_code(
"""Bạn là Reporting Agent, phụ trách tổng hợp Báo cáo Sự cố An ninh Mạng toàn diện.
Nhiệm vụ:
1. Executive Summary: Tóm lược sự cố dành cho cấp quản lý.
2. Technical Findings: Báo cáo kỹ thuật chi tiết tiến trình và kỹ thuật ATT&CK.
3. Bảng IoC Table và Bảng Action Plan.
4. Xuất kết quả theo IncidentReport schema."""
    )

    add_h1("4. KẾT QUẢ KIỂM CHỨNG VÀ TRẠNG THÁI MÃ NGUỒN")
    add_body("Toàn bộ thiết kế trên đã được hiện thực hóa trực tiếp thành các mô-đun mã nguồn sạch trong dự án:")
    add_bullet("src/core/schemas.py: Định nghĩa hoàn chỉnh toàn bộ 8 cấu trúc dữ liệu Pydantic v2.")
    add_bullet("src/core/state.py: Định nghĩa IncidentState và IncidentStateDict cho LangGraph StateGraph.")
    add_bullet("src/agents/prompts.py: Bộ System Prompts hoàn chỉnh cho cả 6 Agent.")
    add_bullet("src/tools/: Các bộ công cụ phân tích log (parsers.py), tra cứu CTI (threat_intel.py) và kịch bản ứng phó (playbooks.py).")
    add_bullet("tests/: 8/8 Unit tests kiểm thử Schemas và Tools vượt qua 100%.")

    out_file = "/home/nam/Desktop/TLCN/Bao_Cao_Thiet_Ke_Chi_Tiet_Tuan_5.docx"
    doc.save(out_file)
    print(f"Week 5 Report generated at: {out_file}")

if __name__ == "__main__":
    build_week5_docx()
