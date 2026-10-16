# -*- coding: utf-8 -*-
"""
Script to generate the comprehensive Word (.docx) report for Weeks 2, 3, and 4.
Topic: XÂY DỰNG HỆ THỐNG MULTI-AGENT ỨNG DỤNG LLM HỖ TRỢ ĐIỀU TRA SỰ CỐ AN NINH MẠNG
Authors: Phan Trường Đô (23162020) & Nguyễn Phạm Hoài Nam (23162059)
Supervisor: ThS. Đinh Công Đoan
"""

import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import qn, nsdecls

def set_cell_background(cell, fill_hex):
    """Sets background color of a table cell."""
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=120, bottom=120, left=160, right=160):
    """Sets cell padding (in dxa)."""
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

def set_table_borders(table, color="D0D7DE", sz="4", val="single"):
    """Sets subtle borders for a table."""
    tblPr = table._tbl.tblPr
    borders = parse_xml(f'''
        <w:tblBorders {nsdecls("w")}>
            <w:top w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>
            <w:left w:val="none"/>
            <w:bottom w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>
            <w:right w:val="none"/>
            <w:insideH w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>
            <w:insideV w:val="none"/>
        </w:tblBorders>
    ''')
    tblPr.append(borders)

def set_callout_borders(table, border_color="1B365D"):
    """Sets callout style: thick left border, no top/bottom/right."""
    tblPr = table._tbl.tblPr
    borders = parse_xml(f'''
        <w:tblBorders {nsdecls("w")}>
            <w:top w:val="none"/>
            <w:left w:val="single" w:sz="24" w:space="0" w:color="{border_color}"/>
            <w:bottom w:val="none"/>
            <w:right w:val="none"/>
            <w:insideH w:val="none"/>
            <w:insideV w:val="none"/>
        </w:tblBorders>
    ''')
    tblPr.append(borders)

def set_code_borders(table, border_color="CBD5E1"):
    """Sets code block border."""
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

def create_document():
    doc = docx.Document()
    
    # Page Setup: A4, 1 inch margins (1440 dxa = 1 inch)
    for section in doc.sections:
        section.page_width = Inches(8.27)  # A4 width
        section.page_height = Inches(11.69) # A4 height
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)
    
    # Base Color Palette
    COLOR_PRIMARY = RGBColor(27, 54, 93)     # Deep Navy #1B365D
    COLOR_SECONDARY = RGBColor(43, 94, 138)  # Slate Blue #2B5E8A
    COLOR_DARK = RGBColor(34, 34, 34)        # Charcoal Text #222222
    COLOR_MUTED = RGBColor(100, 116, 139)    # Muted Slate #64748B
    
    # Configure Normal Style
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Times New Roman'
    normal_style.font.size = Pt(12)
    normal_style.font.color.rgb = COLOR_DARK
    normal_style.paragraph_format.line_spacing = 1.25
    normal_style.paragraph_format.space_after = Pt(4)
    normal_style.paragraph_format.space_before = Pt(0)
    
    # Helper to add headings
    def add_h1(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(16)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.name = 'Times New Roman'
        run.font.size = Pt(16)
        run.font.bold = True
        run.font.color.rgb = COLOR_PRIMARY
        return p

    def add_h2(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(12)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.name = 'Times New Roman'
        run.font.size = Pt(13.5)
        run.font.bold = True
        run.font.color.rgb = COLOR_SECONDARY
        return p

    def add_h3(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.name = 'Times New Roman'
        run.font.size = Pt(12)
        run.font.bold = True
        run.font.color.rgb = COLOR_DARK
        return p

    def add_body(text, bold_prefix=None, italic=False):
        p = doc.add_paragraph()
        if bold_prefix:
            r_pre = p.add_run(bold_prefix)
            r_pre.font.name = 'Times New Roman'
            r_pre.font.size = Pt(12)
            r_pre.font.bold = True
            r_pre.font.color.rgb = COLOR_DARK
        run = p.add_run(text)
        run.font.name = 'Times New Roman'
        run.font.size = Pt(12)
        run.font.italic = italic
        run.font.color.rgb = COLOR_DARK
        return p

    def add_bullet(text, bold_prefix=None, level=0):
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.line_spacing = 1.2
        if level > 0:
            p.paragraph_format.left_indent = Inches(0.25 * (level + 1))
        if bold_prefix:
            r_pre = p.add_run(bold_prefix)
            r_pre.font.name = 'Times New Roman'
            r_pre.font.size = Pt(12)
            r_pre.font.bold = True
            r_pre.font.color.rgb = COLOR_DARK
        run = p.add_run(text)
        run.font.name = 'Times New Roman'
        run.font.size = Pt(12)
        run.font.color.rgb = COLOR_DARK
        return p

    def add_callout(text, title=None, border_color="1B365D", fill_hex="F4F6F9"):
        tbl = doc.add_table(rows=1, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = tbl.cell(0, 0)
        cell.width = Inches(6.27)
        set_cell_background(cell, fill_hex)
        set_cell_margins(cell, top=140, bottom=140, left=200, right=160)
        set_callout_borders(tbl, border_color)
        
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.line_spacing = 1.2
        if title:
            rt = p.add_run(title + "\n")
            rt.font.name = 'Times New Roman'
            rt.font.size = Pt(12)
            rt.font.bold = True
            rt.font.color.rgb = COLOR_PRIMARY
        r = p.add_run(text)
        r.font.name = 'Times New Roman'
        r.font.size = Pt(11.5)
        r.font.italic = True
        r.font.color.rgb = COLOR_DARK
        doc.add_paragraph() # Spacing

    def add_code_block(code_text):
        tbl = doc.add_table(rows=1, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = tbl.cell(0, 0)
        cell.width = Inches(6.27)
        set_cell_background(cell, "F8FAFC")
        set_cell_margins(cell, top=140, bottom=140, left=180, right=160)
        set_code_borders(tbl, "CBD5E1")
        
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.15
        lines = code_text.strip().split('\n')
        for i, line in enumerate(lines):
            r = p.add_run(line + ('\n' if i < len(lines)-1 else ''))
            r.font.name = 'Consolas'
            r.font.size = Pt(9.5)
            r.font.color.rgb = RGBColor(30, 41, 59)
        doc.add_paragraph() # Spacing

    # ==================== TRANG BÌA & THÔNG TIN ====================
    title_p = doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_p.paragraph_format.space_before = Pt(10)
    title_p.paragraph_format.space_after = Pt(4)
    r = title_p.add_run("TRƯỜNG ĐẠI HỌC SƯ PHẠM KỸ THUẬT THÀNH PHỐ HỒ CHÍ MINH\nKHOA CÔNG NGHỆ THÔNG TIN\nBỘ MÔN AN TOÀN THÔNG TIN\n")
    r.font.name = 'Times New Roman'
    r.font.size = Pt(12)
    r.font.bold = True
    r.font.color.rgb = COLOR_PRIMARY
    
    line_p = doc.add_paragraph()
    line_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    line_p.paragraph_format.space_after = Pt(28)
    r_line = line_p.add_run("═════════════════════════════════════")
    r_line.font.color.rgb = COLOR_MUTED
    
    rep_title = doc.add_paragraph()
    rep_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    rep_title.paragraph_format.space_after = Pt(12)
    r_rt = rep_title.add_run("BÁO CÁO KẾT QUẢ THỰC HIỆN NHIỆM VỤ\nTUẦN 2 – TUẦN 3 – TUẦN 4\n")
    r_rt.font.name = 'Times New Roman'
    r_rt.font.size = Pt(18)
    r_rt.font.bold = True
    r_rt.font.color.rgb = COLOR_PRIMARY

    sub_title = doc.add_paragraph()
    sub_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub_title.paragraph_format.space_after = Pt(24)
    r_sub = sub_title.add_run("ĐỀ TÀI: XÂY DỰNG HỆ THỐNG MULTI-AGENT ỨNG DỤNG LLM\nHỖ TRỢ ĐIỀU TRA SỰ CỐ AN NINH MẠNG\n(Học phần: Tiểu luận chuyên ngành An toàn thông tin)")
    r_sub.font.name = 'Times New Roman'
    r_sub.font.size = Pt(13)
    r_sub.font.bold = True
    r_sub.font.color.rgb = COLOR_SECONDARY

    # Box thông tin sinh viên
    info_table = doc.add_table(rows=5, cols=2)
    info_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    info_table.autofit = False
    col_widths = [Inches(2.4), Inches(3.8)]
    
    info_data = [
        ("Giảng viên hướng dẫn:", "ThS. Đinh Công Đoan"),
        ("Sinh viên thực hiện 1:", "Phan Trường Đô – MSSV: 23162020"),
        ("Sinh viên thực hiện 2:", "Nguyễn Phạm Hoài Nam – MSSV: 23162059"),
        ("Giai đoạn thực hiện:", "Tuần 2 đến Tuần 4 (27/09/2026 – 17/10/2026)"),
        ("Sản phẩm bàn giao:", "Bản thảo Chương 1, Chương 2 & Tài liệu Kiến trúc Hệ thống")
    ]
    for row_idx, (k, v) in enumerate(info_data):
        row = info_table.rows[row_idx]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width, c1.width = col_widths[0], col_widths[1]
        set_cell_background(c0, "F8FAFC")
        set_cell_background(c1, "F8FAFC")
        set_cell_margins(c0, 80, 80, 100, 100)
        set_cell_margins(c1, 80, 80, 100, 100)
        
        p0 = c0.paragraphs[0]
        p0.paragraph_format.space_after = Pt(2)
        r0 = p0.add_run(k)
        r0.font.name = 'Times New Roman'
        r0.font.bold = True
        r0.font.size = Pt(11.5)
        
        p1 = c1.paragraphs[0]
        p1.paragraph_format.space_after = Pt(2)
        r1 = p1.add_run(v)
        r1.font.name = 'Times New Roman'
        r1.font.size = Pt(11.5)
        
    set_table_borders(info_table, "CBD5E1", "6")

    doc.add_paragraph().paragraph_format.space_after = Pt(24)
    
    date_p = doc.add_paragraph()
    date_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_date = date_p.add_run("Thành phố Hồ Chí Minh, Tháng 10 Năm 2026")
    r_date.font.name = 'Times New Roman'
    r_date.font.italic = True
    r_date.font.size = Pt(11)
    r_date.font.color.rgb = COLOR_MUTED

    doc.add_page_break()

    # ==================== PHẦN I ====================
    add_h1("PHẦN I: THÔNG TIN TỔNG QUAN VÀ BẢNG PHÂN RÃ NHIỆM VỤ (TASK BREAKDOWN)")
    
    add_body("Báo cáo này được xây dựng nhằm chuẩn hóa và hiện thực hóa chi tiết các nhiệm vụ kỹ thuật trong giai đoạn 3 tuần đầu tiên của Đề tài Tiểu luận Chuyên ngành: ", bold_prefix="Mục đích báo cáo: ")
    add_body("«Xây dựng hệ thống Multi-Agent ứng dụng LLM hỗ trợ điều tra sự cố an ninh mạng». Nội dung bám sát tiến độ đã cam kết với Giảng viên hướng dẫn trong Đề cương chi tiết (Mẫu DC-03), tuân thủ quy trình chuẩn hóa nhiệm vụ theo nguyên tắc Planning and Task Breakdown, phân định rõ ràng trách nhiệm của từng thành viên (Nguyễn Phạm Hoài Nam và Phan Trường Đô).")

    add_h2("1. Tóm tắt kế hoạch phân công giai đoạn Tuần 2 – Tuần 4")
    
    # Bảng phân công 3 tuần
    summary_table = doc.add_table(rows=4, cols=5)
    summary_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    summary_table.autofit = False
    widths = [Inches(0.7), Inches(1.1), Inches(1.7), Inches(1.8), Inches(1.2)]
    
    headers = ["Tuần", "Thời gian", "Hạng mục trọng tâm", "Phân công chi tiết", "Sản phẩm bàn giao"]
    hdr_row = summary_table.rows[0]
    for idx, text in enumerate(headers):
        cell = hdr_row.cells[idx]
        cell.width = widths[idx]
        set_cell_background(cell, "1B365D")
        set_cell_margins(cell, 120, 120, 100, 100)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(text)
        r.font.name = 'Times New Roman'
        r.font.bold = True
        r.font.size = Pt(10.5)
        r.font.color.rgb = RGBColor(255, 255, 255)
        
    t_data = [
        ("Tuần 2", "27/09 - 03/10", "Nghiên cứu nền tảng & Tổng quan", 
         "• Nam: NIST SP 800-61, Log format (Sysmon, Zeek, EVTX)\n• Đô: LLM, Prompt Engineering, Structured Output, Tool Calling", 
         "Bản thảo Báo cáo Chương 1 (Phần 1)"),
        ("Tuần 3", "04/10 - 10/10", "Nghiên cứu Agent & Tri thức an ninh", 
         "• Nam: Threat Intel, MITRE ATT&CK (STIX/TAXII)\n• Đô: Kiến trúc LangGraph, State Management, Agent Orchestration", 
         "Bản thảo Báo cáo Chương 1 (Phần 2 & Khung Chương 2)"),
        ("Tuần 4", "11/10 - 17/10", "Đặc tả yêu cầu & Kiến trúc hệ thống", 
         "• Cả nhóm: 3 Kịch bản sự cố & Luồng dữ liệu chung\n• Đô: Thiết kế kiến trúc StateGraph điều phối\n• Nam: Thiết kế Schema I/O chuẩn (Pydantic)", 
         "Tài liệu System Architecture & Sequence Diagram")
    ]
    
    for row_idx, row_data in enumerate(t_data):
        row = summary_table.rows[row_idx + 1]
        bg_col = "FFFFFF" if row_idx % 2 == 0 else "F8FAFC"
        for col_idx, text in enumerate(row_data):
            cell = row.cells[col_idx]
            cell.width = widths[col_idx]
            set_cell_background(cell, bg_col)
            set_cell_margins(cell, 100, 100, 100, 100)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.line_spacing = 1.15
            if col_idx == 0 or col_idx == 1:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r = p.add_run(text)
            r.font.name = 'Times New Roman'
            r.font.size = Pt(10)
            
    set_table_borders(summary_table, "CBD5E1", "4")
    doc.add_paragraph().paragraph_format.space_after = Pt(8)

    add_h2("2. Bảng phân rã nhiệm vụ kỹ thuật chi tiết (Task Breakdown)")
    add_body("Theo nguyên tắc chia nhỏ nhiệm vụ độc lập, có thể đo lường và kiểm chứng (Acceptance Criteria & Verification), các công việc được phân rã thành các gói công việc cụ thể như sau:")

    tasks = [
        ("Task 2.1 (Nam)", "Nghiên cứu quy trình NIST SP 800-61 & Format Log an ninh mạng",
         "Nghiên cứu chuyên sâu vòng đời xử lý sự cố an ninh mạng 4 giai đoạn của NIST SP 800-61 (Rev 2 & Rev 3); phân tích các điểm nghẽn thực tế tại trung tâm SOC (Alert Fatigue, MTTR, kỹ năng phân tích). Phân tích cấu trúc chi tiết, các trường thông tin trọng yếu của log Sysmon (Event ID 1, 3, 7, 11, 13), Zeek (conn, dns, http, ssl) và Windows EVTX (4624, 4625, 4688).",
         ["Văn bản hóa đầy đủ 4 giai đoạn NIST SP 800-61 gắn với chức năng hệ sinh thái Agent.",
          "Bảng tổng hợp chi tiết cấu trúc các Event ID cốt lõi của Sysmon, Zeek, EVTX và ánh xạ trường dữ liệu."],
         "Đối chiếu chéo với dataset log thực tế trích xuất từ môi trường lab; thẩm định tính chính xác của các trường log.",
         "Bản thảo Báo cáo Chương 1 (Mục 1.1 & Mục 1.2)."),
         
        ("Task 2.2 (Đô)", "Nghiên cứu cơ sở lý thuyết LLM, Prompting & Tool Calling",
         "Nghiên cứu nguyên lý hoạt động của LLM, cơ chế suy luận, ưu nhược điểm (ảo giác, context window) trong an ninh mạng. Xây dựng các kỹ thuật Prompt Engineering nâng cao (Few-shot, Chain-of-Thought, ReAct). Khảo sát cơ chế Structured Output (JSON Mode) và Tool Calling / Function Calling làm nền tảng tương tác giữa LLM và môi trường ngoài.",
         ["Tài liệu phân tích chuyên sâu về ứng dụng LLM trong SOC và các kỹ thuật Prompting.",
          "Thiết kế template prompt mẫu cho tác vụ phân tích an ninh; cơ chế ép kiểu đầu ra qua JSON Schema."],
         "Thực nghiệm chạy thử các prompt mẫu trên mô hình LLM qua API; kiểm tra tỷ lệ tuân thủ định dạng JSON đạt 100%.",
         "Bản thảo Báo cáo Chương 1 (Mục 1.3 & Mục 1.4)."),

        ("Task 3.1 (Nam)", "Nghiên cứu Cyber Threat Intelligence (CTI) & Khung MITRE ATT&CK",
         "Nghiên cứu toàn diện về CTI, kim tự tháp nỗi đau (Pyramid of Pain), các loại IoC (Hash, IP, Domain). Phân tích chi tiết ma trận MITRE ATT&CK Enterprise (14 Tactics, Techniques & Sub-techniques). Nghiên cứu chuẩn biểu diễn dữ liệu an ninh STIX 2.1 (SDO, SRO) và giao thức chia sẻ TAXII 2.1 để phục vụ làm giàu dữ liệu cảnh báo.",
         ["Tài liệu nghiên cứu CTI, ma trận MITRE ATT&CK kèm ví dụ ánh xạ từ log sang TTPs cụ thể.",
          "Cấu trúc JSON mẫu chuẩn STIX 2.1 cho Indicator và Attack Pattern phục vụ tích hợp."],
         "Kiểm tra tính hợp lệ của STIX 2.1 qua schema validator; đối chiếu kỹ thuật ATT&CK với cơ sở dữ liệu MITRE chính thức.",
         "Bản thảo Báo cáo Chương 1 (Mục 1.5 & Mục 1.6)."),

        ("Task 3.2 (Đô)", "Nghiên cứu kiến trúc Multi-Agent & Nền tảng điều phối LangGraph",
         "Nghiên cứu mô hình AI Agent (Perception - Reasoning - Action - Memory) và hệ thống Multi-Agent System (MAS). So sánh ưu thế của MAS so với Single-Agent LLM. Nghiên cứu sâu framework LangGraph: StateGraph, cơ chế quản lý trạng thái tập trung (State Management), định tuyến rẽ nhánh có điều kiện (Conditional Edges), cơ chế Human-in-the-loop (HITL) và lưu vết (Checkpointer).",
         ["Tài liệu so sánh kiến trúc Single-Agent vs Multi-Agent trong phân tích sự cố.",
          "Mô hình khái niệm StateGraph điều phối các Agent chuyên biệt theo mô hình Supervisor-Worker."],
         "Xây dựng đoạn mã prototype tối giản (PoC) trên LangGraph kiểm chứng việc truyền State giữa 2 node.",
         "Bản thảo Báo cáo Chương 2 (Mục 2.1 & Khung kiến trúc)."),

        ("Task 4.1 (Cả nhóm)", "Đặc tả 3 Kịch bản sự cố trọng tâm & Luồng dữ liệu chung",
         "Cùng thảo luận và thống nhất lựa chọn 3 kịch bản tấn công thực tế tiêu biểu để làm phạm vi kiểm thử: (1) Phishing Email dẫn đến Credential Harvesting; (2) Endpoint Malware Execution & Persistence; (3) Network Reconnaissance & Lateral Movement. Xây dựng sơ đồ luồng dữ liệu (Data Flow) tổng thể từ lúc tiếp nhận log đến khi xuất báo cáo điều tra.",
         ["Tài liệu đặc tả chi tiết 3 kịch bản: Vector tấn công, dấu vết log đặc trưng, hành vi và mục tiêu phát hiện.",
          "Sơ đồ luồng dữ liệu End-to-End mô tả sự luân chuyển thông tin giữa các tầng chức năng."],
         "Rà soát tính khả thi về dữ liệu thực nghiệm; đảm bảo 3 kịch bản bao phủ đủ nguồn log Sysmon, Zeek và EVTX.",
         "Tài liệu Đặc tả Kịch bản & Data Flow Specification."),

        ("Task 4.2 (Đô)", "Thiết kế kiến trúc StateGraph điều phối Multi-Agent",
         "Thiết kế cấu trúc StateGraph hoàn chỉnh điều phối 6 Agent chuyên trách: (1) Ingestion Agent, (2) Detection & Triage Agent, (3) Threat Intel Agent, (4) RCA Agent, (5) Response Agent, (6) Reporting Agent. Xác định chính xác các Node, Edge, Conditional Routing (rẽ nhánh khi False Positive hoặc nghi vấn cao) và Checkpoint dừng chờ chuyên viên phê duyệt (Human-in-the-loop).",
         ["Sơ đồ kiến trúc StateGraph chi tiết với đầy đủ các nút xử lý và điều kiện chuyển trạng thái.",
          "Mô tả thuật toán điều phối và cơ chế xử lý lỗi/fallback giữa các agent."],
         "Mô phỏng logic chuyển trạng thái trên đồ thị có hướng không chu trình (hoặc có vòng lặp tinh chỉnh); kiểm tra tính toàn vẹn trạng thái.",
         "Tài liệu System Architecture & Thiết kế StateGraph."),

        ("Task 4.3 (Nam)", "Thiết kế Schema Input/Output chuẩn hóa bằng Pydantic",
         "Thiết kế toàn bộ cấu trúc dữ liệu chuẩn hóa cho hệ thống bằng Pydantic v2 nhằm đảm bảo Type Safety và Validation nghiêm ngặt giữa các agent. Xây dựng các Model: AlertSchema, ParsedEvent, TriageOutput, ThreatIntelEnrichment, RootCauseAnalysis, ResponseAction, IncidentReport và State trung tâm (IncidentState).",
         ["Bộ mã nguồn Python chứa đầy đủ các class Pydantic định nghĩa Schema Input/Output của 6 Agent.",
          "Cơ chế validation dữ liệu tự động, tài liệu hóa docstrings cho từng trường thuộc tính."],
         "Chạy Unit Test kiểm tra tính hợp lệ của dữ liệu (valid input parse thành công, invalid input báo lỗi chính xác).",
         "Tập tin mã nguồn schemas.py và tài liệu đặc tả Data Models."),

        ("Task 4.4 (Cả nhóm)", "Xây dựng Tài liệu Kiến trúc Hệ thống & Sequence Diagrams",
         "Hợp nhất các kết quả thiết kế thành Tài liệu Kiến trúc Hệ thống hoàn chỉnh (System Architecture Document). Phân chia hệ thống thành 4 tầng: (1) Data Source Layer, (2) Multi-Agent Orchestration Layer, (3) Knowledge & Tool Layer, (4) Presentation/UI Layer. Xây dựng các sơ đồ tuần tự (Sequence Diagrams) mô tả chi tiết tương tác thời gian thực giữa các agent cho từng kịch bản.",
         ["Tài liệu kiến trúc hệ thống 4 tầng chi tiết kèm mô tả chức năng từng thành phần.",
          "3 Sơ đồ Sequence Diagram hoàn chỉnh tương ứng với 3 kịch bản sự cố trọng tâm."],
         "Kiểm tra tính nhất quán giữa Sequence Diagram, Pydantic Schema và StateGraph Architecture.",
         "Tài liệu System Architecture & Sequence Diagrams hoàn chỉnh.")
    ]

    for t_id, title, desc, criteria, verif, deliverable in tasks:
        add_h3(f"{t_id}: {title}")
        add_body(desc, bold_prefix="Mô tả công việc: ")
        add_body("Tiêu chí chấp nhận (Acceptance Criteria):", bold_prefix=None, italic=True)
        for c in criteria:
            add_bullet(c, bold_prefix="[✓] ")
        add_body(verif, bold_prefix="Phương pháp kiểm chứng (Verification): ")
        add_body(deliverable, bold_prefix="Sản phẩm bàn giao: ")
        doc.add_paragraph().paragraph_format.space_after = Pt(2)

    doc.add_page_break()

    # ==================== PHẦN II: TUẦN 2 ====================
    add_h1("PHẦN II: NỘI DUNG THỰC HIỆN NHIỆM VỤ TUẦN 2 (27/09 – 03/10)")
    add_body("Trọng tâm tuần 2: Nghiên cứu nền tảng & Tổng quan cơ sở lý thuyết. Sản phẩm bàn giao là Bản thảo Báo cáo Chương 1 (Phần 1: Quy trình xử lý sự cố an ninh mạng, nguồn log chuẩn và Nền tảng mô hình ngôn ngữ lớn LLM).")

    add_h2("1. Nghiên cứu Quy trình ứng phó sự cố an ninh mạng NIST SP 800-61 (Nguyễn Phạm Hoài Nam thực hiện)")
    add_body("Quy trình điều tra và xử lý sự cố an ninh mạng trong đề tài được chuẩn hóa dựa trên hướng dẫn của Viện Tiêu chuẩn và Kỹ thuật Quốc gia Hoa Kỳ – NIST Special Publication 800-61 (Revision 2 và định hướng tích hợp CSF 2.0 trong Revision 3).")
    
    add_callout(
        "NIST SP 800-61 chia vòng đời xử lý sự cố an ninh mạng thành 4 giai đoạn khép kín:\n"
        "1. Giai đoạn Chuẩn bị (Preparation): Thiết lập chính sách, công cụ, cấu hình hệ thống ghi log và hạ tầng phòng thủ.\n"
        "2. Giai đoạn Phát hiện và Phân tích (Detection & Analysis): Tiếp nhận cảnh báo, phân loại (Triage), xác minh tính xác thực, phân tích phạm vi ảnh hưởng và xác định nguyên nhân gốc rễ (Root Cause).\n"
        "3. Giai đoạn Ngăn chặn, Loại bỏ và Phục hồi (Containment, Eradication & Recovery): Cô lập hệ thống bị xâm nhập, triệt tiêu mã độc/cửa sau, khôi phục dịch vụ an toàn.\n"
        "4. Hoạt động sau sự cố (Post-Incident Activity / Lessons Learned): Đúc rút kinh nghiệm, lập báo cáo chi tiết và cập nhật chính sách phòng thủ.",
        title="4 GIAI ĐOẠN THEO KHUNG CHUẨN NIST SP 800-61"
    )

    add_body("Thực trạng và Điểm nghẽn (Bottlenecks) tại Trung tâm Điều hành An ninh mạng (SOC):", bold_prefix="Phân tích bài toán thực tế: ")
    add_bullet("Hiện tượng Bùng nổ cảnh báo (Alert Fatigue): Mỗi ngày một hệ thống SIEM doanh nghiệp ghi nhận từ hàng chục nghìn đến hàng triệu sự kiện log. Chuyên viên SOC Tier 1 thường xuyên bị quá tải trước số lượng lớn cảnh báo dương tính giả (False Positives), dẫn đến nguy cơ bỏ sót các cuộc tấn công tinh vi kéo dài (APT).")
    add_bullet("Thời gian phát hiện và phản ứng kéo dài: Chỉ số MTTD (Mean Time to Detect) và MTTR (Mean Time to Respond) còn cao do quá trình điều tra phụ thuộc nặng nề vào thao tác thủ công: tra cứu IP/Domain trên VirusTotal, dịch ngược dòng lệnh PowerShell mã hóa, lục lọi process tree trên SIEM.")
    add_bullet("Sự phân mảnh tri thức và kỹ năng: Việc xâu chuỗi sự kiện giữa cảnh báo mạng (Network log) và hành vi máy trạm (Endpoint log) đòi hỏi chuyên viên giàu kinh nghiệm (Tier 3 / Incident Responder), trong khi nhân lực trình độ cao luôn khan hiếm.")
    add_body("=> Định hướng đề tài: Ứng dụng hệ thống Multi-Agent AI đóng vai trò như một «Trợ lý SOC tự động hóa cao cấp», hỗ trợ đắc lực cho chuyên viên từ khâu tiếp nhận log thô, lọc nhiễu, làm giàu tri thức tình báo, truy vết nguyên nhân đến đề xuất phương án ngăn chặn tức thời.")

    add_h2("2. Nghiên cứu Định dạng Log an ninh mạng chuyên sâu (Nguyễn Phạm Hoài Nam thực hiện)")
    add_body("Hệ thống tập trung xử lý và liên kết 3 nguồn log nền tảng phổ biến nhất trong hệ sinh thái an ninh mạng doanh nghiệp:")

    add_h3("a) Sysmon (Microsoft System Monitor) - Dấu vết Endpoint chuyên sâu")
    add_body("Sysmon cung cấp khả năng giám sát tiến trình, kết nối mạng và thay đổi hệ thống tệp ở tầng kernel của hệ điều hành Windows. Hệ thống tập trung bóc tách các Event ID sau:")
    add_bullet("Event ID 1 (Process Creation): Trường thông tin cốt lõi gồm Image, CommandLine (chứa tham số thực thi, câu lệnh script), ParentImage, ParentCommandLine, Hashes (MD5, SHA256 để kiểm tra IoC), User, CurrentDirectory. Đây là dấu vết quan trọng nhất để phát hiện Living-off-the-Land (LotL) và mã độc.")
    add_bullet("Event ID 3 (Network Connection): Ghi nhận tiến trình khởi tạo kết nối mạng ra ngoài. Trường quan trọng: Image, Protocol, SourceIp, SourcePort, DestinationIp, DestinationPort, DestinationHostname. Dùng để phát hiện hành vi kết nối Command & Control (C2).")
    add_bullet("Event ID 7 (Image Loaded): Giám sát nạp DLL vào tiến trình. Giúp phát hiện DLL Side-Loading, DLL Injection.")
    add_bullet("Event ID 11 (FileCreate): Giám sát việc tạo tệp tin trên đĩa (TargetFilename, CreationUtcTime). Phát hiện mã độc ghi payload hoặc ransomware tạo tệp tống tiền.")
    add_bullet("Event ID 13 (RegistryEvent - Value Set): Ghi nhận sửa đổi khóa Registry (TargetObject, Details). Phát hiện cơ chế duy trì quyền truy cập (Persistence) như khóa Run/RunOnce, Winlogon.")

    add_h3("b) Zeek (Bro Network Security Monitor) - Giám sát giao thức mạng")
    add_body("Zeek phân tích lưu lượng mạng ở tầng ứng dụng và sinh ra các tệp log theo từng giao thức với định dạng có cấu trúc cao (TSV hoặc JSON):")
    add_bullet("conn.log: Giám sát toàn bộ luồng mạng (Flow). Trường quan trọng: id.orig_h (IP nguồn), id.orig_p, id.resp_h (IP đích), id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state (nhận diện quét cổng SYN qua cờ S0).")
    add_bullet("dns.log: Giám sát truy vấn phân giải tên miền. Trường quan trọng: query, qclass_name, qtype_name, answers, rcode_name. Dùng để phát hiện DNS Tunneling, DGA (Domain Generation Algorithm).")
    add_bullet("http.log: Giám sát giao thức Web. Trường quan trọng: method, host, uri, referrer, user_agent, status_code, request_body_len. Nhận diện các cuộc tấn công Web và tải tệp độc hại.")
    add_bullet("ssl.log: Giám sát mã hóa TLS/SSL. Trường quan trọng: server_name (SNI), ja3, ja3s (dấu vân tay bắt tay TLS để nhận diện họ mã độc mà không cần giải mã gói tin).")

    add_h3("c) Windows Security Event Logs (EVTX) - Kiểm toán định danh và xác thực")
    add_body("Nguồn log chuẩn từ Windows Event Viewer cung cấp bằng chứng pháp lý về hành vi xác thực:")
    add_bullet("Event ID 4624 (Successful Logon): Đăng nhập thành công. Cần chú ý LogonType (Type 2: Interactive cục bộ, Type 3: Network qua mạng chia sẻ SMB/RPC, Type 10: RemoteDesktop RDP).")
    add_bullet("Event ID 4625 (Failed Logon): Đăng nhập thất bại. Chuỗi nhiều sự kiện 4625 liên tiếp từ cùng một IP/Account là dấu hiệu điển hình của tấn công Brute-force hoặc Password Spraying.")
    add_bullet("Event ID 4688 (A new process has been created): Cung cấp audit tiến trình tương tự Sysmon nếu đã bật chính sách Include Command Line.")
    add_bullet("Event ID 7045 / 4697 (A service was installed in the system): Phát hiện tấn công tạo dịch vụ chạy ngầm để leo thang đặc quyền hoặc duy trì quyền truy cập.")

    add_h2("3. Nghiên cứu Mô hình ngôn ngữ lớn (LLM) trong An ninh mạng (Phan Trường Đô thực hiện)")
    add_body("Mô hình ngôn ngữ lớn (Large Language Models – LLMs) với kiến trúc Transformer và khả năng học ngữ cảnh (In-context Learning) mang lại bước đột phá trong tự động hóa SOC:")
    add_bullet("Khả năng phân tích cú pháp phi cấu trúc: LLM có thể đọc hiểu các dòng log thô lộn xộn, giải mã các câu lệnh PowerShell/Bash bị obfuscate (Base64, hex encoding) mà không cần viết các bộ giải mã tĩnh phức tạp.")
    add_bullet("Khả năng tổng hợp tri thức liên ngành: LLM kết nối thông tin giữa dấu vết log kỹ thuật và tri thức chiến thuật tấn công (MITRE ATT&CK), tự động sinh văn bản báo cáo tóm lược cho lãnh đạo (Executive Summary) lẫn hướng dẫn kỹ thuật cho kỹ sư điều tra.")
    add_bullet("Thách thức cần giải quyết: Hiện tượng ảo giác (Hallucination) – bịa đặt IoC hoặc kỹ thuật tấn công không có trong log; giới hạn cửa sổ ngữ cảnh (Context Window) khi xử lý hàng nghìn dòng log; rủi ro rò rỉ dữ liệu nhạy cảm khi dùng API đám mây.")
    add_body("=> Giải pháp khắc phục: Áp dụng cơ chế RAG (Retrieval-Augmented Generation) kết hợp bộ lọc tri thức MITRE ATT&CK cục bộ, sử dụng kỹ thuật ép kiểu cấu trúc chặt chẽ (Structured Output) và cơ chế xác thực chéo giữa các Agent.")

    add_h2("4. Kỹ thuật Prompt Engineering, Structured Output & Tool Calling (Phan Trường Đô thực hiện)")
    
    add_h3("a) Kỹ thuật Prompt Engineering chuyên sâu")
    add_bullet("Few-Shot Security Prompting: Cung cấp từ 2-3 ví dụ mẫu về việc bóc tách log và suy luận sự cố, giúp LLM nắm bắt chính xác quy cách phân tích và giảm thiểu tối đa ảo giác.")
    add_bullet("Chain-of-Thought (CoT) Prompting: Hướng dẫn LLM suy luận từng bước tương tự như một Senior SOC Analyst: (1) Trích xuất bằng chứng khách quan -> (2) Đặt giả thuyết tấn công -> (3) Đối chiếu dấu vết thứ cấp -> (4) Đưa ra kết luận và độ tin cậy.")
    add_bullet("ReAct (Reasoning + Acting) Framework: Mô hình lặp 'Thought -> Action -> Observation'. Khi LLM phát hiện một IP lạ, nó 'Thought' rằng cần kiểm tra danh tiếng IP, thực hiện 'Action' gọi API VirusTotal, nhận 'Observation' là điểm độc hại 85/90, từ đó suy luận bước tiếp theo.")

    add_h3("b) Structured Output (Đầu ra có cấu trúc tuyệt đối)")
    add_body("Trong hệ thống tự động hóa đa tác tử, các Agent giao tiếp với nhau bằng dữ liệu máy tính có thể phân tích được (JSON/Schema), tuyệt đối không dùng văn bản tự do không định dạng:")
    add_bullet("Sử dụng JSON Schema Enforcement và Pydantic Validator để ép buộc LLM chỉ trả về duy nhất chuỗi JSON hợp lệ theo đúng cấu trúc lớp dữ liệu đã định nghĩa trước.")
    add_bullet("Loại bỏ hoàn toàn các lời mở đầu/kết thúc thừa thãi (ví dụ: 'Sure, here is the JSON...') làm gãy vỡ pipeline xử lý.")

    add_h3("c) Tool Calling / Function Calling")
    add_body("Cơ chế cho phép LLM chủ động quyết định khi nào cần tra cứu công cụ ngoại vi thay vì tự suy đoán:")
    add_bullet("Định nghĩa bộ công cụ (Tools Specification): Gồm tên hàm, mô tả chức năng, tham số đầu vào (ví dụ: `lookup_ip_reputation(ip: str)`, `search_mitre_technique(keyword: str)`).")
    add_bullet("LLM sinh lệnh gọi hàm với các đối số chuẩn xác; hệ thống thực thi hàm và trả kết quả về cho LLM tổng hợp.")

    doc.add_page_break()

    # ==================== PHẦN III: TUẦN 3 ====================
    add_h1("PHẦN III: NỘI DUNG THỰC HIỆN NHIỆM VỤ TUẦN 3 (04/10 – 10/10)")
    add_body("Trọng tâm tuần 3: Nghiên cứu chuyên sâu về Tri thức an ninh mạng (CTI, MITRE ATT&CK, STIX/TAXII) và Kiến trúc điều phối đa tác tử (Multi-Agent System, LangGraph StateGraph). Sản phẩm bàn giao là Bản thảo hoàn thiện Chương 1 và Khung phân tích Chương 2.")

    add_h2("1. Nghiên cứu Cyber Threat Intelligence (CTI) & Chỉ số IoC (Nguyễn Phạm Hoài Nam thực hiện)")
    add_body("Cyber Threat Intelligence (CTI) cung cấp dữ liệu ngữ cảnh về mối đe dọa giúp biến các dòng log khô khan thành bức tranh tấn công có ý nghĩa:")
    
    add_callout(
        "Mô hình Pyramid of Pain (David Bianco) phân cấp độ khó khăn của kẻ tấn công khi các chỉ số bị phòng thủ ngăn chặn:\n"
        "1. Hash Values (MD5, SHA256): Rất dễ thay đổi (Trivial) - Kẻ tấn công chỉ cần đổi 1 byte trong mã nguồn.\n"
        "2. IP Addresses: Dễ thay đổi (Easy) - Sử dụng proxy, VPN, mạng botnet động.\n"
        "3. Domain Names: Tương đối dễ (Simple) - Sử dụng DGA, đăng ký tên miền miễn phí.\n"
        "4. Network & Host Artifacts: Khó chịu (Annoying) - Sửa đổi user-agent, đường dẫn URI, cấu trúc gói tin.\n"
        "5. Tools: Khó (Challenging) - Buộc kẻ tấn công phải viết lại mã độc hoặc tìm công cụ khai thác khác.\n"
        "6. Tactics, Techniques & Procedures (TTPs): Cực kỳ khó khăn (Tough) - Thay đổi toàn bộ hành vi, tư duy và thói quen tấn công.",
        title="Ý NGHĨA CỦA KIM TỰ THÁP NỖI ĐAU (PYRAMID OF PAIN)"
    )

    add_body("Hệ thống đề xuất tập trung nhận diện các IoC tầng thấp để ngăn chặn tức thì (Triage/Response), đồng thời suy luận lên tầng TTPs (Root Cause Analysis) để triệt tiêu hoàn toàn nguồn cơn cuộc tấn công.")

    add_h2("2. Khung tri thức MITRE ATT&CK & Ánh xạ TTPs (Nguyễn Phạm Hoài Nam thực hiện)")
    add_body("Khung MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) là cơ sở tri thức toàn cầu chuẩn hóa hành vi tấn công mạng:")
    add_bullet("14 Chiến thuật (Tactics) theo tiến trình tấn công: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact.")
    add_bullet("Kỹ thuật (Techniques) & Kỹ thuật phụ (Sub-techniques): Được định danh bằng mã chuẩn Txxxx (ví dụ: T1059.001 - Command and Scripting Interpreter: PowerShell).")
    add_body("Bảng ví dụ ánh xạ từ dấu vết log thực tế sang mã định danh MITRE ATT&CK:", bold_prefix="Ánh xạ thực nghiệm: ")

    # Bảng ánh xạ ATT&CK
    att_table = doc.add_table(rows=5, cols=4)
    att_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    att_table.autofit = False
    a_widths = [Inches(1.2), Inches(1.8), Inches(1.8), Inches(1.5)]
    
    a_headers = ["Dấu vết Log / Hành vi", "Chiến thuật (Tactic)", "Kỹ thuật (Technique)", "Mã định danh (ID)"]
    for idx, text in enumerate(a_headers):
        cell = att_table.rows[0].cells[idx]
        cell.width = a_widths[idx]
        set_cell_background(cell, "1B365D")
        set_cell_margins(cell, 100, 100, 80, 80)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(text)
        r.font.name = 'Times New Roman'
        r.font.bold = True
        r.font.size = Pt(10)
        r.font.color.rgb = RGBColor(255, 255, 255)

    att_data = [
        ("PowerShell chạy lệnh mã hóa Base64 (-enc)", "Execution", "Command and Scripting Interpreter: PowerShell", "T1059.001"),
        ("Tạo Scheduled Task thực thi script hàng ngày", "Persistence / PrivEsc", "Scheduled Task/Job: Scheduled Task", "T1053.005"),
        ("Quét mạng nội bộ bằng Nmap (cờ SYN)", "Discovery", "Network Service Discovery", "T1046"),
        ("Truy vấn DNS liên tục tên miền ngẫu nhiên", "Command and Control", "Dynamic Resolution: Domain Generation Algorithms", "T1568.002")
    ]
    for row_idx, r_data in enumerate(att_data):
        row = att_table.rows[row_idx + 1]
        bg_col = "FFFFFF" if row_idx % 2 == 0 else "F8FAFC"
        for col_idx, text in enumerate(r_data):
            cell = row.cells[col_idx]
            cell.width = a_widths[col_idx]
            set_cell_background(cell, bg_col)
            set_cell_margins(cell, 80, 80, 80, 80)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.line_spacing = 1.15
            if col_idx == 3:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r = p.add_run(text)
            r.font.name = 'Times New Roman'
            r.font.size = Pt(9.5)
            
    set_table_borders(att_table, "CBD5E1", "4")
    doc.add_paragraph().paragraph_format.space_after = Pt(8)

    add_h2("3. Chuẩn trao đổi CTI: STIX 2.1 & TAXII 2.1 (Nguyễn Phạm Hoài Nam thực hiện)")
    add_body("Để các Agent có thể xuất và nạp tri thức đe dọa với các nguồn mở (AlienVault OTX, MISP), hệ thống ứng dụng chuẩn STIX/TAXII:")
    add_bullet("STIX 2.1 (Structured Threat Information Expression): Mô hình biểu diễn dữ liệu an ninh mạng dạng JSON Graph. Gồm các STIX Domain Objects (SDO) như `indicator`, `attack-pattern`, `malware`, `observed-data` và các STIX Relationship Objects (SRO) như `indicates`, `uses`.")
    add_bullet("TAXII 2.1 (Trusted Automated eXchange of Intelligence Information): Giao thức truyền tải tầng ứng dụng qua REST API (HTTPS) để truy vấn và đẩy các gói tin STIX giữa các hệ thống an ninh mạng.")

    add_h2("4. Nghiên cứu Kiến trúc Multi-Agent System (MAS) (Phan Trường Đô thực hiện)")
    add_body("Hệ thống tác tử thông minh (AI Agent) là thực thể tính toán có khả năng cảm nhận môi trường (Perception), suy luận và lập kế hoạch (Reasoning/Planning), sử dụng công cụ (Tool Use), lưu giữ trí nhớ (Memory) và thực thi hành động (Action).")
    
    add_body("So sánh giữa Kiến trúc Single-Agent và Multi-Agent:", bold_prefix="Ưu thế vượt trội của Multi-Agent: ")
    add_bullet("Phân chia trách nhiệm rõ ràng (Separation of Concerns): Thay vì ép một mô hình LLM duy nhất phải đảm nhận toàn bộ các khâu từ đọc regex log, tra cứu API đến viết báo cáo (dễ gây quá tải ngữ cảnh và suy giảm độ chính xác), hệ thống chia nhỏ thành 6 Agent chuyên biệt, mỗi Agent có System Prompt và bộ Tool riêng biệt tối ưu hóa cho tác vụ đó.")
    add_bullet("Tiết kiệm chi phí và tối ưu Context Window: Các tác vụ sơ bộ (Ingestion, Triage) chỉ xử lý dữ liệu nhỏ gọn và có thể dùng mô hình nhỏ, nhanh (như GPT-4o-mini hoặc Llama 3 8B), trong khi tác vụ phức tạp (Root Cause Analysis, Báo cáo) mới dùng mô hình suy luận mạnh.")
    add_bullet("Khả năng kiểm thử, mở rộng và bảo trì độc lập: Có thể nâng cấp logic hoặc thay thế prompt của một Agent mà không làm ảnh hưởng đến tính ổn định của các Agent khác.")

    add_h2("5. Nền tảng điều phối LangGraph & State Management (Phan Trường Đô thực hiện)")
    add_body("LangGraph là framework hàng đầu hiện nay xây dựng trên nền tảng LangChain, chuyên biệt cho việc thiết kế các hệ thống tác tử có chu trình (Cyclic Graphs):")
    add_bullet("Mô hình StateGraph: Biểu diễn toàn bộ quy trình điều tra dưới dạng đồ thị có hướng. Các nút (Nodes) đại diện cho các Agent hoặc Hàm chức năng; Các cạnh (Edges) đại diện cho luồng chuyển đổi; Các cạnh có điều kiện (Conditional Edges) thực hiện định tuyến động dựa trên trạng thái hiện tại của sự cố.")
    add_bullet("Quản lý trạng thái tập trung (Centralized State): Một đối tượng State duy nhất (định nghĩa qua TypedDict/Pydantic) được truyền qua lại giữa các Node. Mỗi Node chỉ cập nhật thêm thông tin mà nó phân tích được vào State (ví dụ: Triage Agent cập nhật điểm rủi ro, Threat Intel Agent bổ sung thông tin IP, RCA Agent vẽ process tree).")
    add_bullet("Cơ chế Human-in-the-loop (HITL): Điểm độc đáo của LangGraph cho phép đóng băng trạng thái tại một Node (Checkpoint) và dừng lại chờ con người phê duyệt (ví dụ: Chuyên viên SOC bấm duyệt phương án cô lập máy trạm) trước khi chuyển trạng thái sang bước thực thi kế tiếp.")

    doc.add_page_break()

    # ==================== PHẦN IV: TUẦN 4 ====================
    add_h1("PHẦN IV: NỘI DUNG THỰC HIỆN NHIỆM VỤ TUẦN 4 (11/10 – 17/10)")
    add_body("Trọng tâm tuần 4: Đặc tả yêu cầu kỹ thuật, xây dựng 3 kịch bản sự cố trọng tâm, thiết kế kiến trúc StateGraph điều phối, thiết kế bộ Schema Pydantic I/O chuẩn hóa và hoàn thiện Tài liệu System Architecture & Sequence Diagram.")

    add_h2("1. Đặc tả 3 Kịch bản sự cố trọng tâm & Luồng dữ liệu chung (Cả nhóm thực hiện)")
    add_body("Để đảm bảo tính khả thi thực nghiệm và bao phủ đa dạng các bề mặt tấn công (Email, Endpoint, Network), nhóm thống nhất xây dựng 3 kịch bản sự cố thực tế tiêu biểu:")

    add_h3("a) Kịch bản 1: Phishing Email dẫn đến Credential Harvesting & Initial Access")
    add_bullet("Vector tấn công: Kẻ tấn công gửi email lừa đảo mạo danh thông báo nâng cấp bảo mật của Microsoft 365, đính kèm đường link dẫn đến trang web giả mạo có giao diện giống hệt trang đăng nhập nội bộ.")
    add_bullet("Hành vi: Nạn nhân bấm vào link, nhập thông tin tài khoản (Username, Password). Kẻ tấn công thu thập thông tin và ngay lập tức sử dụng tài khoản đó đăng nhập từ một địa chỉ IP lạ (nước ngoài).")
    add_bullet("Dấu vết Log thu thập: Alert từ Mail Gateway (chứa sender lạ, URL phishing), Web Proxy Log (chứa kết nối tới domain giả mạo) và Windows Security Log Event ID 4624 (Logon thành công nhưng với địa chỉ IP bất thường, Logon Type 3 hoặc 10).")

    add_h3("b) Kịch bản 2: Endpoint Malware Execution & Persistence")
    add_bullet("Vector tấn công: Nạn nhân tải về và kích hoạt một tệp tin nén chứa mã độc dạng shortcut (.lnk) hoặc tệp văn bản kích hoạt macro độc hại.")
    add_bullet("Hành vi: Tệp tin kích hoạt `powershell.exe` với tham số `-ExecutionPolicy Bypass -WindowStyle Hidden -enc ...` để tải payload độc hại từ máy chủ C2, lưu vào thư mục `C:\\Users\\Public\\`, sau đó tạo một Scheduled Task chạy định kỳ mỗi khi khởi động máy.")
    add_bullet("Dấu vết Log thu thập: Sysmon Event ID 1 (Process Create: phát hiện `powershell.exe` với cờ thực thi ẩn và lệnh mã hóa), Sysmon Event ID 3 (Network Connect: kết nối đến IP máy chủ C2), Sysmon Event ID 11 (File Create: tạo file binary lạ), Windows Event ID 4698/7045 (Scheduled Task / Service Created).")

    add_h3("c) Kịch bản 3: Network Reconnaissance & Lateral Movement")
    add_bullet("Vector tấn công: Sau khi chiếm được quyền kiểm soát một máy trạm nội bộ, kẻ tấn công thực hiện do thám mạng nội bộ để tìm kiếm các máy chủ chứa dữ liệu quan trọng.")
    add_bullet("Hành vi: Sử dụng Nmap hoặc script Python quét dải mạng nội bộ qua cổng SMB (445), RDP (3389). Phát hiện máy chủ chia sẻ tệp có lỗ hổng, kẻ tấn công dùng kỹ thuật Pass-the-Hash hoặc khai thác dịch vụ SMB để di chuyển ngang sang máy chủ đích.")
    add_bullet("Dấu vết Log thu thập: Zeek `conn.log` (ghi nhận hàng nghìn kết nối SYN trong thời gian ngắn với trạng thái S0), Zeek `smb.log` (ghi nhận các giao dịch SMB bất thường), Windows Security Log Event ID 4624 (Logon Type 3 từ IP nội bộ với đặc quyền Administrator).")

    add_h3("d) Luồng dữ liệu chung End-to-End (End-to-End Data Flow)")
    add_body("Dữ liệu thô luân chuyển xuyên suốt qua 5 chặng xử lý chính:")
    add_bullet("Chặng 1 (Ingestion): Log thô từ Sysmon/Zeek/EVTX được làm sạch, bóc tách cấu trúc thành các trường chuẩn hóa.")
    add_bullet("Chặng 2 (Triage): Đánh giá sơ bộ xem đây có phải là sự cố thực sự hay không; nếu là False Positive thì kết thúc sớm và giải phóng tài nguyên; nếu là True Positive thì phân loại mức độ nghiêm trọng (Severity: Low, Medium, High, Critical).")
    add_bullet("Chặng 3 (Enrichment & RCA): Trích xuất IoC và tra cứu Threat Intel; tái hiện chuỗi tiến trình cha-con (Process Tree) và dòng thời gian (Timeline) để xác định nguyên nhân gốc rễ và kỹ thuật MITRE ATT&CK tương ứng.")
    add_bullet("Chặng 4 (Response Formulation): Đề xuất danh sách hành động ngăn chặn (Block IP, Cách ly host, Thu hồi tài khoản) theo đúng quy trình và gửi đến Node chờ phê duyệt của chuyên viên (Human-in-the-loop).")
    add_bullet("Chặng 5 (Reporting): Tự động sinh báo cáo tổng hợp chi tiết lưu lại toàn bộ hồ sơ sự cố dưới dạng Markdown và PDF/DOCX.")

    add_h2("2. Thiết kế Kiến trúc StateGraph điều phối Multi-Agent (Phan Trường Đô thực hiện)")
    add_body("Hệ thống được thiết kế theo mô hình 6 Agent chuyên biệt phối hợp thông qua một Bộ điều phối trung tâm (Supervisor/StateGraph Orchestrator):")

    agents_info = [
        ("1. Data Ingestion Agent", "Tiếp nhận log thô từ file JSON, XML, Syslog. Sử dụng các biểu thức chính quy (Regex) và JSON Parser để chuẩn hóa dữ liệu thành các trường sự kiện chuẩn (`ParsedEvent`)."),
        ("2. Detection & Triage Agent", "Áp dụng kỹ thuật Prompting kết hợp bộ lọc quy tắc để phát hiện bất thường, tính toán điểm rủi ro (Risk Score từ 0-100), phân loại mức độ nghiêm trọng và quyết định xem có cần kích hoạt điều tra sâu hay không."),
        ("3. Threat Intelligence (CTI) Agent", "Trích xuất danh sách các IoC (IP, Domain, File Hash) từ sự cố, gọi các API bên ngoài (VirusTotal, AbuseIPDB, AlienVault) và tra cứu cơ sở tri thức MITRE ATT&CK cục bộ để làm giàu ngữ cảnh."),
        ("4. Root Cause Analysis (RCA) Agent", "Chuyên viên phân tích chuyên sâu: Xâu chuỗi các sự kiện rời rạc, xây dựng Process Lineage (Cây tiến trình), xác định điểm khởi phát xâm nhập ban đầu (Initial Access Vector) và các kỹ thuật tấn công liên quan."),
        ("5. Response Recommendation Agent", "Đề xuất các biện pháp khắc phục dựa trên chuẩn NIST SP 800-61 và các kịch bản phản ứng mẫu (Playbooks). Đóng gói hành động thành các lệnh có cấu trúc và gửi đến cổng Human Review."),
        ("6. Reporting Agent", "Tổng hợp toàn bộ trạng thái sự cố, trích xuất số liệu định lượng, bằng chứng kỹ thuật và danh sách khuyến nghị để sinh bản báo cáo toàn diện đạt chuẩn chuyên nghiệp.")
    ]
    for a_name, a_desc in agents_info:
        add_bullet(a_desc, bold_prefix=f"• {a_name}: ")

    add_body("Sơ đồ luồng chuyển trạng thái trong LangGraph StateGraph:", bold_prefix="Cơ chế chuyển trạng thái: ")
    add_code_block(
"""[START]
   │
   ▼
[node_ingestion]  ──(Parse raw logs)──> Updates State with ParsedEvent
   │
   ▼
[node_triage]     ──(Evaluate Risk)───> Updates State with TriageResult
   │
   ├─► [Condition: is_incident == False] ──────► [END] (False Positive)
   │
   └─► [Condition: is_incident == True]
         │
         ▼
     [node_threat_intel]  ──(Enrich IoCs)───> Updates State with ThreatIntel
         │
         ▼
     [node_root_cause]    ──(Process Tree)──> Updates State with RCAOutput
         │
         ▼
     [node_response]      ──(Build Actions)─> Updates State with Actions
         │
         ▼
     [node_human_review]  ──(HITL Checkpoint: Await Analyst Approval)
         │
         ▼
     [node_reporting]     ──(Compile Report)─> Updates State with FinalReport
         │
         ▼
       [END]"""
    )

    add_h2("3. Thiết kế Schema Input/Output chuẩn hóa bằng Pydantic (Nguyễn Phạm Hoài Nam thực hiện)")
    add_body("Dưới đây là bản thiết kế hoàn chỉnh bộ mã nguồn Schemas sử dụng Pydantic v2, thiết lập nền tảng kiểu dữ liệu cho toàn bộ hệ thống:")

    schema_code = '''# schemas.py - Bộ Schema Input/Output chuẩn hóa cho Hệ thống Multi-Agent
from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime

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

# 1. Input Schemas cho Ingestion Agent
class RawLogInput(BaseModel):
    log_source: str = Field(..., description="Nguồn log: Sysmon, Zeek, EVTX")
    raw_payload: str = Field(..., description="Dữ liệu log thô (JSON, XML hoặc chuỗi text)")
    collected_at: datetime = Field(default_factory=datetime.utcnow)

class ParsedEvent(BaseModel):
    event_id: str
    timestamp: datetime
    source_type: str
    host_name: Optional[str] = None
    user_name: Optional[str] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    parent_process: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    file_hash: Optional[str] = None
    raw_attributes: Dict[str, Any] = Field(default_factory=dict)

# 2. Output Schema cho Triage Agent
class TriageOutput(BaseModel):
    is_incident: bool = Field(..., description="Xác định có phải sự cố thực sự hay không")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Độ tin cậy từ 0 đến 1")
    severity: SeverityLevel
    summary: str = Field(..., description="Tóm tắt ngắn gọn nhận định ban đầu")
    rule_or_model: str = Field(..., description="Phương pháp phát hiện: Model LLM hoặc Rule-based")

# 3. Output Schema cho Threat Intel Agent
class IoCItem(BaseModel):
    ioc_type: str = Field(..., description="IP, DOMAIN, MD5, SHA256")
    value: str
    reputation_score: Optional[int] = Field(None, description="Điểm rủi ro từ 0-100")
    is_malicious: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)

class ThreatIntelEnrichment(BaseModel):
    extracted_iocs: List[IoCItem] = Field(default_factory=list)
    related_threat_actors: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list, description="Mã kỹ thuật ATT&CK")
    enrichment_summary: str

# 4. Output Schema cho Root Cause Analysis (RCA) Agent
class ProcessNode(BaseModel):
    process_id: str
    process_name: str
    command_line: str
    parent_id: Optional[str] = None
    is_malicious_origin: bool = False

class RootCauseAnalysis(BaseModel):
    initial_access_vector: str = Field(..., description="Đường xâm nhập ban đầu")
    attack_timeline: List[str] = Field(default_factory=list, description="Dòng thời gian sự kiện")
    process_tree: List[ProcessNode] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    root_cause_summary: str

# 5. Output Schema cho Response Agent
class RecommendedAction(BaseModel):
    action_type: ActionType
    target: str = Field(..., description="Đối tượng thực thi: IP, Hostname, PID, User")
    description: str
    priority: int = Field(..., ge=1, le=5)
    require_human_approval: bool = True
    is_approved: Optional[bool] = None

# 6. Output Schema cho Reporting Agent
class IncidentReport(BaseModel):
    report_id: str
    incident_title: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    executive_summary: str
    detailed_findings: str
    mitre_attack_matrix_mapping: List[str]
    ioc_table: List[IoCItem]
    action_plan: List[RecommendedAction]

# 7. Root State cho LangGraph Orchestration
class IncidentState(BaseModel):
    incident_id: str
    status: IncidentStatus = IncidentStatus.NEW
    raw_logs: List[RawLogInput] = Field(default_factory=list)
    parsed_events: List[ParsedEvent] = Field(default_factory=list)
    triage_result: Optional[TriageOutput] = None
    threat_intel: Optional[ThreatIntelEnrichment] = None
    rca_result: Optional[RootCauseAnalysis] = None
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    final_report: Optional[IncidentReport] = None
    analyst_feedback: Optional[str] = None'''

    add_code_block(schema_code)

    add_h2("4. Tài liệu System Architecture & Sequence Diagrams (Cả nhóm thực hiện)")
    add_body("Kiến trúc hệ thống được phân rã thành 4 tầng kiến trúc rõ ràng (4-Tier Architectural Pattern):")
    add_bullet("Tầng 1 - Nguồn dữ liệu (Data Source Layer): Nơi thu thập các tệp log thô (Sysmon XML, Zeek TSV/JSON, Windows EVTX) và các cảnh báo từ hệ thống SIEM giả lập.")
    add_bullet("Tầng 2 - Điều phối Đa Tác tử (Multi-Agent Orchestration Layer): Trái tim của hệ thống, vận hành trên LangGraph StateGraph. Quản lý vòng đời trạng thái `IncidentState`, định tuyến các Agent thực thi theo thứ tự hoặc song song, xử lý ngoại lệ và điểm dừng Human-in-the-loop.")
    add_bullet("Tầng 3 - Công cụ & Cơ sở Tri thức (Tools & Knowledge Layer): Cung cấp các công cụ ngoại vi cho Agent như Parser Regex, Client kết nối VirusTotal API, AbuseIPDB API, Vector Database ChromaDB lưu trữ ma trận MITRE ATT&CK và NIST Incident Response Playbooks.")
    add_bullet("Tầng 4 - Giao diện & Hiển thị (Presentation & Dashboard Layer): Giao diện Web xây dựng bằng Streamlit cho phép chuyên viên SOC theo dõi tiến trình điều tra theo thời gian thực, tương tác duyệt hành động phản ứng (HITL) và tải về báo cáo sự cố dạng Markdown/PDF.")

    add_h3("Sơ đồ tuần tự (Sequence Diagram) - Kịch bản Endpoint Malware Execution")
    add_body("Sơ đồ dưới đây mô tả luồng giao tiếp tuần tự giữa các thành phần khi phát hiện và xử lý sự cố mã độc thực thi PowerShell trên máy trạm:")

    seq_diagram_text = """sequenceDiagram
    autonumber
    actor Analyst as SOC Analyst (Human)
    participant Ingest as Data Ingestion Agent
    participant Triage as Triage Agent
    participant CTI as Threat Intel Agent
    participant RCA as Root Cause Agent
    participant Resp as Response Agent
    participant Report as Reporting Agent
    participant Graph as LangGraph State

    Note over Ingest: Tiếp nhận log Sysmon & EVTX
    Ingest->>Graph: Gửi parsed_events (PowerShell -enc, Event ID 1 & 3)
    Graph->>Triage: Kích hoạt phân tích rủi ro
    Triage-->>Graph: Cập nhật TriageResult (is_incident=True, Severity=HIGH)
    
    par Tra cứu IoC & Phân tích chuỗi tiến trình
        Graph->>CTI: Trích xuất IP C2 & Hash mã độc
        CTI->>CTI: Gọi API VirusTotal / AbuseIPDB
        CTI-->>Graph: Cập nhật ThreatIntel (IP độc hại, T1059.001)
    and
        Graph->>RCA: Tái hiện cây tiến trình cha-con
        RCA->>RCA: Phát hiện winword.exe sinh powershell.exe
        RCA-->>Graph: Cập nhật RCA (Initial Access: Macro Phishing)
    end

    Graph->>Resp: Yêu cầu xây dựng phương án ứng phó
    Resp-->>Graph: Đề xuất ISOLATE_HOST và KILL_PROCESS (require_approval=True)
    
    Graph->>Analyst: Thông báo yêu cầu phê duyệt hành động (HITL)
    Analyst->>Graph: Xác nhận DUYỆT (is_approved=True)
    
    Graph->>Report: Yêu cầu tổng hợp báo cáo sự cố toàn diện
    Report-->>Graph: Xuất bản IncidentReport (Executive Summary & Action Plan)
    Graph->>Analyst: Trình diễn Báo cáo hoàn chỉnh trên Dashboard"""

    add_code_block(seq_diagram_text)

    doc.add_page_break()

    # ==================== PHẦN V: KẾT LUẬN ====================
    add_h1("PHẦN V: KẾT LUẬN VÀ KẾ HOẠCH CHUYỂN TIẾP TUẦN 5")
    
    add_h2("1. Đánh giá kết quả đạt được trong giai đoạn Tuần 2 – Tuần 4")
    add_bullet("Đã hoàn thành 100% khối lượng công việc đặt ra trong Đề cương chi tiết cho giai đoạn 3 tuần đầu tiên.")
    add_bullet("Lý thuyết nền tảng (NIST SP 800-61, Sysmon, Zeek, EVTX, LLM, Prompting, CTI, MITRE ATT&CK, Multi-Agent System, LangGraph) đã được nghiên cứu kỹ lưỡng và văn bản hóa hoàn chỉnh, sẵn sàng tích hợp trực tiếp vào Chương 1 và Chương 2 của quyển Báo cáo Tiểu luận.")
    add_bullet("Đặc tả kiến trúc hệ thống và luồng dữ liệu 3 kịch bản sự cố đã được thống nhất; bộ Schema Pydantic I/O đã được thiết kế hoàn thiện, đảm bảo tính chặt chẽ về dữ liệu cho giai đoạn code sắp tới.")

    add_h2("2. Kế hoạch chuyển tiếp Tuần 5 (18/10 – 24/10)")
    add_body("Bước sang Tuần 5, nhóm sẽ chuyển từ giai đoạn Thiết kế tổng thể sang Thiết kế chi tiết từng Agent chuyên biệt (thực hiện song song):")
    add_bullet("Nguyễn Phạm Hoài Nam: Thiết kế chi tiết Prompts, Tools và bộ quy tắc xử lý cho 3 Agent đầu vào: Ingestion Agent, Detection & Triage Agent, Threat Intelligence Agent.")
    add_bullet("Phan Trường Đô: Thiết kế chi tiết Prompts, Tools và logic suy luận cho 3 Agent chuyên sâu và đầu ra: Root Cause Analysis Agent, Response Recommendation Agent, Reporting Agent.")
    add_bullet("Sản phẩm bàn giao dự kiến Tuần 5: Bản đặc tả chi tiết Prompts, Schemas, Tools của toàn bộ 6 Agent.")

    doc.add_paragraph().paragraph_format.space_after = Pt(20)
    
    # Ký tên xác nhận
    sign_table = doc.add_table(rows=2, cols=2)
    sign_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    sign_table.autofit = False
    s_col_widths = [Inches(3.1), Inches(3.1)]
    
    for row in sign_table.rows:
        row.cells[0].width, row.cells[1].width = s_col_widths[0], s_col_widths[1]
        set_cell_margins(row.cells[0], 60, 60, 80, 80)
        set_cell_margins(row.cells[1], 60, 60, 80, 80)
        
    p_s0 = sign_table.rows[0].cells[0].paragraphs[0]
    p_s0.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_s0 = p_s0.add_run("GIẢNG VIÊN HƯỚNG DẪN\n(Ký và ghi rõ họ tên)")
    r_s0.font.name = 'Times New Roman'
    r_s0.font.bold = True
    r_s0.font.size = Pt(11)

    p_s1 = sign_table.rows[0].cells[1].paragraphs[0]
    p_s1.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_s1 = p_s1.add_run("SINH VIÊN THỰC HIỆN\n(Ký và ghi rõ họ tên)")
    r_s1.font.name = 'Times New Roman'
    r_s1.font.bold = True
    r_s1.font.size = Pt(11)

    p_n0 = sign_table.rows[1].cells[0].paragraphs[0]
    p_n0.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_n0.paragraph_format.space_before = Pt(45)
    r_n0 = p_n0.add_run("ThS. Đinh Công Đoan")
    r_n0.font.name = 'Times New Roman'
    r_n0.font.bold = True
    r_n0.font.size = Pt(11.5)

    p_n1 = sign_table.rows[1].cells[1].paragraphs[0]
    p_n1.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_n1.paragraph_format.space_before = Pt(45)
    r_n1 = p_n1.add_run("Phan Trường Đô      Nguyễn Phạm Hoài Nam")
    r_n1.font.name = 'Times New Roman'
    r_n1.font.bold = True
    r_n1.font.size = Pt(11.5)

    set_table_borders(sign_table, "FFFFFF", "0")

    output_path = "/home/nam/Desktop/TLCN/Bao_Cao_Thuc_Hien_Nhiem_Vu_Tuan_2_3_4.docx"
    doc.save(output_path)
    print(f"Report generated successfully at: {output_path}")

if __name__ == "__main__":
    create_document()
