# XÂY DỰNG HỆ THỐNG MULTI-AGENT ỨNG DỤNG LLM HỖ TRỢ ĐIỀU TRA SỰ CỐ AN NINH MẠNG

> **Đề tài:** Tiểu luận chuyên ngành An toàn thông tin  
> **Khoa:** Công nghệ Thông tin – Trường Đại học Sư phạm Kỹ thuật TP.HCM (HCMUTE)  
> **Sinh viên thực hiện:**  
> - **Phan Trường Đô** – MSSV: 23162020  
> - **Nguyễn Phạm Hoài Nam** – MSSV: 23162059  
> **Giảng viên hướng dẫn:** ThS. Đinh Công Đoan  
> **Thời gian thực hiện:** 20/09/2026 – 14/12/2026  

---

## 📌 1. Giới thiệu tổng quan

Đề tài tập trung nghiên cứu và xây dựng hệ thống **Multi-Agent System (MAS)** ứng dụng mô hình ngôn ngữ lớn (LLM) để tự động hóa toàn diện quy trình điều tra, phản ứng và báo cáo sự cố an ninh mạng theo chuẩn **NIST SP 800-61** và ma trận **MITRE ATT&CK**.

Hệ thống giải quyết bài toán bùng nổ cảnh báo (**Alert Fatigue**) tại trung tâm điều hành an ninh mạng (SOC), rút ngắn thời gian phát hiện và phản ứng trung bình (**MTTD/MTTR**) từ vài giờ xuống còn vài phút.

---

## 🏗️ 2. Kiến trúc Hệ thống Multi-Agent (6 Agents)

Hệ thống được điều phối bằng **LangGraph StateGraph** với 6 tác tử chuyên trách:

```
[Log thô: Sysmon / Zeek / EVTX]
               │
               ▼
   [1. Data Ingestion Agent] ──► Chuẩn hóa sang ParsedEvent
               │
               ▼
   [2. Detection & Triage Agent]
               │
          (is_incident?)
          ├── False ──► [END: Đóng cảnh báo False Positive]
          └── True
               │
         ┌─────┴────────────────────────┐
         ▼                              ▼
[3. Threat Intel Agent]      [4. Root Cause Analysis (RCA) Agent]
(Tra cứu IoC: VT, AbuseIPDB) (Tái hiện Process Tree & Timeline)
         └─────┬────────────────────────┘
               │
               ▼
   [5. Response Recommendation Agent] ──► Đề xuất hành động theo NIST Playbooks
               │
               ▼
   [Human-in-the-loop (HITL)] ──────► Chuyên viên SOC duyệt hành động
               │
               ▼
   [6. Reporting Agent] ─────────────► Tự động xuất Báo cáo sự cố toàn diện
```

### Phân công chi tiết các Agent:
1. **Data Ingestion Agent** *(Nam)*: Bóc tách log thô đa nguồn, làm sạch, giải mã Base64 PowerShell.
2. **Detection & Triage Agent** *(Nam)*: Chuyên viên SOC Tier 1 lọc nhiễu cảnh báo, đánh giá điểm rủi ro và phân loại mức độ nghiêm trọng.
3. **Threat Intelligence Agent** *(Nam)*: Tra cứu uy tín IoC, phân loại Threat Actor và ánh xạ mã kỹ thuật MITRE ATT&CK.
4. **Root Cause Analysis (RCA) Agent** *(Đô)*: Chuyên viên điều tra số SOC Tier 3 tái hiện phả hệ tiến trình, truy vết vector xâm nhập ban đầu.
5. **Response Recommendation Agent** *(Đô)*: Đề xuất phương án ngăn chặn (Isolate Host, Block IP, Kill Process) theo NIST Playbook có trạm dừng HITL.
6. **Reporting Agent** *(Đô)*: Tổng hợp toàn bộ hồ sơ sự cố sinh bản báo cáo toàn diện đạt chuẩn chuyên nghiệp.

---

## 🎯 3. Ba Kịch bản Sự cố Thực nghiệm

Hệ thống được kiểm thử trên 3 kịch bản tấn công thực tế bao phủ đa dạng bề mặt:
* **Kịch bản 1: Phishing Credential Harvesting & Initial Access:** Email giả mạo Office 365, liên kết lừa đảo thu thập mật khẩu, đăng nhập trái phép từ IP nước ngoài.
* **Kịch bản 2: Endpoint Malware Execution & Persistence:** Mở tệp văn bản macro, kích hoạt `powershell.exe -enc` tải payload C2, tạo Scheduled Task duy trì quyền truy cập.
* **Kịch bản 3: Network Reconnaissance & Lateral Movement:** Quét cổng nội bộ SYN scan qua Zeek `conn.log`, khai thác dịch vụ SMB để di chuyển ngang sang máy chủ dữ liệu.

---

## 📂 4. Cấu trúc Thư mục Dự án

```
TLCN/
├── data/
│   └── raw/                 # Dataset log mẫu cho 3 kịch bản
├── src/
│   ├── core/
│   │   ├── schemas.py       # Pydantic v2 schemas chuẩn hóa
│   │   └── state.py         # IncidentState & IncidentStateDict cho LangGraph
│   ├── agents/
│   │   └── prompts.py       # System prompts & CoT reasoning cho 6 Agent
│   └── tools/
│       ├── parsers.py       # Bộ bóc tách log Sysmon, Zeek, Windows EVTX
│       ├── threat_intel.py  # Công cụ CTI tra cứu IoC & MITRE ATT&CK
│       └── playbooks.py     # Response Playbooks xử lý mã độc & phishing
├── tests/
│   ├── test_schemas.py      # Unit tests cho Schemas
│   └── test_tools.py        # Unit tests cho Tools
├── scripts/
│   ├── generate_datasets.py # Script sinh dữ liệu kịch bản
│   ├── generate_report.py   # Script tạo Báo cáo Tuần 2-3-4 (.docx)
│   └── generate_week5_report.py # Script tạo Báo cáo Tuần 5 (.docx)
├── requirements.txt         # Thư viện phụ thuộc
└── README.md                # Tài liệu dự án
```

---

## 🚀 5. Hướng dẫn Cài đặt & Chạy Thử nghiệm

### Yêu cầu hệ thống:
* Python 3.10 trở lên
* `pydantic >= 2.7.0`

### Cài đặt thư viện:
```bash
pip install -r requirements.txt
```

### Chạy kiểm thử tự động (Unit Tests):
```bash
python3 -m unittest discover tests
```

---

## 📄 6. Tài liệu Báo cáo & Đề cương
Toàn bộ các bản thảo báo cáo, đề cương chi tiết đã được lưu trữ tập trung tại thư mục:  
📁 `/home/nam/Desktop/TLCN-NAM/BC/`
* `Bao_Cao_Thuc_Hien_Nhiem_Vu_Tuan_2_3_4.docx`
* `Bao_Cao_Thiet_Ke_Chi_Tiet_Tuan_5.docx`
* `DC-03-Phan Trường Đô-Nguyễn Phạm Hoài Nam.docx`
* `Text Document.docx`