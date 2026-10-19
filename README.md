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

## 📅 5. Kế hoạch và Bảng Phân công Nhiệm vụ (13 Tuần)

Hệ thống được triển khai theo lộ trình 13 tuần đã được chuẩn hóa tích hợp cùng **Wazuh SIEM** và **Môi trường Giả lập EVE-NG**:

| Tuần | Thời gian | Hạng mục công việc trọng tâm | Phân công chi tiết | Sản phẩm bàn giao (Deliverable) |
| :---: | :---: | :--- | :--- | :--- |
| **1** | 20/09 - 26/09 | Tiếp thu góp ý GVHD, chốt đề cương chi tiết | **Cả nhóm** (Nam: chuẩn hóa format tài liệu; Đô: rà soát mục tiêu kỹ thuật) | Đề cương chi tiết hoàn chỉnh |
| **2** | 27/09 - 03/10 | Nghiên cứu nền tảng & Tổng quan | • **Nam:** Quy trình NIST SP 800-61, format log (Sysmon, Zeek, EVTX)<br>• **Đô:** LLM, Prompt Engineering, Structured Output, Tool Calling | Bản thảo Báo cáo Chương 1 (Phần 1) |
| **3** | 04/10 - 10/10 | Nghiên cứu Agent & Tri thức an ninh | • **Nam:** Threat Intelligence, MITRE ATT&CK (STIX/TAXII)<br>• **Đô:** Kiến trúc LangGraph, State Management, Agent Orchestration | Bản thảo Báo cáo Chương 1 (Phần 2 & Khung Chương 2) |
| **4** | 11/10 - 17/10 | Đặc tả yêu cầu & Kiến trúc hệ thống | • **Cả nhóm:** Xác định 3 kịch bản sự cố & Luồng dữ liệu chung<br>• **Đô:** Thiết kế kiến trúc StateGraph điều phối<br>• **Nam:** Thiết kế Schema Input/Output chuẩn (Pydantic v2) | Tài liệu System Architecture & Sequence Diagram |
| **5** | 18/10 - 24/10 | Thiết kế chi tiết từng Agent & Tích hợp Wazuh (Làm song song) | • **Nam:** Thiết kế Ingestion Agent (kết nối Wazuh), Triage Agent (Wazuh Rule Level), Threat Intel Agent<br>• **Đô:** Thiết kế RCA Agent, Response Agent (Wazuh Active Response), Reporting Agent | Bản đặc tả chi tiết Prompts, Schemas (WazuhAlert), Tools |
| **6** | 25/10 - 31/10 | Dựng Lab EVE-NG, Hạ tầng Wazuh & Cơ sở tri thức RAG | • **Nam:** Thiết lập Topology EVE-NG (Firewall, Kali, Win10 Sysmon, Wazuh Server), xuất dataset alert thực tế<br>• **Đô:** Xây dựng Vector DB/ChromaDB lưu trữ MITRE ATT&CK Matrix & Wazuh Ruleset | Hạ tầng Lab EVE-NG + Bộ dataset Wazuh alert thực tế + RAG Knowledge base sẵn sàng |
| **7** | 01/11 - 07/11 | Hiện thực hóa Framework & Cụm Agent đầu vào | • **Đô:** Dựng khung LangGraph StateGraph, luồng chuyển trạng thái<br>• **Nam:** Code Wazuh Ingestion Tool (API & File stream) & Detection/Triage Agent | Khung điều phối + Ingestion Agent tiếp nhận cảnh báo Wazuh chạy độc lập |
| **8** | 08/11 - 14/11 | Hiện thực hóa Cụm Agent Chuyên sâu | • **Nam:** Code Threat Intel Agent (tích hợp API VirusTotal, AbuseIPDB)<br>• **Đô:** Code RCA Agent (bóc tách tiến trình Sysmon từ Wazuh Alert, suy luận attack path) | 2 Agent chuyên sâu vượt qua Unit Test |
| **9** | 15/11 - 21/11 | Hiện thực Cụm Đề xuất/Báo cáo & TÍCH HỢP ĐỢT 1 | • **Đô:** Code Response Agent (tích hợp Wazuh Active Response API) & Reporting Agent<br>• **Nam:** Ráp cụm Ingestion-Triage-ThreatIntel vào LangGraph | Prototype v0.1: Chạy luồng từ Wazuh Alert → Phân tích đe dọa & Đề xuất phản ứng |
| **10** | 22/11 - 28/11 | Tích hợp hoàn chỉnh & Dashboard UI | • **Đô:** Tích hợp RCA + Response + Report vào LangGraph, cơ chế HITL duyệt hành động<br>• **Nam:** Xây dựng Dashboard UI bằng Streamlit hiển thị đồng thời Wazuh alerts & Agent graph | Prototype v1.0: Hoàn chỉnh toàn bộ luồng End-to-End có UI tương tác |
| **11** | 29/11 - 05/12 | Thử nghiệm hệ thống trên 3 kịch bản EVE-NG | • **Nam:** Thực thi kịch bản Phishing & Scanning từ Kali EVE-NG, đo False Positive/Negative<br>• **Đô:** Thực thi kịch bản Malware trên Windows 10 EVE-NG, đo thời gian điều tra (MTTI) | Bộ số liệu thực nghiệm đầy đủ trên môi trường mạng EVE-NG |
| **12** | 06/12 - 12/12 | Đánh giá so sánh Baseline & Hoàn thiện báo cáo | • **Cả nhóm:** Chạy so sánh Multi-Agent với Single-Agent LLM và Wazuh Rule-based truyền thống<br>• **Nam:** Viết Chương 4 (Triển khai hệ thống EVE-NG, Wazuh & Agent)<br>• **Đô:** Viết Chương 5 (Kết quả thực nghiệm & Đánh giá) | Bản thảo toàn văn Báo cáo (Chương 1 đến 5) |
| **13** | 13/12 - 14/12 | Chuẩn bị bảo vệ & Đóng gói sản phẩm | • **Nam:** Dựng video demo kịch bản tấn công EVE-NG, thiết kế Slide báo cáo<br>• **Đô:** Kiểm tra mã nguồn, in ấn quyển báo cáo, tổng duyệt thuyết trình | Quyển báo cáo in nộp + Slide + Demo EVE-NG hoàn chỉnh |

---

## 🚀 6. Hướng dẫn Cài đặt & Chạy Thử nghiệm

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

## 📄 7. Tài liệu Báo cáo & Đề cương
Toàn bộ các bản thảo báo cáo, đề cương chi tiết đã được lưu trữ tập trung tại thư mục:  
📁 `/home/nam/Desktop/TLCN-NAM/BC/`
* `Bao_Cao_Thuc_Hien_Nhiem_Vu_Tuan_2_3_4.docx`: Báo cáo nghiệm thu giai đoạn Tuần 2, 3, 4.
* `Bao_Cao_Thiet_Ke_Chi_Tiet_Tuan_5.docx`: Đặc tả chi tiết Prompts, Schemas (WazuhAlert) và Tools của 6 Agent.
* `DC-03-Phan Trường Đô-Nguyễn Phạm Hoài Nam.docx`: Đề cương chi tiết đã duyệt với GVHD.
* `CongViecChinh.docx`: Bảng kế hoạch tiến độ 13 tuần tích hợp Wazuh & EVE-NG.