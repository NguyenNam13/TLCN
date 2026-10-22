# XÂY DỰNG HỆ THỐNG MULTI-AGENT ỨNG DỤNG LLM HỖ TRỢ ĐIỀU TRA SỰ CỐ AN NINH MẠNG
## (AUTONOMOUS MULTI-AGENT CYBERSECURITY INCIDENT INVESTIGATION & RESPONSE SYSTEM)

> **Trường:** Đại học Sư phạm Kỹ thuật TP. Hồ Chí Minh (HCMUTE)  
> **Khoa:** Công nghệ Thông tin – **Bộ môn:** An toàn Thông tin  
> **Đề tài:** Khóa luận Tốt nghiệp / Tiểu luận Chuyên ngành An toàn Thông tin  
> **Sinh viên thực hiện:**  
> - **Nguyễn Phạm Hoài Nam** – MSSV: 23162059  
> - **Phan Trường Đô** – MSSV: 23162020  
> **Giảng viên hướng dẫn:** ThS. Đinh Công Đoan  
> **Thời gian thực hiện:** 20/09/2026 – 14/12/2026  
> **Trạng thái:** ✅ **Hoàn thiện 100% – Sẵn sàng Báo cáo & Nghiệm thu** (198/198 Test Cases PASS)

---

## 📌 1. Giới thiệu Tổng quan

Trong các trung tâm điều hành an ninh mạng (SOC) hiện đại, các chuyên viên phân tích thường xuyên đối mặt với hiện tượng quá tải cảnh báo (**Alert Fatigue**) với hàng chục nghìn cảnh báo mỗi ngày từ SIEM/EDR, dẫn đến việc bỏ sót các cuộc tấn công nguy hiểm và kéo dài thời gian phản ứng trung bình (**MTTD/MTTR**).

Đề tài nghiên cứu và phát triển **Hệ thống Multi-Agent ứng dụng LLM** phối hợp cùng **Wazuh SIEM**, cơ sở tri thức **RAG ChromaDB** và cơ chế an toàn **Human-in-the-Loop (HITL)** nhằm:
1. **Tự động hóa toàn diện quy trình điều tra** theo chuẩn **NIST SP 800-61 Rev.2** và ma trận **MITRE ATT&CK**.
2. **Lọc nhiễu thông minh (Triage Ensemble):** Phân loại chính xác các cảnh báo giả (False Positive) và cảnh báo thật (True Positive) với độ tin cậy giải thích chuỗi suy luận (Chain-of-Thought).
3. **Phân tích số chuyên sâu (Deep Forensics & RCA):** Tự động giải mã chuỗi PowerShell Base64/Gzip đa tầng, tái hiện phả hệ tiến trình Sysmon cấp miligiây (Process Lineage Tree) và truy vết điểm xâm nhập ban đầu (*Patient Zero*).
4. **Phản ứng an toàn có kiểm soát (HITL):** Đề xuất playbook ngăn chặn (Isolate Host, Block IP, Kill Process, Active Response) kèm cơ chế xem xét, chỉnh sửa tham số và hoàn tác (Rollback).
5. **Trợ lý ảo tương tác 2 chiều (SOC AI Copilot):** Tích hợp qua API OpenRouter/OmniRouter cho phép chuyên viên đối thoại, truy vấn dữ liệu sự cố và ra lệnh điều khiển hệ thống bằng ngôn ngữ tự nhiên.

---

## 🏗️ 2. Kiến trúc Hệ thống Multi-Agent

Hệ thống được điều phối tuần tự và song song trên nền tảng **LangGraph StateGraph DAG**:

```
[Log thô: Wazuh SIEM Webhook / Sysmon Event 1,3,11 / Windows Security 4624,4625]
                                  │
                                  ▼
                    [1. Data Ingestion Agent]
                    (Chuẩn hóa log, giải mã đệ quy Deobfuscator)
                                  │
                                  ▼
                 [2. Detection & Triage Agent]
                 (Ensemble 3 mô hình, xác định True/False Positive)
                                  │
                       (Sự cố có thực? is_incident)
                       ├── False ──► [END: Đóng cảnh báo Benign / Lọc nhiễu]
                       └── True
                                  │
            ┌─────────────────────┴─────────────────────┐
            ▼                                           ▼
 [3. Threat Intel Agent]                     [4. RCA Agent (Root Cause)]
 (Tra cứu VirusTotal, AbuseIPDB,             (Dựng cây tiến trình Sysmon,
  RAG Vector ChromaDB MITRE)                  truy vết Patient Zero & Timeline)
            └─────────────────────┬─────────────────────┘
                                  │
                                  ▼
                 [5. Response Recommendation Agent]
                 (Sinh kịch bản ngăn chặn NIST SP 800-61 + Active Response)
                                  │
                                  ▼
                 [Trạm dừng Human-in-the-Loop (HITL)]
                 (Chuyên viên SOC duyệt: APPROVE / REJECT / MODIFY / ROLLBACK)
                                  │
                                  ▼
                      [6. Reporting Agent]
                      (Tự động xuất báo cáo chuẩn Markdown, JSON, Word .docx)
```

### Phân công chi tiết các Agent:
1. **Data Ingestion Agent** *(Nam)*: Tiếp nhận log từ Webhook/File, tiền xử lý, bóc tách cấu trúc và tích hợp bộ giải mã đệ quy `AdvancedPowerShellDeobfuscator` (Base64 + GzipStream).
2. **Detection & Triage Agent** *(Nam)*: Hoạt động như SOC Tier 1, sử dụng mô hình đồng thuận Ensemble phân định mức độ nghiêm trọng, loại tấn công và phát hiện False Positive.
3. **Threat Intelligence Agent** *(Nam)*: Tích hợp RAG ChromaDB truy vấn ma trận MITRE ATT&CK, trích xuất IoC và tra cứu điểm danh tiếng (Threat Scoring) đa nguồn.
4. **Root Cause Analysis (RCA) Agent** *(Đô)*: Chuyên viên điều tra số SOC Tier 3, xây dựng cây tiến trình cha-con (Process Tree), xác định vector đột nhập ban đầu và chuỗi 5 giai đoạn Cyber Kill Chain.
5. **Response Recommendation Agent** *(Đô)*: Sinh mã kịch bản ứng cứu (PowerShell, Bash iptables, Wazuh Active Response API) với chính sách phân quyền an toàn.
6. **Reporting Agent** *(Đô)*: Biên soạn báo cáo tổng kết theo chuẩn **NIST SP 800-61 Rev.2** và **Nghị định 13/2023/NĐ-CP**, xuất bản định dạng Markdown, JSON và Word `.docx`.

---

## 💎 3. Điểm Nhấn Kỹ Thuật Độc Đáo (Key Technical Innovations)

- **Cơ chế Event-Driven Webhook thời gian thực:** Tiếp nhận trực tiếp các cảnh báo từ máy ảo Wazuh Manager All-in-One qua endpoint HTTP POST `/api/v1/wazuh-alert` xác thực Bearer Token, có cửa sổ khử trùng lặp cảnh báo (Sliding-window Deduplication).
- **Bộ giải mã đệ quy đa tầng (Recursive Deobfuscator):** Bóc tách các chuỗi lệnh PowerShell bị mã hóa lồng nhau thường gặp trong mã độc thực chiến (Emotet, Cobalt Strike, RATs).
- **SOC AI Copilot tương tác 2 chiều:** Tích hợp mô hình ngôn ngữ lớn (OpenRouter/OmniRouter hoặc Local Ollama, kèm Deterministic Rule Engine fallback) hỗ trợ chuyên viên ra lệnh phê duyệt hành động ngăn chặn trực tiếp từ khung chat.
- **Incident Store & Quản lý Lịch sử Sự cố:** Lưu trữ bền vững (Persistence) trạng thái điều tra dưới dạng JSON, hỗ trợ xem lại lịch sử sự cố và tải lại báo cáo bất cứ lúc nào.
- **Streamlit Tactical Dashboard:** Giao diện tác chiến trực quan, tích hợp sơ đồ luồng thực thi động, biểu đồ Mermaid DAG, bảng IoC và các thẻ KPI theo dõi MTTR/MTTD.

---

## 🎯 4. Bốn Kịch Bản Thực Nghiệm (Cyber Range Scenarios)

Dữ liệu thực nghiệm được tham chiếu chuẩn từ kho nghiên cứu quốc tế **OTRF Mordor Security Datasets** kết hợp mô phỏng trong phòng lab **EVE-NG & Wazuh OVA**:
1. **Kịch bản 1: Phishing Credential Access (`T1110.003`, `T1078.002`):** Thu thập mật khẩu, đăng nhập trái phép ngoài giờ từ IP bất thường, kích hoạt chuỗi leo thang đặc quyền.
2. **Kịch bản 2: Endpoint Malware & C2 Reverse Shell (`T1059.001`, `T1027`, `T1071.001`):** Thực thi mã độc qua PowerShell encoded payload, tạo tệp trong thư mục Temp và kết nối C2 Server.
3. **Kịch bản 3: Network Reconnaissance & Scanning (`T1018`, `T1046`):** Dò quét mạng diện rộng (Ping Sweep, SYN Port Scan) từ máy tấn công Kali Linux.
4. **Kịch bản 4: Benign Normal Logon (False Positive Verification):** Đăng nhập hợp lệ của quản trị viên trong giờ hành chính, chứng minh khả năng lọc nhiễu và ngắt sớm (Short-circuit) của Triage Agent.

---

## 📂 5. Cấu trúc Thư mục Dự án

```
TLCN/
├── src/                            # Mã nguồn chính của hệ thống
│   ├── agents/                     # 6 Tác tử AI (Ingestion, Triage, CTI, RCA, Response, Report)
│   ├── api/                        # Webhook Receiver thời gian thực (FastAPI / Starlette)
│   ├── copilot/                    # Trợ lý ảo SOC Copilot Chatbot & OmniRouter LLM Provider
│   ├── core/                       # Schemas (Pydantic v2), StateGraph Orchestrator, HITL, IncidentStore
│   ├── tools/                      # Deobfuscator, Parsers, CTI, WazuhClient, RAG ChromaDB, Playbooks
│   └── ui/                         # Streamlit Dashboard, Cyber Banner, Mermaid Diagrams, Components
├── tests/                          # 19 tệp kiểm thử tự động (198/198 Test Cases PASS 100%)
├── data/                           # Dữ liệu thực nghiệm & CSDL Vector
│   ├── chromadb/                   # Vector DB lưu trữ ma trận MITRE ATT&CK & Wazuh Ruleset
│   ├── incidents/                  # Kho lưu trữ trạng thái các sự cố đã điều tra (JSON)
│   ├── raw/                        # Bộ dataset nguyên gốc OTRF Mordor (Sysmon JSON Lines)
│   └── wazuh_alerts/               # Bộ cảnh báo mẫu 4 kịch bản phục vụ demo
├── run_live_soc.py                 # File thực thi khởi chạy đồng thời Webhook & Dashboard
├── requirements.txt                # Danh mục thư viện Python phụ thuộc
└── README.md                       # Tài liệu tổng quan dự án
```

---

## 🚀 6. Hướng dẫn Cài đặt & Vận hành

### 6.1. Yêu cầu môi trường
- **Hệ điều hành:** Linux (Ubuntu 22.04+, CachyOS, Debian) hoặc macOS / Windows WSL2.
- **Python:** Phiên bản 3.10 trở lên (khuyến nghị Python 3.11 – 3.14).

### 6.2. Cài đặt thư viện
```bash
# Tạo và kích hoạt môi trường ảo (Virtual Environment)
python3 -m venv .venv
source .venv/bin/activate

# Cài đặt toàn bộ dependencies
pip install -r requirements.txt
```

### 6.3. Khởi chạy toàn bộ Hệ thống (Khuyến nghị)
Sử dụng script tích hợp để khởi chạy đồng thời **Webhook Receiver (Port 8000)** và **Streamlit Dashboard (Port 8501)**:
```bash
python run_live_soc.py
```
Sau khi khởi chạy thành công:
- Truy cập Dashboard tác chiến tại: `http://localhost:8501`
- Endpoint nhận cảnh báo từ Wazuh SIEM: `http://localhost:8000/api/v1/wazuh-alert`

### 6.4. Khởi chạy riêng lẻ từng dịch vụ
- **Chỉ mở Dashboard UI:**
  ```bash
  streamlit run src/ui/dashboard.py
  ```
- **Chỉ mở Webhook Receiver:**
  ```bash
  python -m uvicorn src.api.webhook_server:app --host 0.0.0.0 --port 8000
  ```

---

## 🧪 7. Kiểm thử Chất lượng Hệ thống (Test Suite)

Dự án áp dụng phương pháp kiểm thử toàn diện với **198 test cases** tự động bao phủ 100% các thành phần logic cốt lõi:

```bash
# Thực thi toàn bộ test suite bằng pytest
pytest tests/ -v
```

### Kết quả kiểm định:
```text
TLCN/tests/test_copilot.py .................                             [  8%]
TLCN/tests/test_dataset_coverage.py ......                               [ 11%]
TLCN/tests/test_deobfuscator.py ...............                          [ 19%]
TLCN/tests/test_hitl.py ........                                         [ 23%]
TLCN/tests/test_hitl_default_safety.py ......                            [ 26%]
TLCN/tests/test_hitl_rollback.py ..........                              [ 31%]
TLCN/tests/test_ingestion_triage.py ...................                  [ 40%]
TLCN/tests/test_orchestrator.py ..................                       [ 50%]
TLCN/tests/test_prototype_v1.py ......                                   [ 53%]
TLCN/tests/test_rag.py ............                                      [ 59%]
TLCN/tests/test_rca_agent.py ............                                [ 65%]
TLCN/tests/test_reporting_agent.py .........                             [ 69%]
TLCN/tests/test_response_agent.py ..........                             [ 74%]
TLCN/tests/test_schemas.py ....                                          [ 76%]
TLCN/tests/test_threat_intel_agent.py ..........                         [ 81%]
TLCN/tests/test_tools.py ....                                            [ 83%]
TLCN/tests/test_ui.py ...................                                [ 93%]
TLCN/tests/test_wazuh.py ....                                            [ 95%]
TLCN/tests/test_webhook_receiver.py .........                            [100%]

============================= 198 passed in 12.65s =============================
```
- **Tổng số tests:** 198 test cases.
- **Tỷ lệ thành công:** **100% PASS (0 Failures, 0 Errors)**.
- Chi tiết từng mã test case (từ `TC-001` đến `TC-198`) được tự động hóa hoàn toàn trong thư mục `tests/`.

---

## 👥 8. Thông tin Liên hệ & Tác quyền

Đề tài được thực hiện bởi nhóm sinh viên ngành An toàn Thông tin – Trường Đại học Sư phạm Kỹ thuật TP.HCM:
- **Nguyễn Phạm Hoài Nam** – Email: `23162059@student.hcmute.edu.vn`
- **Phan Trường Đô** – Email: `23162020@student.hcmute.edu.vn`
- **Giảng viên hướng dẫn:** ThS. Đinh Công Đoan – Email: `doandc@hcmute.edu.vn`

*Mã nguồn được phân phối phục vụ mục đích học tập và nghiên cứu khoa học an toàn thông tin.*