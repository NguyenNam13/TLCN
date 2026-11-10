# XÂY DỰNG HỆ THỐNG MULTI-AGENT ỨNG DỤNG LLM HỖ TRỢ ĐIỀU TRA SỰ CỐ AN NINH MẠNG

---

## 📌 1. Giới thiệu Tổng quan

Trong các trung tâm điều hành an ninh mạng (SOC) hiện đại, các chuyên viên phân tích thường xuyên đối mặt với hiện tượng quá tải cảnh báo (**Alert Fatigue**) với hàng chục nghìn cảnh báo mỗi ngày từ SIEM/EDR, dẫn đến việc bỏ sót các cuộc tấn công nguy hiểm và kéo dài thời gian phản ứng trung bình (**MTTD/MTTR**).

Hệ thống được phát triển nhằm xây dựng mô hình **Multi-Agent ứng dụng LLM** phối hợp cùng **Wazuh SIEM**, cơ sở tri thức **RAG ChromaDB** và cơ chế an toàn **Human-in-the-Loop (HITL)** nhằm:
1. **Tự động hóa toàn diện quy trình điều tra** theo chuẩn **NIST SP 800-61 Rev.2** và ma trận **MITRE ATT&CK**.
2. **Lọc nhiễu thông minh (Triage Ensemble):** Phân loại chính xác các cảnh báo giả (False Positive) và cảnh báo thật (True Positive) với độ tin cậy giải thích chuỗi suy luận (Chain-of-Thought), tích hợp lớp bảo vệ chống tấn công **Indirect Prompt Injection**.
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

### Chi tiết các Agent chức năng:
1. **Data Ingestion Agent**: Tiếp nhận log từ Webhook/File, tiền xử lý, bóc tách cấu trúc và tích hợp bộ giải mã đệ quy `AdvancedPowerShellDeobfuscator` (Base64 + GzipStream).
2. **Detection & Triage Agent**: Hoạt động như SOC Tier 1, sử dụng mô hình đồng thuận Ensemble phân định mức độ nghiêm trọng, loại tấn công và phát hiện False Positive.
3. **Threat Intelligence Agent**: Tích hợp RAG ChromaDB truy vấn ma trận MITRE ATT&CK, trích xuất IoC và tra cứu điểm danh tiếng (Threat Scoring) đa nguồn.
4. **Root Cause Analysis (RCA) Agent**: Chuyên viên điều tra số SOC Tier 3, xây dựng cây tiến trình cha-con (Process Tree), xác định vector đột nhập ban đầu và chuỗi 5 giai đoạn Cyber Kill Chain.
5. **Response Recommendation Agent**: Sinh mã kịch bản ứng cứu (PowerShell, Bash iptables, Wazuh Active Response API) với chính sách phân quyền an toàn.
6. **Reporting Agent**: Biên soạn báo cáo tổng kết theo chuẩn **NIST SP 800-61 Rev.2** và **Nghị định 13/2023/NĐ-CP**, xuất bản định dạng Markdown, JSON và Word `.docx`.

---

## 💎 3. Điểm Nhấn Kỹ Thuật Độc Đáo (Key Technical Innovations)

- **Cơ chế Event-Driven Webhook thời gian thực:** Tiếp nhận trực tiếp các cảnh báo từ Wazuh Manager qua endpoint HTTP POST `/api/v1/wazuh-alert` xác thực Secret Token, có cửa sổ khử trùng lặp cảnh báo (Sliding-window Deduplication).
- **Bộ giải mã đệ quy đa tầng (Recursive Deobfuscator):** Bóc tách các chuỗi lệnh PowerShell bị mã hóa lồng nhau thường gặp trong mã độc thực chiến (Emotet, Cobalt Strike, RATs).
- **Lớp bảo vệ phòng thủ đối kháng (Adversarial AI Guard):** Kiểm soát và vô hiệu hóa các nỗ lực tấn công Indirect Prompt Injection trong nội dung CommandLine nhằm thao túng mô hình Triage.
- **SOC AI Copilot tương tác 2 chiều:** Tích hợp mô hình ngôn ngữ lớn (OpenRouter/OmniRouter hoặc Local Ollama, kèm Deterministic Rule Engine fallback) hỗ trợ chuyên viên đối thoại, truy vấn và phê duyệt hành động ngăn chặn trực tiếp từ khung chat.
- **Incident Store & Quản lý Lịch sử Sự cố:** Lưu trữ bền vững (Persistence) trạng thái điều tra dưới dạng JSON, hỗ trợ xem lại lịch sử sự cố và tải lại báo cáo bất cứ lúc nào.
- **Streamlit Tactical Dashboard:** Giao diện tác chiến trực quan, tích hợp sơ đồ luồng thực thi động, biểu đồ Mermaid DAG, bảng IoC và các thẻ KPI theo dõi MTTR/MTTD.

---

## 📂 4. Cấu trúc Thư mục Dự án

```
TLCN/
├── data/                           # Dữ liệu tri thức RAG, mô hình ML & datasets
│   ├── chromadb/                   # Vector DB lưu trữ ma trận MITRE ATT&CK & Ruleset
│   ├── incidents/                  # Kho lưu trữ trạng thái các sự cố đã điều tra (JSON)
│   ├── knowledge_docs/             # Tài liệu tri thức bảo mật & playbooks (YAML)
│   ├── models/                     # Hồ sơ hành vi tấn công huấn luyện (Mordor/OTRF)
│   └── raw/                        # Bộ dataset thực nghiệm (Mordor, LogHub, Wazuh)
├── src/                            # Mã nguồn chính của hệ thống
│   ├── agents/                     # 6 Tác tử AI (Ingestion, Triage, CTI, RCA, Response, Report)
│   ├── api/                        # Webhook Receiver thời gian thực (Starlette / Uvicorn)
│   ├── copilot/                    # Trợ lý ảo SOC Copilot Chatbot & OmniRouter LLM Provider
│   ├── core/                       # Schemas (Pydantic v2), StateGraph Orchestrator, HITL, SecurityGuard
│   ├── tools/                      # Deobfuscator, Parsers, CTI, WazuhClient, RAG Knowledge, Playbooks
│   └── ui/                         # Streamlit Dashboard, Cyber Banner, Mermaid Diagrams, Components
├── run_live_soc.py                 # File thực thi khởi chạy đồng thời Webhook & Dashboard
├── requirements.txt                # Danh mục toàn bộ thư viện Python phụ thuộc
└── README.md                       # Tài liệu hướng dẫn sử dụng và kiến trúc
```

---

## 🚀 5. Hướng dẫn Cài đặt & Vận hành

### 5.1. Yêu cầu môi trường
- **Hệ điều hành:** Linux (Ubuntu 20.04+, Debian, Arch/CachyOS) hoặc macOS / Windows WSL2.
- **Python:** Phiên bản 3.10 trở lên (khuyến nghị Python 3.11 – 3.14).

### 5.2. Cài đặt thư viện tự động
```bash
# 1. Tạo và kích hoạt môi trường ảo (Virtual Environment)
python3 -m venv .venv
source .venv/bin/activate

# 2. Cài đặt toàn bộ dependencies tự động
pip install -r requirements.txt
```

### 5.3. Kiểm tra tính sẵn sàng của hệ thống (Pre-flight Check)
Trước khi khởi chạy, bạn có thể thực hiện kiểm tra nhanh toàn bộ các thành phần:
```bash
python run_live_soc.py --check-only
```

### 5.4. Khởi chạy toàn bộ Hệ thống (Khuyến nghị)
Sử dụng script tích hợp để khởi chạy đồng thời **Webhook Receiver (Port 8000)** và **Streamlit Dashboard (Port 8501)**:
```bash
python run_live_soc.py
```
Sau khi khởi chạy thành công:
- **Dashboard tác chiến:** `http://localhost:8501`
- **Endpoint nhận cảnh báo từ Wazuh:** `http://localhost:8000/api/v1/wazuh-alert`
- **Health check endpoint:** `http://localhost:8000/api/v1/health`

### 5.5. Khởi chạy riêng lẻ từng dịch vụ (Tùy chọn)
- **Chỉ chạy Dashboard UI:**
  ```bash
  python run_live_soc.py --ui-only
  # hoặc: streamlit run src/ui/dashboard.py
  ```
- **Chỉ chạy Webhook Server:**
  ```bash
  python run_live_soc.py --webhook-only
  # hoặc: python -m uvicorn src.api.webhook_server:app --host 0.0.0.0 --port 8000
  ```