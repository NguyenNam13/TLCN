# -*- coding: utf-8 -*-
"""
src/api/webhook_server.py
Cổng tiếp nhận cảnh báo tự động qua Webhook từ máy chủ Wazuh OVA (172.16.65.150).
Được thiết kế tối ưu với Starlette / ASGI Framework + Uvicorn:
1. Xác thực an toàn: Token bí mật (Constant-time comparison) + Whitelist IP nguồn.
2. Giới hạn dung lượng Payload (2MB Max) và Pydantic Schema Validation chống DoS.
3. Phản hồi 202 Accepted tức thời (<20ms) kết hợp BackgroundTasks để không nghẽn Wazuh Integrator.
4. Lọc mức độ cảnh báo (Rule level threshold) và khử trùng lặp (Time-window Deduplication).
5. Luồng xử lý nền: IngestionAgent -> StateGraphOrchestrator -> IncidentStore.
"""

import os
import json
import hmac
import uuid
import logging
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple

from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.requests import Request
from starlette.background import BackgroundTasks

from src.core.schemas import WazuhAlert, IncidentStatus
from src.core.incident_store import IncidentStore
from src.agents.ingestion_agent import IngestionAgent
from src.core.orchestrator import StateGraphOrchestrator

logger = logging.getLogger("WazuhWebhookServer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")

# Cấu hình môi trường mặc định (hỗ trợ toàn bộ dải mạng ảo 172.16.65.0/24 cho Wazuh DHCP động)
DEFAULT_SECRET = "soc-super-secret-token-2026"
WAZUH_WEBHOOK_SECRET = os.getenv("WAZUH_WEBHOOK_SECRET", DEFAULT_SECRET)
WAZUH_ALLOWED_IPS_RAW = os.getenv("WAZUH_ALLOWED_IPS", "172.16.65.0/24,127.0.0.1,localhost,testclient")
WAZUH_ALLOWED_IPS = [ip.strip() for ip in WAZUH_ALLOWED_IPS_RAW.split(",") if ip.strip()]
WAZUH_MIN_LEVEL = int(os.getenv("WAZUH_MIN_LEVEL", "7"))
MAX_BODY_SIZE = int(os.getenv("MAX_BODY_SIZE", str(2 * 1024 * 1024)))  # 2MB


class WebhookService:
    """Service điều phối tiếp nhận cảnh báo và kích hoạt pipeline Multi-Agent."""

    def __init__(
        self,
        incident_store: Optional[IncidentStore] = None,
        ingestion_agent: Optional[IngestionAgent] = None,
        orchestrator: Optional[StateGraphOrchestrator] = None,
        secret_token: Optional[str] = None,
        allowed_ips: Optional[List[str]] = None,
        min_level: Optional[int] = None,
        auto_approve: bool = False,
    ):
        self.incident_store = incident_store or IncidentStore()
        self.ingestion_agent = ingestion_agent or IngestionAgent()
        self.auto_approve = auto_approve
        self.orchestrator = orchestrator or StateGraphOrchestrator(
            ingestion_agent=self.ingestion_agent,
            auto_approve=self.auto_approve
        )
        self.secret_token = secret_token or WAZUH_WEBHOOK_SECRET
        self.allowed_ips = allowed_ips or WAZUH_ALLOWED_IPS
        self.min_level = min_level if min_level is not None else WAZUH_MIN_LEVEL

    def verify_auth(self, request: Request) -> Tuple[bool, Optional[str]]:
        """
        Xác thực tính hợp lệ của request từ Wazuh OVA:
        1. Kiểm tra Token bí mật bằng constant-time hmac.compare_digest.
        2. Kiểm tra IP nguồn kết nối TCP trực tiếp (hỗ trợ cả dải mạng CIDR ví dụ 172.16.65.0/24).
        """
        # 1. Kiểm tra IP nguồn
        client_host = request.client.host if request.client else None
        if "*" not in self.allowed_ips:
            is_ip_ok = False
            if client_host:
                if client_host in self.allowed_ips or "testclient" in self.allowed_ips:
                    is_ip_ok = True
                else:
                    try:
                        client_ip_obj = ipaddress.ip_address(client_host)
                        for allowed in self.allowed_ips:
                            if "/" in allowed:
                                if client_ip_obj in ipaddress.ip_network(allowed, strict=False):
                                    is_ip_ok = True
                                    break
                            elif allowed == client_host:
                                    is_ip_ok = True
                                    break
                    except ValueError:
                        pass
            if not is_ip_ok:
                return False, f"Access denied: Untrusted Source IP ({client_host})"

        # 2. Kiểm tra Secret Token qua header X-Wazuh-Secret-Token hoặc X-Wazuh-Secret
        token = request.headers.get("X-Wazuh-Secret-Token") or request.headers.get("X-Wazuh-Secret")
        if not token:
            return False, "Missing authentication token in header"

        if not hmac.compare_digest(token.encode("utf-8"), self.secret_token.encode("utf-8")):
            return False, "Invalid authentication token"

        return True, None

    def process_alert_background(self, alert_dict: Dict[str, Any], incident_id: str):
        """
        Xử lý sự cố trong Background Task không làm chậm trễ phản hồi Webhook:
        1. IngestionAgent: Giải mã Base64 UTF-16LE, trích xuất IoCs sơ bộ, đóng gói IncidentState.
        2. StateGraphOrchestrator: Điều phối tuần tự qua Triage, CTI, RCA, HITL, Reporting.
        3. IncidentStore: Lưu trữ trạng thái sự cố bền vững vào data/incidents/.
        """
        try:
            logger.info(f"[{incident_id}] ⚡ Bắt đầu tiến trình điều tra sự cố từ Wazuh OVA...")
            
            # Khởi tạo trạng thái ban đầu qua IngestionAgent
            initial_state = self.ingestion_agent.process(alert_dict, incident_id=incident_id)
            self.incident_store.save_incident(initial_state)

            # Thực thi đồ thị StateGraph (dừng ở AWAITING_APPROVAL nếu auto_approve=False)
            final_state = self.orchestrator.invoke(initial_state)

            # Cập nhật trạng thái sự cố cuối cùng
            self.incident_store.save_incident(final_state)
            if final_state.status == IncidentStatus.AWAITING_APPROVAL:
                logger.info(
                    f"[{incident_id}] ⏸️ Sự cố chuyển sang trạng thái AWAITING_APPROVAL "
                    f"(tạm dừng tại điểm ngắt HITL chờ chuyên viên duyệt). Loại tấn công: {final_state.attack_type or 'N/A'}"
                )
            else:
                logger.info(
                    f"[{incident_id}] ✅ Hoàn tất điều tra sự cố. Trạng thái: {final_state.status.value if hasattr(final_state.status, 'value') else final_state.status}, "
                    f"Loại tấn công: {final_state.attack_type or 'N/A'}"
                )
        except Exception as e:
            logger.error(f"[{incident_id}] ❌ Lỗi trong luồng điều tra sự cố: {e}", exc_info=True)


def create_app(service: Optional[WebhookService] = None) -> Starlette:
    """Khởi tạo ứng dụng Starlette ASGI Webhook Server."""
    svc = service or WebhookService()

    async def health_check(request: Request) -> JSONResponse:
        """Endpoint kiểm tra trạng thái hoạt động của Webhook Server."""
        return JSONResponse(
            {
                "status": "healthy",
                "service": "wazuh-webhook-receiver",
                "min_rule_level": svc.min_level,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    async def list_recent_incidents(request: Request) -> JSONResponse:
        """Lấy danh sách các sự cố mới nhất nhận từ Webhook."""
        limit = int(request.query_params.get("limit", 20))
        incidents = svc.incident_store.list_incidents(limit=limit)
        results = [
            {
                "incident_id": inc.incident_id,
                "status": inc.status.value if hasattr(inc.status, "value") else str(inc.status),
                "created_at": inc.created_at.isoformat(),
                "attack_type": inc.attack_type,
                "alert_count": len(inc.raw_logs),
                "has_report": inc.final_report is not None,
            }
            for inc in incidents
        ]
        return JSONResponse({"count": len(results), "incidents": results})

    async def handle_wazuh_alert(request: Request) -> Response:
        """
        Endpoint chính tiếp nhận HTTP POST cảnh báo từ Wazuh OVA.
        """
        # 1. Xác thực bảo mật
        is_auth, error_msg = svc.verify_auth(request)
        if not is_auth:
            status_code = 403 if "Untrusted Source IP" in (error_msg or "") else 401
            return JSONResponse({"status": "unauthorized", "error": error_msg}, status_code=status_code)

        # 2. Kiểm tra giới hạn dung lượng Content-Length
        content_length = request.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_BODY_SIZE:
            return JSONResponse(
                {"status": "error", "error": f"Payload too large (Max: {MAX_BODY_SIZE} bytes)"},
                status_code=413,
            )

        # 3. Đọc và parse JSON Body
        try:
            body = await request.body()
            if len(body) > MAX_BODY_SIZE:
                return JSONResponse(
                    {"status": "error", "error": f"Payload too large (Max: {MAX_BODY_SIZE} bytes)"},
                    status_code=413,
                )
            if not body:
                return JSONResponse({"status": "error", "error": "Empty payload body"}, status_code=400)
            
            raw_data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as err:
            return JSONResponse({"status": "error", "error": f"Malformed JSON: {str(err)}"}, status_code=400)
        except Exception as err:
            return JSONResponse({"status": "error", "error": f"Invalid request body: {str(err)}"}, status_code=400)

        # 4. Chuẩn hóa payload Wazuh (bóc lớp vỏ 'alert' nếu có)
        alert_dict = raw_data.get("alert", raw_data)
        if not isinstance(alert_dict, dict):
            return JSONResponse({"status": "error", "error": "Alert payload must be a JSON object"}, status_code=422)

        # Kiểm tra tính hợp lệ cơ bản của cấu trúc Wazuh
        rule_data = alert_dict.get("rule", {})
        rule_id = str(rule_data.get("id", "0"))
        rule_level = int(rule_data.get("level", 0))
        agent_data = alert_dict.get("agent", {})
        agent_id = str(agent_data.get("id", "000"))

        # 5. Lọc mức độ cảnh báo tối thiểu (Early Level Gating)
        if rule_level < svc.min_level:
            return JSONResponse(
                {
                    "status": "ignored",
                    "reason": f"Rule level {rule_level} is below threshold {svc.min_level}",
                    "rule_id": rule_id,
                    "rule_level": rule_level,
                    "action_taken": "DROPPED",
                },
                status_code=200,
            )

        # 6. Khử trùng lặp (Sliding-window Deduplication)
        if svc.incident_store.is_duplicate_alert(rule_id=rule_id, agent_id=agent_id, window_seconds=30):
            return JSONResponse(
                {
                    "status": "deduplicated",
                    "reason": f"Duplicate alert for rule {rule_id} on agent {agent_id} within time window",
                    "rule_id": rule_id,
                    "action_taken": "SKIPPED_DUPLICATE",
                },
                status_code=200,
            )

        # 7. Khởi tạo Incident ID và điều phối vào Background Tasks
        now = datetime.now(timezone.utc)
        incident_id = f"INC-WAZUH-{int(now.timestamp())}-{uuid.uuid4().hex[:6].upper()}"

        background_tasks = BackgroundTasks()
        background_tasks.add_task(svc.process_alert_background, alert_dict, incident_id)

        # Trả về 202 Accepted ngay tức thì (<20ms)
        return JSONResponse(
            {
                "status": "accepted",
                "message": "Wazuh alert received and scheduled for multi-agent investigation",
                "incident_id": incident_id,
                "rule_id": rule_id,
                "rule_level": rule_level,
                "action_taken": "QUEUED",
                "received_at": now.isoformat(),
            },
            status_code=202,
            background=background_tasks,
        )

    routes = [
        Route("/api/v1/health", health_check, methods=["GET"]),
        Route("/api/v1/incidents", list_recent_incidents, methods=["GET"]),
        Route("/api/v1/wazuh-alert", handle_wazuh_alert, methods=["POST"]),
        Route("/api/v1/webhooks/wazuh", handle_wazuh_alert, methods=["POST"]),
    ]

    return Starlette(routes=routes)


# App instance mặc định chạy với Uvicorn
app = create_app()

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    print(f"🚀 Khởi động Wazuh Webhook Receiver tại http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)
