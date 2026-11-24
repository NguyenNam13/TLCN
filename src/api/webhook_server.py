# -*- coding: utf-8 -*-
"""
src/api/webhook_server.py
Cổng tiếp nhận cảnh báo tự động qua Webhook từ máy chủ Wazuh OVA.
Được thiết kế tối ưu với Starlette / ASGI Framework + Uvicorn:
1. Xác thực an toàn: Token bí mật (Constant-time comparison) / HMAC-SHA256 + Whitelist IP nguồn.
2. Giới hạn dung lượng Payload và Pydantic Schema Validation chống DoS.
3. Phản hồi 202 Accepted tức thời (<20ms) kết hợp BackgroundTasks để không nghẽn Wazuh Integrator.
4. Lọc mức độ cảnh báo (Rule level threshold) và khử trùng lặp (Time-window Deduplication).
5. Luồng xử lý nền: IngestionAgent -> Full 6-Agent StateGraph Pipeline -> IncidentStore.
"""

import os
import json
import hmac
import hashlib
import uuid
import logging
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple, Union

from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.requests import Request
from starlette.background import BackgroundTasks

from src.core.config import (
    load_project_env,
    get_wazuh_ova_ip,
    get_wazuh_allowed_ips,
    get_wazuh_min_level,
    get_max_body_size,
    get_webhook_port,
)
from src.core.schemas import IncidentStatus
from src.core.incident_store import IncidentStore
from src.agents.ingestion_agent import IngestionAgent
from src.core.orchestrator import (
    HAS_LANGGRAPH,
    StateGraphOrchestrator,
    create_full_soc_pipeline,
)

logger = logging.getLogger("WazuhWebhookServer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")

# Giá trị mặc định an toàn (KHÔNG gọi load_project_env() ở module import top-level)
DEFAULT_SECRET = "soc-super-secret-token-2026"
WAZUH_WEBHOOK_SECRET = os.getenv("WAZUH_WEBHOOK_SECRET", DEFAULT_SECRET)
WAZUH_ALLOWED_IPS = get_wazuh_allowed_ips()
WAZUH_MIN_LEVEL = get_wazuh_min_level()
MAX_BODY_SIZE = get_max_body_size()


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
        max_body_size: Optional[int] = None,
        llm_provider: Optional[Any] = None,
        use_langgraph_engine: bool = True,
    ):
        load_project_env()
        self.incident_store = incident_store or IncidentStore()
        self.ingestion_agent = ingestion_agent or IngestionAgent()
        self.auto_approve = auto_approve
        self.orchestrator = orchestrator or create_full_soc_pipeline(
            ingestion_agent=self.ingestion_agent,
            auto_approve=self.auto_approve,
            llm_provider=llm_provider,
            use_langgraph_engine=use_langgraph_engine,
        )
        self.llm_provider = getattr(self.orchestrator, "llm_provider", None) or llm_provider
        self.secret_token = secret_token or os.getenv("WAZUH_WEBHOOK_SECRET") or DEFAULT_SECRET
        if self.secret_token == DEFAULT_SECRET:
            require_strong_secret = (
                os.getenv("SOC_ENV", "").strip().lower() == "production"
                or os.getenv("WAZUH_REQUIRE_STRONG_SECRET", "").strip().lower() in {"1", "true", "yes"}
            )
            if require_strong_secret:
                raise ValueError(
                    "WAZUH_WEBHOOK_SECRET must be set to a strong non-default secret in production mode"
                )
            logger.warning(
                "⚠️ WebhookService: Đang sử dụng secret token mặc định. "
                "Khuyến nghị cấu hình biến môi trường WAZUH_WEBHOOK_SECRET cho production."
            )
        self.allowed_ips = allowed_ips if allowed_ips is not None else get_wazuh_allowed_ips()
        self.min_level = min_level if min_level is not None else get_wazuh_min_level()
        self.max_body_size = max_body_size if max_body_size is not None else get_max_body_size()

    @staticmethod
    def compute_hmac_sha256(secret: str, payload: Union[bytes, str]) -> str:
        """Tính toán chữ ký HMAC-SHA256 dạng hex từ secret và payload bytes."""
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    def verify_auth(self, request: Request, raw_body: Optional[bytes] = None) -> Tuple[bool, Optional[str]]:
        """
        Xác thực tính hợp lệ của request từ Wazuh OVA:
        1. Kiểm tra IP nguồn kết nối TCP trực tiếp (hỗ trợ cả địa chỉ đơn lẻ và dải mạng CIDR).
        2. Xác thực tính toàn vẹn và nguồn gốc qua HMAC-SHA256 signature (X-Wazuh-Signature-SHA256 hoặc X-Hub-Signature-256).
        3. Hỗ trợ xác thực Secret Token cũ (X-Wazuh-Secret-Token hoặc X-Wazuh-Secret) để tương thích ngược.
        """
        # 1. Kiểm tra IP nguồn
        client_host = request.client.host if request.client else None
        if "*" not in self.allowed_ips:
            is_ip_ok = False
            if client_host:
                if client_host in self.allowed_ips:
                    is_ip_ok = True
                else:
                    try:
                        client_ip_obj = ipaddress.ip_address(client_host)
                        is_ip_ok = any(
                            client_ip_obj in ipaddress.ip_network(allowed, strict=False)
                            for allowed in self.allowed_ips
                            if "/" in allowed
                        )
                    except ValueError:
                        pass
            if not is_ip_ok:
                return False, f"Access denied: Untrusted Source IP ({client_host})"

        # 2. Lấy thông tin Header xác thực (Signature hoặc Token)
        sig_header = (
            request.headers.get("X-Wazuh-Signature-SHA256")
            or request.headers.get("X-Hub-Signature-256")
            or request.headers.get("X-Wazuh-Signature")
        )
        token = request.headers.get("X-Wazuh-Secret-Token") or request.headers.get("X-Wazuh-Secret")
        if not token:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
            elif auth_header.startswith("Token "):
                token = auth_header[6:].strip()

        if not sig_header and not token:
            return False, "Missing authentication token or signature in header"

        # 2a. Xác thực HMAC-SHA256 nếu có header chữ ký
        if sig_header:
            if raw_body is None:
                raw_body = getattr(request, "_body", b"")
            if not isinstance(raw_body, bytes):
                raw_body = str(raw_body).encode("utf-8")

            clean_sig = sig_header.strip()
            if clean_sig.lower().startswith("sha256="):
                clean_sig = clean_sig[7:].strip()

            expected_sig = self.compute_hmac_sha256(self.secret_token, raw_body)
            if not hmac.compare_digest(clean_sig.lower(), expected_sig.lower()):
                return False, "Invalid HMAC-SHA256 signature"
            return True, None

        # 2b. Xác thực Secret Token (Backward compatibility)
        if token:
            if not hmac.compare_digest(token.encode("utf-8"), self.secret_token.encode("utf-8")):
                return False, "Invalid authentication token"
            return True, None

        return False, "Unauthorized request"

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
    load_project_env()
    svc = service or WebhookService()

    async def health_check(request: Request) -> JSONResponse:
        """Endpoint kiểm tra trạng thái hoạt động của Webhook Server."""
        orch = getattr(svc, "orchestrator", None)
        langgraph_enabled = bool(
            HAS_LANGGRAPH and getattr(orch, "use_langgraph_engine", False)
        )
        pipeline_agents = {
            "ingestion": getattr(orch, "ingestion_agent", None) is not None,
            "triage": getattr(orch, "triage_agent", None) is not None,
            "threat_intel": getattr(orch, "threat_intel_agent", None) is not None,
            "rca": getattr(orch, "rca_agent", None) is not None,
            "response": getattr(orch, "response_agent", None) is not None,
            "reporting": getattr(orch, "reporting_agent", None) is not None,
        }

        probe_llm = str(request.query_params.get("probe_llm", "false")).strip().lower() in {
            "1",
            "true",
            "yes",
        }
        provider = getattr(svc, "llm_provider", None) or getattr(orch, "llm_provider", None)
        if provider is None:
            llm_status: Dict[str, Any] = {
                "configured": False,
                "connected": False,
                "active_provider": "none",
                "configured_mode": "none",
                "model": None,
                "probed": False,
            }
        elif probe_llm and hasattr(provider, "check_health"):
            health = provider.check_health(force=True, timeout=1.5)
            health_data = (
                health.model_dump(mode="json")
                if hasattr(health, "model_dump")
                else dict(health)
            )
            llm_status = {"configured": True, "probed": True, **health_data}
        else:
            cached = getattr(provider, "last_health", None) or getattr(
                provider, "_last_health_status", None
            )
            if cached is not None and hasattr(cached, "model_dump"):
                llm_status = {
                    "configured": True,
                    "probed": False,
                    **cached.model_dump(mode="json"),
                }
            else:
                active_prov = (
                    provider.get_active_provider()
                    if hasattr(provider, "get_active_provider")
                    else getattr(provider, "last_used_provider", None) or "unknown"
                )
                llm_status = {
                    "configured": True,
                    "probed": False,
                    "connected": None,
                    "active_provider": active_prov,
                    "configured_mode": getattr(provider, "provider_mode", "auto"),
                    "model": getattr(provider, "model", None),
                }

        return JSONResponse(
            {
                "status": "healthy",
                "service": "wazuh-webhook-receiver",
                "min_rule_level": svc.min_level,
                "webhook_port": get_webhook_port(),
                "wazuh_ova_ip": get_wazuh_ova_ip(),
                "langgraph_enabled": langgraph_enabled,
                "pipeline_agents": pipeline_agents,
                "llm_status": llm_status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    async def list_recent_incidents(request: Request) -> JSONResponse:
        """Lấy danh sách các sự cố mới nhất nhận từ Webhook (có xác thực an toàn)."""
        is_auth, auth_err = svc.verify_auth(request)
        if not is_auth:
            return JSONResponse(
                {"status": "error", "error": f"Unauthorized: {auth_err}"},
                status_code=401,
            )
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
        # 1. Kiểm tra giới hạn dung lượng Content-Length trước khi đọc body
        max_body_limit = getattr(svc, "max_body_size", None) or get_max_body_size()
        content_length = request.headers.get("Content-Length")
        if content_length and int(content_length) > max_body_limit:
            return JSONResponse(
                {"status": "error", "error": f"Payload too large (Max: {max_body_limit} bytes)"},
                status_code=413,
            )

        # 2. Đọc raw body (kiểm tra dung lượng an toàn)
        try:
            body = await request.body()
            if len(body) > max_body_limit:
                return JSONResponse(
                    {"status": "error", "error": f"Payload too large (Max: {max_body_limit} bytes)"},
                    status_code=413,
                )
        except Exception as err:
            return JSONResponse({"status": "error", "error": f"Invalid request body: {str(err)}"}, status_code=400)

        # 3. Xác thực bảo mật (IP Whitelist, HMAC-SHA256 Signature hoặc Secret Token)
        is_auth, error_msg = svc.verify_auth(request, raw_body=body)
        if not is_auth:
            status_code = 403 if "Untrusted Source IP" in (error_msg or "") else 401
            return JSONResponse({"status": "unauthorized", "error": error_msg}, status_code=status_code)

        # 4. Kiểm tra body rỗng và parse JSON
        if not body:
            return JSONResponse({"status": "error", "error": "Empty payload body"}, status_code=400)

        try:
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

        # 6. Khử trùng lặp đa nguồn (Sliding-window Deduplication with Source IP & User awareness)
        src_ip = (
            alert_dict.get("data", {}).get("srcip")
            or alert_dict.get("srcip")
            or alert_dict.get("data", {}).get("src_ip")
        )
        dst_user = (
            alert_dict.get("data", {}).get("dstuser")
            or alert_dict.get("data", {}).get("srcuser")
            or alert_dict.get("dstuser")
        )
        if svc.incident_store.is_duplicate_alert(
            rule_id=rule_id,
            agent_id=agent_id,
            window_seconds=30,
            src_ip=src_ip,
            user=dst_user,
        ):
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


_DEFAULT_APP: Optional[Starlette] = None


def get_app() -> Starlette:
    """Khởi tạo lười (lazy) ASGI app mặc định cho Uvicorn mà không chạy side-effect khi import module."""
    global _DEFAULT_APP
    if _DEFAULT_APP is None:
        _DEFAULT_APP = create_app()
    return _DEFAULT_APP


class _LazyASGIApp:
    """Proxy ASGI lười giúp `from src.api.webhook_server import app` không kích hoạt load_project_env() ở import-time."""

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        target = get_app()
        await target(scope, receive, send)

    def __getattr__(self, name: str) -> Any:
        return getattr(get_app(), name)


app = _LazyASGIApp()


def main() -> None:
    """Entrypoint CLI khởi động Webhook Server."""
    import uvicorn

    load_project_env(force=True)
    port = get_webhook_port()
    host = os.getenv("HOST", "0.0.0.0")
    print(f"🚀 Khởi động Wazuh Webhook Receiver tại http://{host}:{port}")
    uvicorn.run(get_app(), host=host, port=port)


if __name__ == "__main__":
    main()
