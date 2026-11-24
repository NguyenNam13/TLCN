#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_live_soc.py
Trình khởi động hợp nhất Hệ thống SOC Multi-Agent Live Mode.
Khởi chạy song song:
1. FastAPI/Starlette Webhook Receiver: Nhận cảnh báo thời gian thực từ Wazuh OVA.
2. Streamlit Dashboard: Giao diện điều hành tác chiến SOC và duyệt HITL.

Sử dụng:
    python3 run_live_soc.py                 # Chạy cả 2 dịch vụ song song
    python3 run_live_soc.py --webhook-only  # Chỉ chạy Webhook Server
    python3 run_live_soc.py --ui-only       # Chỉ chạy Streamlit Dashboard
    python3 run_live_soc.py --check-only    # Kiểm tra cấu hình và kiểm thử nhanh (offline)
"""

import os
import sys
import time
import argparse
import subprocess
from typing import Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.core.config import (
    load_project_env,
    get_wazuh_ova_ip,
    get_wazuh_host_ip,
    get_webhook_port,
    get_llm_provider_mode,
)


def check_system() -> bool:
    """Kiểm tra tính sẵn sàng của cấu hình offline, full 6-agent pipeline và Dashboard headless."""
    ova_ip = get_wazuh_ova_ip()
    host_ip = get_wazuh_host_ip()
    webhook_port = get_webhook_port()
    llm_mode = get_llm_provider_mode()

    print("=" * 65)
    print("🔍 KIỂM TRA HỆ THỐNG SOC MULTI-AGENT (PRE-FLIGHT CHECK)")
    print("=" * 65)
    print(f"  [i] Cấu hình: Wazuh OVA={ova_ip} | Host={host_ip}:{webhook_port} | LLM Mode={llm_mode}")

    # 1. Kiểm tra IncidentStore
    try:
        from src.core.incident_store import IncidentStore

        store = IncidentStore()
        inc_count = len(store.list_incidents())
        print(f"  [✓] IncidentStore: Sẵn sàng (Đang lưu trữ {inc_count} sự cố)")
    except Exception as e:
        print(f"  [✗] IncidentStore Lỗi: {e}")
        return False

    # 2. Kiểm tra Full 6-Agent StateGraph Pipeline
    try:
        from src.core.orchestrator import create_full_soc_pipeline

        pipeline = create_full_soc_pipeline(auto_approve=False)
        missing = [
            name
            for name in (
                "ingestion_agent",
                "triage_agent",
                "threat_intel_agent",
                "rca_agent",
                "response_agent",
                "reporting_agent",
            )
            if getattr(pipeline, name, None) is None
        ]
        if missing:
            raise RuntimeError(f"Thiếu agents: {missing}")
        if pipeline.auto_approve is not False:
            raise RuntimeError("auto_approve mặc định phải là False")
        print("  [✓] Full 6-Agent StateGraph Pipeline: Sẵn sàng (Shared LLM & RAG)")
    except Exception as e:
        print(f"  [✗] StateGraph Pipeline Lỗi: {e}")
        return False

    # 3. Kiểm tra Webhook App
    try:
        from src.api.webhook_server import create_app

        _ = create_app()
        print("  [✓] Starlette/ASGI Webhook Server: Sẵn sàng")
    except Exception as e:
        print(f"  [✗] Webhook Server Lỗi: {e}")
        return False

    # 4. Kiểm tra Dashboard Headless
    try:
        from src.ui.dashboard import run_dashboard_headless_check

        res = run_dashboard_headless_check()
        ok = bool(res.get("ok")) if isinstance(res, dict) else bool(res)
        if ok:
            print("  [✓] Streamlit Dashboard: Sẵn sàng (Headless check PASS)")
        else:
            print("  [✗] Streamlit Dashboard: Headless check FAIL")
            return False
    except Exception as e:
        print(f"  [✗] Streamlit Dashboard Lỗi: {e}")
        return False

    print("=" * 65)
    print(f"✅ HỆ THỐNG ĐÃ SẴN SÀNG KẾT NỐI VỚI WAZUH OVA ({ova_ip})!")
    print("=" * 65)
    return True


def run_webhook_server(host: str = "0.0.0.0", port: Optional[int] = None):
    """Khởi chạy Uvicorn Webhook Server."""
    target_port = port if port is not None else get_webhook_port()
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "src.api.webhook_server:app",
        f"--host={host}",
        f"--port={target_port}",
        "--log-level=info",
    ]
    return subprocess.Popen(cmd, cwd=BASE_DIR)


def run_streamlit_dashboard(port: int = 8501):
    """Khởi chạy Streamlit Dashboard."""
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "src/ui/dashboard.py",
        f"--server.port={port}",
        "--server.headless=true",
        "--theme.base=dark",
    ]
    return subprocess.Popen(cmd, cwd=BASE_DIR)


def main():
    load_project_env(force=True)
    default_webhook_port = get_webhook_port()

    parser = argparse.ArgumentParser(description="Khởi động Hệ thống SOC Multi-Agent Live Mode")
    parser.add_argument("--check-only", action="store_true", help="Chỉ kiểm tra cấu hình hệ thống (offline)")
    parser.add_argument("--webhook-only", action="store_true", help="Chỉ chạy Webhook Receiver")
    parser.add_argument("--ui-only", action="store_true", help="Chỉ chạy Streamlit Dashboard")
    parser.add_argument("--host", default="0.0.0.0", help="Địa chỉ IP lắng nghe (mặc định: 0.0.0.0)")
    parser.add_argument(
        "--port-api",
        type=int,
        default=default_webhook_port,
        help=f"Cổng Webhook API (mặc định: {default_webhook_port})",
    )
    parser.add_argument("--port-ui", type=int, default=8501, help="Cổng Streamlit Dashboard (mặc định: 8501)")

    args = parser.parse_args()

    if args.check_only:
        success = check_system()
        sys.exit(0 if success else 1)

    ova_ip = get_wazuh_ova_ip()
    host_ip = get_wazuh_host_ip()
    llm_mode = get_llm_provider_mode()

    print("\n" + "=" * 70)
    print("🛡️  KHỞI ĐỘNG HỆ THỐNG SOC MULTI-AGENT (LIVE WAZUH OVA MODE)")
    print("=" * 70)
    print(f"  • Webhook Endpoint:  http://{args.host}:{args.port_api}/api/v1/wazuh-alert")
    print(f"  • Web Dashboard UI:  http://localhost:{args.port_ui}")
    print(f"  • Wazuh OVA Target:  {ova_ip} -> Host {host_ip}:{args.port_api}")
    print(f"  • LLM Provider Mode: {llm_mode}")
    print("=" * 70)
    print("Nhấn Ctrl+C để dừng toàn bộ hệ thống an toàn.\n")

    processes = []

    try:
        if not args.ui_only:
            print(f"[*] Đang khởi chạy Webhook Receiver trên cổng {args.port_api}...")
            p_api = run_webhook_server(host=args.host, port=args.port_api)
            processes.append(p_api)
            time.sleep(1)

        if not args.webhook_only:
            print(f"[*] Đang khởi chạy Streamlit Dashboard trên cổng {args.port_ui}...")
            p_ui = run_streamlit_dashboard(port=args.port_ui)
            processes.append(p_ui)

        # Chờ các tiến trình
        while True:
            for p in processes:
                if p.poll() is not None:
                    print(f"\n[!] Một dịch vụ đã dừng (Mã thoát: {p.returncode}). Dừng hệ thống.")
                    return
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[*] Đang tắt các dịch vụ an toàn...")
    finally:
        for p in processes:
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                p.kill()
        print("[✓] Đã dừng toàn bộ dịch vụ.")


if __name__ == "__main__":
    main()
