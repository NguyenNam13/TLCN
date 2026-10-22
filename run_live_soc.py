#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_live_soc.py
Trình khởi động hợp nhất Hệ thống SOC Multi-Agent Live Mode.
Khởi chạy song song:
1. FastAPI Webhook Receiver (Port 8000): Nhận cảnh báo thời gian thực từ Wazuh OVA (172.16.65.150).
2. Streamlit Dashboard (Port 8501): Giao diện điều hành tác chiến SOC và duyệt HITL.

Sử dụng:
    python3 run_live_soc.py                 # Chạy cả 2 dịch vụ song song
    python3 run_live_soc.py --webhook-only  # Chỉ chạy Webhook Server
    python3 run_live_soc.py --ui-only       # Chỉ chạy Streamlit Dashboard
    python3 run_live_soc.py --check-only    # Kiểm tra cấu hình và kiểm thử nhanh
"""

import os
import sys
import time
import signal
import argparse
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def check_system():
    """Kiểm tra tính sẵn sàng của các thành phần hệ thống."""
    print("=" * 65)
    print("🔍 KIỂM TRA HỆ THỐNG SOC MULTI-AGENT (PRE-FLIGHT CHECK)")
    print("=" * 65)

    # 1. Kiểm tra IncidentStore
    try:
        from src.core.incident_store import IncidentStore
        store = IncidentStore()
        inc_count = len(store.list_incidents())
        print(f"  [✓] IncidentStore: Sẵn sàng (Đang lưu trữ {inc_count} sự cố)")
    except Exception as e:
        print(f"  [✗] IncidentStore Lỗi: {e}")
        return False

    # 2. Kiểm tra Webhook App
    try:
        from src.api.webhook_server import app
        print("  [✓] FastAPI/Starlette Webhook Server: Sẵn sàng")
    except Exception as e:
        print(f"  [✗] Webhook Server Lỗi: {e}")
        return False

    # 3. Kiểm tra Dashboard Headless
    try:
        from src.ui.dashboard import run_dashboard_headless_check
        ok = run_dashboard_headless_check()
        if ok:
            print("  [✓] Streamlit Dashboard: Sẵn sàng (Headless check PASS)")
        else:
            print("  [✗] Streamlit Dashboard: Headless check FAIL")
            return False
    except Exception as e:
        print(f"  [✗] Streamlit Dashboard Lỗi: {e}")
        return False

    print("=" * 65)
    print("✅ HỆ THỐNG ĐÃ SẴN SÀNG KẾT NỐI VỚI WAZUH OVA (172.16.65.150)!")
    print("=" * 65)
    return True


def run_webhook_server(host: str = "0.0.0.0", port: int = 8000):
    """Khởi chạy Uvicorn Webhook Server."""
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "src.api.webhook_server:app",
        f"--host={host}",
        f"--port={port}",
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
    parser = argparse.ArgumentParser(description="Khởi động Hệ thống SOC Multi-Agent Live Mode")
    parser.add_argument("--check-only", action="store_true", help="Chỉ kiểm tra cấu hình hệ thống")
    parser.add_argument("--webhook-only", action="store_true", help="Chỉ chạy FastAPI Webhook Receiver")
    parser.add_argument("--ui-only", action="store_true", help="Chỉ chạy Streamlit Dashboard")
    parser.add_argument("--host", default="0.0.0.0", help="Địa chỉ IP lắng nghe (mặc định: 0.0.0.0)")
    parser.add_argument("--port-api", type=int, default=8000, help="Cổng Webhook API (mặc định: 8000)")
    parser.add_argument("--port-ui", type=int, default=8501, help="Cổng Streamlit Dashboard (mặc định: 8501)")

    args = parser.parse_args()

    if args.check_only:
        success = check_system()
        sys.exit(0 if success else 1)

    print("\n" + "=" * 70)
    print("🛡️  KHỞI ĐỘNG HỆ THỐNG SOC MULTI-AGENT (LIVE WAZUH OVA MODE)")
    print("=" * 70)
    print(f"  • Webhook Endpoint:  http://{args.host}:{args.port_api}/api/v1/wazuh-alert")
    print(f"  • Web Dashboard UI:  http://localhost:{args.port_ui}")
    print(f"  • Wazuh OVA Target:  172.16.65.150 -> Host 172.16.65.1:{args.port_api}")
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
