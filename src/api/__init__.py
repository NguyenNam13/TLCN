# -*- coding: utf-8 -*-
"""
src/api
Gói cung cấp các API endpoints và Webhook Receiver cho hệ thống SOC.
"""

from src.api.webhook_server import app, create_app

__all__ = ["app", "create_app"]
