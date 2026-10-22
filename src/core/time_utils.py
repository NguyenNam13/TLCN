# -*- coding: utf-8 -*-
"""
src/core/time_utils.py
Mô-đun tiện ích xử lý và định dạng thời gian chuẩn hóa cho thị trường Việt Nam (ICT, UTC+7).
Đảm bảo:
- Lưu trữ dữ liệu an toàn ở định dạng UTC (hoặc ISO 8601 kèm múi giờ).
- Hiển thị thời gian chính xác theo giờ địa phương Việt Nam (GMT+7) trên Báo cáo, UI Dashboard và Logs.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

# Múi giờ chuẩn Việt Nam (Indochina Time - ICT, UTC+7)
VN_TIMEZONE = timezone(timedelta(hours=7), name="ICT")


def to_vn_time(dt: Optional[datetime]) -> Optional[datetime]:
    """Chuyển đổi một đối tượng datetime sang múi giờ Việt Nam (UTC+7 / ICT).
    
    Nếu dt là naive (không có thông tin tzinfo), mặc định coi là thời gian UTC gốc và gán tzinfo=UTC
    trước khi chuyển sang múi giờ Việt Nam.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(VN_TIMEZONE)


def format_vn_time(
    dt: Optional[datetime],
    fmt: str = "%Y-%m-%d %H:%M:%S (ICT)",
    fallback: str = "N/A"
) -> str:
    """Định dạng thời gian theo múi giờ Việt Nam.
    
    :param dt: Đối tượng datetime cần định dạng.
    :param fmt: Định dạng strftime (mặc định bao gồm ký hiệu múi giờ ICT).
    :param fallback: Giá trị trả về nếu dt là None.
    :return: Chuỗi thời gian đã định dạng.
    """
    if dt is None:
        return fallback
    vn_dt = to_vn_time(dt)
    return vn_dt.strftime(fmt)


def now_utc() -> datetime:
    """Lấy thời gian hiện tại theo chuẩn UTC (cho backend / database)."""
    return datetime.now(timezone.utc)


def now_vn() -> datetime:
    """Lấy thời gian hiện tại theo chuẩn múi giờ Việt Nam (UTC+7)."""
    return datetime.now(VN_TIMEZONE)
