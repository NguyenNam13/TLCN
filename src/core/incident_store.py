# -*- coding: utf-8 -*-
"""
src/core/incident_store.py
Quản lý lưu trữ trạng thái sự cố (Incident Persistence Store) cho hệ thống SOC.
Hỗ trợ:
1. Lưu và tải đối tượng IncidentState thành file JSON cấu trúc.
2. Liệt kê danh sách sự cố mới nhất xếp theo thời gian (giảm dần).
3. Cơ chế khử trùng lặp cảnh báo (Deduplication) dựa trên cửa sổ trượt (Sliding Time Window).
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Tuple
from src.core.state import IncidentState

logger = logging.getLogger("IncidentStore")


class IncidentStore:
    """Quản lý lưu trữ bền vững trạng thái IncidentState."""

    def __init__(self, storage_dir: Optional[str] = None):
        """
        Khởi tạo IncidentStore.
        
        :param storage_dir: Đường dẫn thư mục lưu trữ file incidents.
        """
        if storage_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            storage_dir = os.path.join(base_dir, "data", "incidents")
        
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

        # Bộ nhớ đệm khử trùng lặp: (rule_id, agent_id) -> timestamp
        self._dedup_cache: Dict[Tuple[str, str], datetime] = {}

    def _get_file_path(self, incident_id: str) -> str:
        """Lấy đường dẫn tệp tin tương ứng với incident_id."""
        # Chuẩn hóa tên file an toàn
        safe_id = "".join(c for c in incident_id if c.isalnum() or c in ("-", "_"))
        return os.path.join(self.storage_dir, f"{safe_id}.json")

    def save_incident(self, state: IncidentState) -> str:
        """
        Lưu đối tượng IncidentState thành tệp JSON.
        
        :param state: Đối tượng IncidentState cần lưu.
        :return: Đường dẫn tệp tin đã lưu.
        """
        file_path = self._get_file_path(state.incident_id)
        try:
            json_str = state.model_dump_json(indent=2)
            # Ghi ra file tạm rồi atomic rename
            temp_path = f"{file_path}.tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(json_str)
            os.replace(temp_path, file_path)
            logger.debug(f"Đã lưu IncidentState: {state.incident_id} tại {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Lỗi khi lưu IncidentState {state.incident_id}: {e}", exc_info=True)
            raise

    def get_incident(self, incident_id: str) -> Optional[IncidentState]:
        """
        Tải đối tượng IncidentState theo ID.
        
        :param incident_id: ID sự cố cần đọc.
        :return: Đối tượng IncidentState hoặc None nếu không tìm thấy.
        """
        file_path = self._get_file_path(incident_id)
        if not os.path.exists(file_path):
            return None

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            return IncidentState.model_validate_json(content)
        except Exception as e:
            logger.error(f"Lỗi khi nạp IncidentState {incident_id} từ {file_path}: {e}", exc_info=True)
            return None

    def list_incidents(self, limit: int = 50) -> List[IncidentState]:
        """
        Liệt kê danh sách các sự cố được lưu trữ, sắp xếp theo thời gian tạo giảm dần.
        
        :param limit: Số lượng sự cố tối đa cần lấy.
        :return: Danh sách đối tượng IncidentState.
        """
        incidents: List[IncidentState] = []
        if not os.path.exists(self.storage_dir):
            return incidents

        json_files = [
            f for f in os.listdir(self.storage_dir) 
            if f.endswith(".json") and not f.endswith(".tmp")
        ]

        for fname in json_files:
            fpath = os.path.join(self.storage_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = f.read()
                inc = IncidentState.model_validate_json(data)
                incidents.append(inc)
            except Exception as e:
                logger.warning(f"Bỏ qua file hỏng {fpath}: {e}")

        # Sắp xếp theo created_at giảm dần (sự cố mới nhất lên đầu)
        incidents.sort(key=lambda x: x.created_at, reverse=True)
        return incidents[:limit]

    def delete_incident(self, incident_id: str) -> bool:
        """Xóa sự cố khỏi bộ lưu trữ."""
        file_path = self._get_file_path(incident_id)
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        return False

    def clear(self):
        """Xóa toàn bộ các tệp tin lưu trữ (chỉ dùng cho testing/cleanup)."""
        if os.path.exists(self.storage_dir):
            for fname in os.listdir(self.storage_dir):
                if fname.endswith(".json") or fname.endswith(".tmp"):
                    try:
                        os.remove(os.path.join(self.storage_dir, fname))
                    except Exception:
                        pass
        self._dedup_cache.clear()

    def is_duplicate_alert(self, rule_id: str, agent_id: str, window_seconds: int = 60) -> bool:
        """
        Kiểm tra cảnh báo có phải là trùng lặp trong cửa sổ trượt (Time-window) hay không.
        
        :param rule_id: Mã luật Wazuh.
        :param agent_id: ID máy trạm gửi log.
        :param window_seconds: Độ dài cửa sổ trượt (giây).
        :return: True nếu cảnh báo lặp lại trong window_seconds, False nếu là cảnh báo mới.
        """
        now = datetime.now(timezone.utc)
        key = (str(rule_id), str(agent_id))

        # Dọn dẹp cache cũ quá 1 giờ
        cutoff = now - timedelta(hours=1)
        self._dedup_cache = {
            k: ts for k, ts in self._dedup_cache.items() if ts >= cutoff
        }

        last_seen = self._dedup_cache.get(key)
        if last_seen and (now - last_seen).total_seconds() < window_seconds:
            return True

        self._dedup_cache[key] = now
        return False
