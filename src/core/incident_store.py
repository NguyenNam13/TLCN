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
import logging
import tempfile
import threading
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

        # Khóa an toàn luồng cho các thao tác I/O và cache
        self._lock = threading.Lock()

        # Bộ nhớ đệm khử trùng lặp: (rule_id, agent_id, src_ip, user, extra) -> timestamp
        self._dedup_cache: Dict[Tuple[str, str, str, str, str], datetime] = {}

        # In-Memory Cache lưu trữ (mtime, IncidentState) giảm 99% Disk I/O
        self._state_cache: Dict[str, Tuple[float, IncidentState]] = {}

    def _get_file_path(self, incident_id: str) -> str:
        """Lấy đường dẫn tệp tin tương ứng với incident_id."""
        # Chuẩn hóa tên file an toàn
        safe_id = "".join(c for c in incident_id if c.isalnum() or c in ("-", "_"))
        return os.path.join(self.storage_dir, f"{safe_id}.json")

    def save_incident(self, state: IncidentState) -> str:
        """
        Lưu đối tượng IncidentState thành tệp JSON và cập nhật In-Memory Cache.
        
        :param state: Đối tượng IncidentState cần lưu.
        :return: Đường dẫn tệp tin đã lưu.
        """
        file_path = self._get_file_path(state.incident_id)
        try:
            json_str = state.model_dump_json(indent=2)
            # Ghi ra file tạm ngẫu nhiên trong thư mục đích tránh race condition rồi atomic rename
            with self._lock:
                with tempfile.NamedTemporaryFile("w", dir=self.storage_dir, delete=False, encoding="utf-8") as tf:
                    tf.write(json_str)
                    temp_name = tf.name
                os.replace(temp_name, file_path)
                mtime = os.path.getmtime(file_path)
                self._state_cache[file_path] = (mtime, state)
            logger.debug(f"Đã lưu IncidentState: {state.incident_id} tại {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Lỗi khi lưu IncidentState {state.incident_id}: {e}", exc_info=True)
            raise

    def get_incident(self, incident_id: str) -> Optional[IncidentState]:
        """
        Tải đối tượng IncidentState theo ID (tận dụng In-Memory Cache).
        
        :param incident_id: ID sự cố cần đọc.
        :return: Đối tượng IncidentState hoặc None nếu không tìm thấy.
        """
        file_path = self._get_file_path(incident_id)
        if not os.path.exists(file_path):
            return None

        try:
            with self._lock:
                mtime = os.path.getmtime(file_path)
                if file_path in self._state_cache:
                    cached_mtime, cached_state = self._state_cache[file_path]
                    if cached_mtime == mtime:
                        return cached_state

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            state = IncidentState.model_validate_json(content)
            with self._lock:
                self._state_cache[file_path] = (mtime, state)
            return state
        except Exception as e:
            logger.error(f"Lỗi khi nạp IncidentState {incident_id} từ {file_path}: {e}", exc_info=True)
            return None

    def list_incidents(self, limit: int = 50) -> List[IncidentState]:
        """
        Liệt kê danh sách các sự cố tối ưu hóa cao:
        1. Sử dụng os.scandir() đọc mtime mà không cần mở toàn bộ file.
        2. Tận dụng In-Memory Cache dựa trên st_mtime.
        3. Tự động bỏ qua các file hỏng mà không làm sập luồng.
        
        :param limit: Số lượng sự cố tối đa cần lấy.
        :return: Danh sách đối tượng IncidentState.
        """
        if not os.path.exists(self.storage_dir):
            return []

        with self._lock:
            file_entries = []
            try:
                with os.scandir(self.storage_dir) as it:
                    for entry in it:
                        if entry.is_file() and entry.name.endswith(".json") and not entry.name.endswith(".tmp"):
                            try:
                                file_entries.append((entry.path, entry.stat().st_mtime))
                            except OSError:
                                continue
            except Exception as e:
                logger.warning(f"Lỗi quét thư mục incidents: {e}")
                return []

            if not file_entries:
                return []

            # Sắp xếp sơ bộ theo mtime mới nhất
            file_entries.sort(key=lambda x: x[1], reverse=True)

            incidents: List[IncidentState] = []
            active_paths = set()

            for fpath, mtime in file_entries:
                active_paths.add(fpath)
                inc: Optional[IncidentState] = None

                # Cache Hit
                if fpath in self._state_cache:
                    cached_mtime, cached_inc = self._state_cache[fpath]
                    if cached_mtime == mtime:
                        inc = cached_inc

                # Cache Miss: Chỉ mở và parse tệp mới hoặc đã thay đổi
                if inc is None:
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            data = f.read()
                        inc = IncidentState.model_validate_json(data)
                        self._state_cache[fpath] = (mtime, inc)
                    except Exception as e:
                        logger.warning(f"Bỏ qua file không hợp lệ {fpath}: {e}")
                        continue

                incidents.append(inc)

            # Xóa các key cache của các tệp đã bị xóa khỏi đĩa
            stale_keys = [k for k in self._state_cache.keys() if k not in active_paths]
            for k in stale_keys:
                self._state_cache.pop(k, None)

            # Sắp xếp theo created_at giảm dần (sự cố mới nhất lên đầu)
            incidents.sort(key=lambda x: x.created_at, reverse=True)
            return incidents[:limit]

    def delete_incident(self, incident_id: str) -> bool:
        """Xóa sự cố khỏi bộ lưu trữ và dọn dẹp cache."""
        file_path = self._get_file_path(incident_id)
        with self._lock:
            self._state_cache.pop(file_path, None)
            if os.path.exists(file_path):
                os.remove(file_path)
                return True
        return False

    def clear(self):
        """Xóa toàn bộ các tệp tin lưu trữ và cache (chỉ dùng cho testing/cleanup)."""
        with self._lock:
            self._state_cache.clear()
            self._dedup_cache.clear()
            if os.path.exists(self.storage_dir):
                for fname in os.listdir(self.storage_dir):
                    if fname.endswith(".json") or fname.endswith(".tmp"):
                        try:
                            os.remove(os.path.join(self.storage_dir, fname))
                        except Exception:
                            pass

    def is_duplicate_alert(
        self,
        rule_id: str,
        agent_id: str,
        window_seconds: int = 60,
        src_ip: Optional[str] = None,
        user: Optional[str] = None,
        extra_context: Optional[str] = None,
    ) -> bool:
        """
        Kiểm tra cảnh báo có phải là trùng lặp trong cửa sổ trượt (Time-window) hay không.
        
        :param rule_id: Mã luật Wazuh.
        :param agent_id: ID máy trạm gửi log.
        :param window_seconds: Độ dài cửa sổ trượt (giây).
        :param src_ip: IP nguồn của kẻ tấn công (nếu có, giúp phân biệt các đợt tấn công từ IP khác nhau).
        :param user: Tên tài khoản liên quan (nếu có).
        :param extra_context: Ngữ cảnh phụ trợ (tên tệp, tiến trình, ...).
        :return: True nếu cảnh báo lặp lại trong window_seconds, False nếu là cảnh báo mới.
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            # Khóa băm ngữ cảnh: hỗ trợ đầy đủ src_ip và user trong khi vẫn tương thích ngược 100%
            key = (str(rule_id), str(agent_id), str(src_ip or ""), str(user or ""), str(extra_context or ""))

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
