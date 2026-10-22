# -*- coding: utf-8 -*-
"""
src/tools/wazuh_stream.py
Công cụ Stream và Batch cảnh báo Wazuh SIEM cho Data Ingestion Agent.
Hỗ trợ:
1. Đọc stream / batch cảnh báo từ file alerts.json (hỗ trợ cả JSON Array và JSON Lines/NDJSON).
2. Xử lý danh sách cảnh báo WazuhAlert hoặc dictionary thô trong bộ nhớ.
3. Bộ lọc cảnh báo linh hoạt theo: rule level (min_level, max_level), groups, agent_id, agent_name, rule_id.
4. Cơ chế Generator / Iterator tiết kiệm bộ nhớ cho tập dữ liệu lớn.
"""

import os
import json
from typing import List, Dict, Any, Optional, Iterator, Union
from src.core.schemas import WazuhAlert
from src.tools.wazuh_client import WazuhClientTool


class WazuhAlertStreamer:
    """
    Trình đọc và truyền dòng (Streaming) cảnh báo Wazuh SIEM.
    Hỗ trợ cả chế độ đọc từng sự kiện (generator) và gom theo lô (batching)
    với bộ lọc linh hoạt.
    """

    def __init__(
        self,
        source: Union[str, List[Union[Dict[str, Any], WazuhAlert]]],
        min_level: Optional[int] = None,
        max_level: Optional[int] = None,
        groups: Optional[List[str]] = None,
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        rule_id: Optional[str] = None,
    ):
        """
        Khởi tạo WazuhAlertStreamer.

        :param source: Đường dẫn tới file alerts.json hoặc danh sách alerts (dict/WazuhAlert).
        :param min_level: Mức độ Rule level tối thiểu để lọc (0-15).
        :param max_level: Mức độ Rule level tối đa để lọc (0-15).
        :param groups: Danh sách nhóm rule cần lọc (ví dụ: ["windows", "sysmon"]).
        :param agent_id: ID của Agent cần lọc.
        :param agent_name: Tên Agent cần lọc (không phân biệt hoa thường).
        :param rule_id: ID của Rule cần lọc.
        """
        self.source = source
        self.min_level = min_level
        self.max_level = max_level
        self.groups = [g.lower() for g in groups] if groups else None
        self.agent_id = str(agent_id) if agent_id is not None else None
        self.agent_name = agent_name.lower() if agent_name else None
        self.rule_id = str(rule_id) if rule_id is not None else None

    @classmethod
    def from_file(cls, file_path: str, **kwargs) -> "WazuhAlertStreamer":
        """Khởi tạo nhanh streamer từ đường dẫn tệp tin."""
        return cls(source=file_path, **kwargs)

    @classmethod
    def from_list(
        cls, alerts: List[Union[Dict[str, Any], WazuhAlert]], **kwargs
    ) -> "WazuhAlertStreamer":
        """Khởi tạo nhanh streamer từ danh sách alert trong bộ nhớ."""
        return cls(source=alerts, **kwargs)

    def matches_filter(self, alert: WazuhAlert) -> bool:
        """
        Kiểm tra cảnh báo có thỏa mãn các tiêu chí lọc hay không.

        :param alert: Đối tượng WazuhAlert cần kiểm tra.
        :return: True nếu thỏa mãn tất cả tiêu chí lọc đã chỉ định, ngược lại False.
        """
        # 1. Lọc theo rule level
        if self.min_level is not None and alert.rule.level < self.min_level:
            return False
        if self.max_level is not None and alert.rule.level > self.max_level:
            return False

        # 2. Lọc theo rule id
        if self.rule_id is not None and str(alert.rule.id) != self.rule_id:
            return False

        # 3. Lọc theo groups
        if self.groups is not None:
            alert_groups = [g.lower() for g in alert.rule.groups]
            if not any(target_group in alert_groups for target_group in self.groups):
                return False

        # 4. Lọc theo agent id
        if self.agent_id is not None and str(alert.agent.id) != self.agent_id:
            return False

        # 5. Lọc theo agent name
        if self.agent_name is not None:
            if not alert.agent.name or alert.agent.name.lower() != self.agent_name:
                return False

        return True

    def _normalize_alert(self, item: Union[Dict[str, Any], WazuhAlert]) -> WazuhAlert:
        """Chuẩn hóa dictionary hoặc đối tượng có sẵn thành WazuhAlert."""
        if isinstance(item, WazuhAlert):
            return item
        elif isinstance(item, dict):
            return WazuhClientTool.parse_alert_dict(item)
        raise ValueError(f"Không thể chuyển đổi kiểu dữ liệu {type(item)} thành WazuhAlert.")

    def stream_alerts(self) -> Iterator[WazuhAlert]:
        """
        Generator truyền từng cảnh báo thỏa mãn bộ lọc.
        Tiết kiệm RAM khi đọc tệp log lớn từ Wazuh Manager.
        """
        if isinstance(self.source, str):
            file_path = self.source
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"Tệp cảnh báo không tồn tại: {file_path}")

            with open(file_path, "r", encoding="utf-8") as f:
                first_char = f.read(1).strip()
                f.seek(0)

                # Trường hợp 1: File JSON Array (bắt đầu bằng '[')
                if first_char == "[":
                    items = json.load(f)
                    for raw_item in items:
                        if isinstance(raw_item, dict):
                            alert = self._normalize_alert(raw_item)
                            if self.matches_filter(alert):
                                yield alert
                # Trường hợp 2: File JSON Lines / NDJSON (mỗi dòng 1 JSON object)
                else:
                    for line in f:
                        line_str = line.strip()
                        if line_str:
                            try:
                                raw_item = json.loads(line_str)
                                if isinstance(raw_item, dict):
                                    alert = self._normalize_alert(raw_item)
                                    if self.matches_filter(alert):
                                        yield alert
                            except json.JSONDecodeError:
                                continue
        elif isinstance(self.source, (list, tuple)):
            for item in self.source:
                alert = self._normalize_alert(item)
                if self.matches_filter(alert):
                    yield alert
        else:
            raise TypeError(f"Kiểu nguồn dữ liệu không hợp lệ: {type(self.source)}")

    def batch_alerts(self, batch_size: int = 10) -> Iterator[List[WazuhAlert]]:
        """
        Gom cảnh báo thành các lô (batch) có kích thước cố định.
        Hữu ích khi xử lý dữ liệu lớn bằng Multi-threading hoặc LLM inference theo nhóm.

        :param batch_size: Số lượng cảnh báo tối đa trong 1 batch (mặc định: 10).
        :return: Generator trả về danh sách List[WazuhAlert].
        """
        if batch_size <= 0:
            raise ValueError("batch_size phải lớn hơn 0.")

        current_batch: List[WazuhAlert] = []
        for alert in self.stream_alerts():
            current_batch.append(alert)
            if len(current_batch) >= batch_size:
                yield current_batch
                current_batch = []

        if current_batch:
            yield current_batch

    def get_all_alerts(self) -> List[WazuhAlert]:
        """Đọc và trả về toàn bộ danh sách cảnh báo thỏa mãn bộ lọc."""
        return list(self.stream_alerts())

    def count(self) -> int:
        """Đếm số lượng cảnh báo thỏa mãn bộ lọc."""
        count = 0
        for _ in self.stream_alerts():
            count += 1
        return count
