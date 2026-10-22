# -*- coding: utf-8 -*-
"""
src/tools/dataset_validator.py
Bộ công cụ thẩm định tính toàn vẹn và chuẩn hóa của Dataset Wazuh SIEM.
Sử dụng Pydantic v2 (WazuhAlert) để kiểm tra Schema, phát hiện thiếu trường dữ liệu,
và đo lường độ bao phủ khung kỹ thuật MITRE ATT&CK.
"""

import os
import sys
import glob
import json
from typing import Dict, List, Any, Optional, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from pydantic import ValidationError
from src.core.schemas import WazuhAlert, SeverityLevel
from src.tools.wazuh_client import WazuhClientTool


class DatasetValidator:
    """Công cụ kiểm thử và thẩm định bộ Dataset cảnh báo Wazuh."""

    @staticmethod
    def validate_alert_dict(alert_dict: Dict[str, Any]) -> Tuple[bool, Optional[WazuhAlert], List[str]]:
        """
        Kiểm tra 1 bản ghi cảnh báo với schema Pydantic v2 WazuhAlert.
        Trả về: (is_valid, alert_obj, error_messages)
        """
        errors = []
        try:
            alert_obj = WazuhAlert.model_validate(alert_dict)
            return True, alert_obj, []
        except ValidationError as e:
            for err in e.errors():
                loc = " -> ".join(str(x) for x in err.get("loc", []))
                msg = f"Field '{loc}': {err.get('msg')} (type: {err.get('type')})"
                errors.append(msg)
            return False, None, errors
        except Exception as ex:
            return False, None, [f"Unexpected error: {str(ex)}"]

    @classmethod
    def validate_file(cls, file_path: str) -> Dict[str, Any]:
        """
        Đọc và thẩm định toàn bộ các bản ghi cảnh báo trong 1 file JSON.
        """
        result: Dict[str, Any] = {
            "file_path": file_path,
            "filename": os.path.basename(file_path),
            "is_valid": True,
            "total_alerts": 0,
            "valid_alerts": 0,
            "alerts": [],
            "errors": []
        }

        if not os.path.exists(file_path):
            result["is_valid"] = False
            result["errors"].append(f"Tệp không tồn tại: {file_path}")
            return result

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    result["is_valid"] = False
                    result["errors"].append("Tệp rỗng không có dữ liệu.")
                    return result
                raw_data = json.loads(content)
        except json.JSONDecodeError as jde:
            result["is_valid"] = False
            result["errors"].append(f"Lỗi định dạng JSON: {str(jde)}")
            return result
        except Exception as e:
            result["is_valid"] = False
            result["errors"].append(f"Không thể đọc tệp: {str(e)}")
            return result

        if isinstance(raw_data, dict):
            raw_items = [raw_data]
        elif isinstance(raw_data, list):
            raw_items = raw_data
        else:
            result["is_valid"] = False
            result["errors"].append("Cấu trúc JSON gốc phải là Object hoặc Array.")
            return result

        result["total_alerts"] = len(raw_items)

        for idx, item in enumerate(raw_items):
            if not isinstance(item, dict):
                result["is_valid"] = False
                result["errors"].append(f"Bản ghi #{idx} không phải là dictionary hợp lệ.")
                continue

            is_valid, alert_obj, err_msgs = cls.validate_alert_dict(item)
            if is_valid and alert_obj:
                result["valid_alerts"] += 1
                result["alerts"].append(alert_obj)
            else:
                result["is_valid"] = False
                for em in err_msgs:
                    result["errors"].append(f"Alert #{idx} (ID: {item.get('id', 'N/A')}): {em}")

        return result

    @classmethod
    def validate_directory(cls, dir_path: str) -> Dict[str, Any]:
        """
        Quét và kiểm tra toàn bộ các file JSON cảnh báo trong một thư mục.
        """
        summary: Dict[str, Any] = {
            "directory": dir_path,
            "total_files": 0,
            "valid_files": 0,
            "total_alerts": 0,
            "valid_alerts": 0,
            "is_all_valid": True,
            "files": [],
            "all_alerts": [],
            "errors": []
        }

        pattern = os.path.join(dir_path, "*.json")
        file_list = sorted(glob.glob(pattern))
        summary["total_files"] = len(file_list)

        for fpath in file_list:
            f_res = cls.validate_file(fpath)
            summary["files"].append(f_res)
            summary["total_alerts"] += f_res["total_alerts"]
            summary["valid_alerts"] += f_res["valid_alerts"]
            summary["all_alerts"].extend(f_res["alerts"])

            if f_res["is_valid"]:
                summary["valid_files"] += 1
            else:
                summary["is_all_valid"] = False
                for err in f_res["errors"]:
                    summary["errors"].append(f"[{os.path.basename(fpath)}] {err}")

        if summary["total_files"] == 0:
            summary["is_all_valid"] = False
            summary["errors"].append(f"Không tìm thấy file JSON nào trong: {dir_path}")

        return summary

    @staticmethod
    def get_mitre_coverage(alerts: List[WazuhAlert]) -> Dict[str, Any]:
        """
        Trích xuất và tổng hợp thống kê mức độ bao phủ khung MITRE ATT&CK từ danh sách cảnh báo.
        """
        unique_tactics = set()
        unique_techniques = set()
        unique_technique_ids = set()
        tactic_technique_map: Dict[str, List[str]] = {}

        for alert in alerts:
            rule = alert.rule
            if rule.mitre:
                for tac in rule.mitre.tactic:
                    unique_tactics.add(tac)
                    if tac not in tactic_technique_map:
                        tactic_technique_map[tac] = []

                for tid in rule.mitre.id:
                    unique_technique_ids.add(tid)

                for tech in rule.mitre.technique:
                    unique_techniques.add(tech)

                # Ánh xạ Tactic -> Technique ID
                for tac in rule.mitre.tactic:
                    for tid in rule.mitre.id:
                        if tid not in tactic_technique_map[tac]:
                            tactic_technique_map[tac].append(tid)

        return {
            "total_tactics": len(unique_tactics),
            "tactics": sorted(list(unique_tactics)),
            "total_techniques": len(unique_techniques),
            "techniques": sorted(list(unique_techniques)),
            "total_technique_ids": len(unique_technique_ids),
            "technique_ids": sorted(list(unique_technique_ids)),
            "tactic_technique_map": tactic_technique_map
        }

    @staticmethod
    def get_severity_distribution(alerts: List[WazuhAlert]) -> Dict[str, int]:
        """
        Thống kê phân bổ mức độ nghiêm trọng (Severity Level) và Rule Level.
        """
        distribution = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        for alert in alerts:
            sev = WazuhClientTool.map_rule_level_to_severity(alert.rule.level)
            distribution[sev.value] += 1
        return distribution


if __name__ == "__main__":
    wazuh_dir = os.path.join(os.path.dirname(__file__), "..", "..", "data", "raw", "wazuh")
    res = DatasetValidator.validate_directory(wazuh_dir)

    print("\n" + "=" * 70)
    print(" KẾT QUẢ THẨM ĐỊNH DATASET WAZUH SIEM (DATASET VALIDATION REPORT)")
    print("=" * 70)
    print(f"Thư mục thẩm định       : {res['directory']}")
    print(f"Tổng số tệp JSON        : {res['total_files']} (Hợp lệ: {res['valid_files']})")
    print(f"Tổng số cảnh báo        : {res['total_alerts']} (Hợp lệ 100%: {res['valid_alerts']})")
    print(f"Trạng thái Schema       : {'ĐẠT CHUẨN (VALID)' if res['is_all_valid'] else 'KHÔNG ĐẠT (INVALID)'}")
    print("-" * 70)

    for f_info in res["files"]:
        status = "PASSED" if f_info["is_valid"] else "FAILED"
        print(f" -> {f_info['filename']:<42} : {f_info['valid_alerts']}/{f_info['total_alerts']} alerts [{status}]")

    print("-" * 70)
    mitre_cov = DatasetValidator.get_mitre_coverage(res["all_alerts"])
    print(f"Độ bao phủ MITRE ATT&CK : {mitre_cov['total_tactics']} Tactics | {mitre_cov['total_technique_ids']} Techniques (TIDs)")
    print(f"Danh sách Tactics       : {', '.join(mitre_cov['tactics'])}")
    print(f"Danh sách Technique IDs : {', '.join(mitre_cov['technique_ids'])}")

    sev_dist = DatasetValidator.get_severity_distribution(res["all_alerts"])
    print("-" * 70)
    print("Phân bổ mức độ nghiêm trọng (Severity):")
    for s_name, s_count in sev_dist.items():
        print(f"  * {s_name:<10}: {s_count} alerts")
    print("=" * 70 + "\n")
