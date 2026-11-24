# -*- coding: utf-8 -*-
"""
tests/test_dataset_coverage.py
Unit tests thẩm định toàn bộ bộ Dataset Wazuh SIEM trong data/raw/wazuh/.
Kiểm tra tính hợp lệ của Schema Pydantic v2, chuỗi đa bước của các kịch bản sự cố,
đặc tính của kịch bản Benign (False Positive) và độ bao phủ ma trận MITRE ATT&CK.
"""

import os
import unittest
from typing import List

from src.core.schemas import WazuhAlert, SeverityLevel
from src.tools.dataset_validator import DatasetValidator
from src.tools.wazuh_client import WazuhClientTool


class TestDatasetCoverage(unittest.TestCase):
    """Kiểm tra độ bao phủ và tính chuẩn hóa của Dataset Wazuh."""

    @classmethod
    def setUpClass(cls):
        cls.data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "raw", "wazuh"))
        cls.validation_summary = DatasetValidator.validate_directory(cls.data_dir)
        cls.all_alerts = cls.validation_summary["all_alerts"]

    def test_all_wazuh_datasets_valid(self):
        """Khẳng định 100% các tệp dataset JSON trong thư mục đều hợp lệ theo Pydantic schema."""
        self.assertTrue(
            self.validation_summary["is_all_valid"],
            f"Phát hiện lỗi trong dataset: {self.validation_summary.get('errors')}"
        )
        self.assertEqual(self.validation_summary["total_files"], 4, "Cần có đủ 4 file kịch bản sự cố.")
        self.assertEqual(
            self.validation_summary["valid_files"],
            4,
            "Cả 4 file kịch bản phải hoàn toàn hợp lệ."
        )
        self.assertGreaterEqual(
            self.validation_summary["total_alerts"],
            10,
            "Tổng số alert trên 4 kịch bản phải đạt ít nhất 10 cảnh báo."
        )
        self.assertEqual(
            self.validation_summary["valid_alerts"],
            self.validation_summary["total_alerts"],
            "100% cảnh báo phải khớp định dạng WazuhAlert."
        )

    def test_scenario1_phishing_multistage(self):
        """Kiểm tra chuỗi đa bước của Kịch bản 1: Phishing Credential Access."""
        fpath = os.path.join(self.data_dir, "wazuh_alerts_scenario1_phishing.json")
        res = DatasetValidator.validate_file(fpath)
        self.assertTrue(res["is_valid"])
        alerts: List[WazuhAlert] = res["alerts"]
        self.assertEqual(len(alerts), 3, "Kịch bản 1 phải gồm 3 bước tuần tự.")

        # Bước 1: Failed logon / Spray
        self.assertEqual(alerts[0].rule.id, "60105")
        self.assertEqual(alerts[0].rule.level, 5)
        self.assertIn("T1110.003", alerts[0].rule.mitre.id)

        # Bước 2: External Logon Success
        self.assertEqual(alerts[1].rule.id, "60106")
        self.assertEqual(alerts[1].rule.level, 10)
        self.assertIn("T1078.002", alerts[1].rule.mitre.id)
        self.assertEqual(alerts[1].data["win"]["eventdata"]["ipAddress"], "185.220.101.5")

        # Bước 3: Privilege / Account Discovery
        self.assertEqual(alerts[2].rule.id, "60115")
        self.assertEqual(alerts[2].rule.level, 8)
        self.assertIn("Discovery", alerts[2].rule.mitre.tactic)

    def test_scenario2_malware_multistage(self):
        """Kiểm tra chuỗi đa bước của Kịch bản 2: Endpoint Malware (Sysmon Process & C2)."""
        fpath = os.path.join(self.data_dir, "wazuh_alerts_scenario2_malware.json")
        res = DatasetValidator.validate_file(fpath)
        self.assertTrue(res["is_valid"])
        alerts: List[WazuhAlert] = res["alerts"]
        self.assertEqual(len(alerts), 4, "Kịch bản 2 phải gồm 4 bước TTPs hoàn chỉnh.")

        # Giai đoạn 1: Process Creation (PowerShell mã hóa)
        self.assertEqual(alerts[0].rule.id, "92211")
        self.assertEqual(alerts[0].rule.level, 12)
        self.assertIn("sysmon", alerts[0].rule.groups)
        self.assertIn("T1059.001", alerts[0].rule.mitre.id)

        # Giai đoạn 2: Dropper File Creation (Event 11)
        self.assertEqual(alerts[1].rule.id, "92215")
        self.assertEqual(alerts[1].data["win"]["system"]["eventID"], "11")
        self.assertIn("Temp", alerts[1].data["win"]["eventdata"]["targetFilename"])

        # Giai đoạn 3: Network Connection (Event 3 / C2 Beaconing)
        self.assertEqual(alerts[2].rule.id, "92213")
        self.assertEqual(alerts[2].data["win"]["system"]["eventID"], "3")
        self.assertEqual(alerts[2].data["win"]["eventdata"]["destinationIp"], "194.26.29.112")
        self.assertEqual(alerts[2].data["win"]["eventdata"]["destinationPort"], "443")

        # Giai đoạn 4: Persistence Scheduled Task
        self.assertEqual(alerts[3].rule.id, "92218")
        self.assertIn("T1053.005", alerts[3].rule.mitre.id)

    def test_scenario3_network_scan_multistage(self):
        """Kiểm tra chuỗi đa bước của Kịch bản 3: Network Reconnaissance."""
        fpath = os.path.join(self.data_dir, "wazuh_alerts_scenario3_network_scan.json")
        res = DatasetValidator.validate_file(fpath)
        self.assertTrue(res["is_valid"])
        alerts: List[WazuhAlert] = res["alerts"]
        self.assertEqual(len(alerts), 3, "Kịch bản 3 phải gồm 3 bước trinh sát mạng.")

        rule_ids = [a.rule.id for a in alerts]
        self.assertIn("5712", rule_ids, "Phải có cảnh báo ICMP Sweep (5712)")
        self.assertIn("5710", rule_ids, "Phải có cảnh báo SYN Port Scan (5710)")
        self.assertIn("5715", rule_ids, "Phải có cảnh báo Banner Grabbing (5715)")

    def test_scenario4_benign_false_positive(self):
        """Kiểm tra Kịch bản 4: Đăng nhập bình thường trong giờ hành chính (Benign / Level 3)."""
        fpath = os.path.join(self.data_dir, "wazuh_alerts_scenario4_benign.json")
        res = DatasetValidator.validate_file(fpath)
        self.assertTrue(res["is_valid"])
        alerts: List[WazuhAlert] = res["alerts"]
        self.assertEqual(len(alerts), 1, "Kịch bản 4 gồm 1 alert mẫu cho đăng nhập chuẩn.")

        benign = alerts[0]
        self.assertEqual(benign.rule.id, "60100")
        self.assertEqual(benign.rule.level, 3, "Benign alert phải có rule level 3.")
        self.assertEqual(
            WazuhClientTool.map_rule_level_to_severity(benign.rule.level),
            SeverityLevel.LOW,
            "Rule level 3 phải được quy đổi thành SeverityLevel.LOW."
        )
        self.assertEqual(benign.data["win"]["eventdata"]["logonType"], "2", "Logon type 2 là interactive login thông thường.")
        self.assertEqual(benign.data["win"]["eventdata"]["targetUserName"], "truongdo")

    def test_mitre_coverage_report(self):
        """Báo cáo và kiểm tra độ bao phủ khung MITRE ATT&CK trên toàn bộ dataset."""
        mitre_data = DatasetValidator.get_mitre_coverage(self.all_alerts)
        
        # Kiểm tra số lượng tối thiểu các Tactics và Techniques
        self.assertGreaterEqual(mitre_data["total_tactics"], 7, "Dataset phải bao phủ ít nhất 7 MITRE Tactics.")
        self.assertGreaterEqual(mitre_data["total_technique_ids"], 8, "Dataset phải bao phủ ít nhất 8 Technique IDs.")

        # Khẳng định sự hiện diện của các Tactics nòng cốt
        core_tactics = [
            "Initial Access",
            "Execution",
            "Defense Evasion",
            "Discovery",
            "Command and Control",
            "Credential Access",
            "Persistence"
        ]
        for ct in core_tactics:
            self.assertIn(ct, mitre_data["tactics"], f"Tactic '{ct}' phải xuất hiện trong dataset.")

        # In báo cáo phục vụ logging test
        print(f"\n[MITRE COVERAGE TEST REPORT]")
        print(f" -> Tổng số Tactics bao phủ: {mitre_data['total_tactics']}")
        print(f" -> Danh sách Tactics: {', '.join(mitre_data['tactics'])}")
        print(f" -> Tổng số Technique IDs  : {mitre_data['total_technique_ids']}")
        print(f" -> Danh sách Technique IDs: {', '.join(mitre_data['technique_ids'])}")


if __name__ == "__main__":
    unittest.main()
