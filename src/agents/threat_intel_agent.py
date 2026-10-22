# -*- coding: utf-8 -*-
"""
src/agents/threat_intel_agent.py
Cyber Threat Intelligence (CTI) Agent phục vụ điều tra sự cố trong Hệ thống Multi-Agent SOC.
Nhiệm vụ:
1. Tiếp nhận các sự kiện đã chuẩn hóa (ParsedEvent) từ IncidentState hoặc pipeline.
2. Trích xuất đa dạng các loại IoC (IP, Domain, URL, Hash) và lọc bỏ trùng lặp, lọc bỏ IP Private RFC 1918.
3. Thực thi tra cứu danh tiếng song song (Parallel CTI Enrichment) qua ThreadPoolExecutor (VirusTotal, AbuseIPDB, Mock CTI).
4. Tính toán Threat Score tổng hợp (0 - 100) và gán nhãn is_malicious nếu điểm >= 50.
5. Ánh xạ các hành vi, tiến trình và IoC sang danh mục kỹ thuật MITRE ATT&CK.
6. Làm giàu IncidentState và sinh đối tượng ThreatIntelEnrichment chuẩn Pydantic v2.
"""

import re
import urllib.parse
import concurrent.futures
from typing import List, Dict, Any, Optional, Set, Tuple

from src.core.schemas import (
    ParsedEvent,
    IoCItem,
    ThreatIntelEnrichment,
)
from src.core.state import IncidentState
from src.agents.prompts import THREAT_INTEL_AGENT_SYSTEM_PROMPT
from src.tools.threat_intel import ThreatIntelTools


class ThreatIntelAgent:
    """
    Threat Intelligence (CTI) Agent.
    Phụ trách làm giàu ngữ cảnh tình báo mối đe dọa không gian mạng cho sự cố.
    """

    # Regex định danh các loại IoC
    IPV4_REGEX = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    URL_REGEX = re.compile(
        r"https?://[^\s\"'<>]+",
        re.IGNORECASE
    )
    # Domain regex với các TLD phổ biến, không khớp file thực thi/extension
    DOMAIN_REGEX = re.compile(
        r"\b(?!(?:[a-zA-Z0-9-]+\.)+(?:exe|dll|ps1|bat|vbs|txt|json|csv|log|bin|tmp|xml|sys|drv|dat|md)\b)"
        r"(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|xyz|top|io|cc|ru|cn|biz|info|vn|edu|gov|de|nl|eu|uk)\b",
        re.IGNORECASE
    )
    HEX_MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
    HEX_SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
    HEX_SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")

    def __init__(
        self,
        system_prompt: Optional[str] = None,
        tools: Optional[Any] = None,
        max_workers: int = 4
    ):
        self.system_prompt = system_prompt or THREAT_INTEL_AGENT_SYSTEM_PROMPT
        self.tools = tools or ThreatIntelTools
        self.max_workers = max_workers
        self.name = "ThreatIntelAgent"

    # =====================================================================
    # 1. TRÍCH XUẤT VÀ LỌC IOC (IOC EXTRACTION & PRIVATE IP FILTERING)
    # =====================================================================
    def is_private_ip(self, ip: str) -> bool:
        """Kiểm tra IP nội bộ RFC 1918 thông qua ThreatIntelTools."""
        return self.tools.is_private_ip(ip)

    def extract_iocs(self, events: List[ParsedEvent]) -> Dict[str, List[str]]:
        """
        Trích xuất toàn bộ các chỉ số IoC từ danh sách ParsedEvent:
        - IPs: Lọc bỏ IP nội bộ RFC 1918 và trùng lặp.
        - Domains: Trích xuất tên miền hợp lệ từ URL, command line và raw attributes.
        - URLs: Trích xuất các liên kết HTTP/HTTPS.
        - Hashes: Trích xuất MD5, SHA1, SHA256 từ file_hash và các trường liên quan.
        """
        ips: Set[str] = set()
        domains: Set[str] = set()
        urls: Set[str] = set()
        hashes: Set[str] = set()

        for evt in events:
            # 1. Trích xuất IPs từ trường có cấu trúc
            for candidate_ip in [evt.source_ip, evt.dest_ip]:
                if candidate_ip and not self.is_private_ip(candidate_ip):
                    ips.add(candidate_ip.strip())

            # 2. Thu thập văn bản tự do để quét regex
            text_corpus = []
            if evt.command_line:
                text_corpus.append(evt.command_line)
            if evt.process_path:
                text_corpus.append(evt.process_path)
            for k, v in evt.raw_attributes.items():
                if isinstance(v, str):
                    text_corpus.append(v)
                elif isinstance(v, (list, tuple)):
                    for item in v:
                        if isinstance(item, str):
                            text_corpus.append(item)

            combined_text = " ".join(text_corpus)

            # Quét IP từ văn bản tự do
            for match in self.IPV4_REGEX.findall(combined_text):
                if not self.is_private_ip(match):
                    ips.add(match.strip())

            # Quét URL từ văn bản tự do
            for raw_url in self.URL_REGEX.findall(combined_text):
                # Làm sạch dấu chấm câu ở cuối URL
                clean_url = raw_url.rstrip(".,;)\"'<>")
                if clean_url:
                    urls.add(clean_url)
                    # Trích xuất luôn domain từ URL
                    try:
                        parsed_u = urllib.parse.urlparse(clean_url)
                        netloc = parsed_u.netloc.split(":")[0].strip().lower()
                        if netloc and not self.is_private_ip(netloc):
                            # Kiểm tra xem netloc có phải IP không
                            if not self.IPV4_REGEX.fullmatch(netloc):
                                domains.add(netloc)
                    except Exception:
                        pass

            # Quét Domain từ văn bản tự do
            for d in self.DOMAIN_REGEX.findall(combined_text):
                clean_d = d.strip().lower()
                # Loại bỏ nếu là local hoặc IP
                if clean_d and not self.IPV4_REGEX.fullmatch(clean_d):
                    domains.add(clean_d)

            # 3. Trích xuất Hashes
            if evt.file_hash:
                raw_hash = str(evt.file_hash).strip()
                # Xử lý trường hợp Sysmon dạng "MD5=...,SHA256=..."
                if "=" in raw_hash:
                    for part in raw_hash.split(","):
                        if "=" in part:
                            _, h_val = part.split("=", 1)
                            h_val = h_val.strip()
                            if len(h_val) in (32, 40, 64):
                                hashes.add(h_val.lower())
                else:
                    if len(raw_hash) in (32, 40, 64):
                        hashes.add(raw_hash.lower())

            # Quét Hashes từ raw_attributes nếu có
            for h_candidate in self.HEX_SHA256_REGEX.findall(combined_text):
                hashes.add(h_candidate.lower())
            for h_candidate in self.HEX_MD5_REGEX.findall(combined_text):
                # Tránh nhầm chuỗi hex ngẫu nhiên ngắn nếu trùng SHA256 substring
                if not any(h_candidate.lower() in long_h for long_h in hashes if len(long_h) > 32):
                    hashes.add(h_candidate.lower())

        return {
            "ips": sorted(list(ips)),
            "domains": sorted(list(domains)),
            "urls": sorted(list(urls)),
            "hashes": sorted(list(hashes)),
        }

    # =====================================================================
    # 2. TRA CỨU SONG SONG (PARALLEL CTI ENRICHMENT)
    # =====================================================================
    def lookup_iocs_parallel(self, iocs: Dict[str, List[str]]) -> List[IoCItem]:
        """
        Tra cứu song song uy tín nhiều IoC đồng thời bằng ThreadPoolExecutor.
        Tối ưu hóa độ trễ phản hồi qua Cache in-memory và I/O song song.
        """
        results: List[IoCItem] = []
        tasks = []

        # Chuẩn bị danh sách task tra cứu
        for ip in iocs.get("ips", []):
            tasks.append(("IP", ip, self.tools.lookup_ip))
        for domain in iocs.get("domains", []):
            tasks.append(("DOMAIN", domain, self.tools.lookup_domain))
        for url in iocs.get("urls", []):
            tasks.append(("URL", url, self.tools.lookup_url))
        for h in iocs.get("hashes", []):
            tasks.append(("HASH", h, self.tools.lookup_hash))

        if not tasks:
            return results

        # Thực thi song song qua ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ioc = {
                executor.submit(func, val): (ioc_type, val)
                for ioc_type, val, func in tasks
            }
            for future in concurrent.futures.as_completed(future_to_ioc):
                ioc_type, val = future_to_ioc[future]
                try:
                    res: IoCItem = future.result()
                    # Chuẩn hóa trạng thái is_malicious theo ngưỡng >= 50
                    if res.reputation_score is not None and res.reputation_score >= 50:
                        res.is_malicious = True
                    results.append(res)
                except Exception as ex:
                    # Trả về fallback IoC nếu gặp sự cố ngoại lệ
                    results.append(
                        IoCItem(
                            ioc_type=ioc_type,
                            value=val,
                            reputation_score=0,
                            is_malicious=False,
                            details={"error": str(ex)}
                        )
                    )

        # Sắp xếp kết quả: IoC độc hại lên đầu, sau đó theo điểm giảm dần
        results.sort(
            key=lambda x: (1 if x.is_malicious else 0, x.reputation_score or 0),
            reverse=True
        )
        return results

    # =====================================================================
    # 3. TÍNH TOÁN THREAT SCORE & ÁNH XẠ MITRE ATT&CK
    # =====================================================================
    def compute_threat_score(self, ioc_items: List[IoCItem]) -> Tuple[int, bool]:
        """
        Tính toán Threat Score tổng hợp (0 - 100) dựa trên các IoC đã tra cứu.
        Gán cờ is_malicious = True nếu threat_score >= 50.
        """
        if not ioc_items:
            return 0, False

        malicious_items = [item for item in ioc_items if item.is_malicious or (item.reputation_score or 0) >= 50]

        if malicious_items:
            # Lấy điểm cao nhất trong số các IoC độc hại
            max_score = max(item.reputation_score or 0 for item in malicious_items)
            # Cộng thêm điểm thưởng nếu phát hiện nhiều IoC độc hại liên đới (+5 điểm mỗi IoC thêm, tối đa +15)
            bonus = min(15, (len(malicious_items) - 1) * 5)
            composite_score = min(100, max_score + bonus)
            return composite_score, True

        # Nếu không có IoC độc hại nào, lấy điểm cao nhất của các IoC bình thường (hoặc 0)
        clean_max = max((item.reputation_score or 0) for item in ioc_items)
        return clean_max, clean_max >= 50

    def extract_mitre_techniques(
        self,
        events: List[ParsedEvent],
        ioc_items: List[IoCItem]
    ) -> List[str]:
        """
        Ánh xạ kỹ thuật MITRE ATT&CK dựa trên các sự kiện và dấu hiệu CTI đã phát hiện.
        """
        techniques: Set[str] = set()

        # 1. Ánh xạ từ các sự kiện log (tiến trình, dòng lệnh, thuộc tính raw)
        for evt in events:
            # Kiểm tra tag MITRE có sẵn từ SIEM (ví dụ Wazuh)
            w_mitre = evt.raw_attributes.get("mitre_ids") or []
            if isinstance(w_mitre, list):
                for m_id in w_mitre:
                    if isinstance(m_id, str) and m_id.startswith("T"):
                        techniques.add(m_id)

            # Ánh xạ qua từ khóa hành vi từ ThreatIntelTools
            text_targets = [
                evt.process_name or "",
                evt.command_line or "",
                evt.parent_process or ""
            ]
            combined = " ".join(text_targets)
            if combined:
                matches = self.tools.match_mitre_technique(combined)
                for m in matches:
                    techniques.add(m["mitre_id"])

        # 2. Ánh xạ từ thông tin CTI của các IoC độc hại
        for ioc in ioc_items:
            if not ioc.is_malicious:
                continue
            cats = ioc.details.get("categories", [])
            actor = (ioc.threat_actor or "").lower()

            for cat in cats:
                cat_lower = str(cat).lower()
                if "c2" in cat_lower or "botnet" in cat_lower or "beacon" in cat_lower:
                    techniques.add("T1071.001")  # Application Layer Protocol: Web Protocols
                if "phishing" in cat_lower:
                    techniques.add("T1566.002")  # Phishing: Spearphishing Link
                if "credential" in cat_lower or "stealer" in cat_lower:
                    techniques.add("T1003.001")  # OS Credential Dumping
                if "ransomware" in cat_lower:
                    techniques.add("T1486")      # Data Encrypted for Impact

            if "cobalt strike" in actor:
                techniques.add("T1071.001")
            if "mimikatz" in actor:
                techniques.add("T1003.001")
            if "redline" in actor:
                techniques.add("T1555")  # Credentials from Password Stores
            if "lazarus" in actor:
                techniques.add("T1059.001")

        return sorted(list(techniques))

    # =====================================================================
    # 4. LÀM GIÀU DỮ LIỆU & TẠO ENRICHMENT OBJECT (ENRICHMENT PIPELINE)
    # =====================================================================
    def enrich_events(self, events: List[ParsedEvent]) -> ThreatIntelEnrichment:
        """
        Tiếp nhận danh sách ParsedEvent và trả về đối tượng ThreatIntelEnrichment chuẩn Pydantic v2.
        """
        # Bước 1: Trích xuất IoCs
        extracted = self.extract_iocs(events)

        # Bước 2: Tra cứu song song uy tín CTI
        ioc_items = self.lookup_iocs_parallel(extracted)

        # Bước 3: Tính toán điểm đe dọa tổng hợp
        threat_score, is_incident_malicious = self.compute_threat_score(ioc_items)

        # Bước 4: Ánh xạ kỹ thuật MITRE ATT&CK
        mitre_techniques = self.extract_mitre_techniques(events, ioc_items)

        # Bước 5: Tổng hợp danh sách nhóm tin tặc (Threat Actors)
        threat_actors: List[str] = []
        for ioc in ioc_items:
            if ioc.is_malicious and ioc.threat_actor:
                if ioc.threat_actor not in threat_actors:
                    threat_actors.append(ioc.threat_actor)

        # Bước 6: Soạn thảo bản tóm tắt tình báo làm giàu
        malicious_count = sum(1 for ioc in ioc_items if ioc.is_malicious)
        total_iocs = len(ioc_items)

        if is_incident_malicious:
            summary = (
                f"Phát hiện {malicious_count}/{total_iocs} IoC độc hại đã xác nhận. "
                f"Threat Score: {threat_score}/100 (Nguy cơ cao). "
                f"Nhóm tấn công liên quan: {', '.join(threat_actors) if threat_actors else 'Chưa xác định'}. "
                f"Ánh xạ {len(mitre_techniques)} kỹ thuật MITRE ATT&CK."
            )
        else:
            summary = (
                f"Đã kiểm tra {total_iocs} IoC (không phát hiện dấu hiệu độc hại bên ngoài). "
                f"Threat Score: {threat_score}/100 (An toàn/Sạch). "
                f"Ánh xạ {len(mitre_techniques)} kỹ thuật MITRE ATT&CK liên quan."
            )

        return ThreatIntelEnrichment(
            extracted_iocs=ioc_items,
            related_threat_actors=threat_actors,
            mitre_techniques=mitre_techniques,
            enrichment_summary=summary
        )

    def enrich_state(self, state: IncidentState) -> IncidentState:
        """
        Tích hợp và cập nhật trực tiếp vào đối tượng IncidentState của LangGraph.
        Lưu vết StateTransition đầy đủ.
        """
        enrichment = self.enrich_events(state.parsed_events)
        state.threat_intel = enrichment

        malicious_count = sum(1 for ioc in enrichment.extracted_iocs if ioc.is_malicious)
        threat_score, is_malicious = self.compute_threat_score(enrichment.extracted_iocs)

        state.record_transition(
            node="ThreatIntelAgent",
            to_status=state.status,
            message=(
                f"Hoàn tất làm giàu Threat Intel: {len(enrichment.extracted_iocs)} IoCs "
                f"({malicious_count} độc hại, Threat Score: {threat_score})"
            ),
            metadata={
                "total_iocs": len(enrichment.extracted_iocs),
                "malicious_iocs": malicious_count,
                "threat_score": threat_score,
                "is_malicious": is_malicious,
                "threat_actors": enrichment.related_threat_actors,
                "mitre_count": len(enrichment.mitre_techniques)
            }
        )
        return state
