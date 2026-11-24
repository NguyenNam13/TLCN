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
import ipaddress
import logging
import urllib.parse
import concurrent.futures
from typing import List, Dict, Any, Optional, Set, Tuple

from src.core.schemas import (
    ParsedEvent,
    IoCItem,
    ThreatIntelEnrichment,
    ThreatIntelLLMAnalysis,
)
from src.core.state import IncidentState
from src.core.security_guard import (
    UNTRUSTED_LOG_SECURITY_HEADER,
    inspect_and_wrap_untrusted,
    sanitize_prompt_text,
    wrap_untrusted_log,
)
from src.agents.prompts import THREAT_INTEL_AGENT_SYSTEM_PROMPT
from src.agents.llm_utils import invoke_structured_llm
from src.tools.threat_intel import ThreatIntelTools

logger = logging.getLogger("ThreatIntelAgent")

_MITRE_CODE_REGEX = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
_STRICT_MITRE_ID_REGEX = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_EXPLICIT_MD5_REGEX = re.compile(
    r"(?:md5|imphash|file_hash|hash)\s*[:=]\s*([a-fA-F0-9]{32})\b",
    re.IGNORECASE,
)
_UUID_OR_ID_PREFIX_REGEX = re.compile(
    r"(?:uuid|guid|session[_-]?id|trace[_-]?id|request[_-]?id|correlation[_-]?id|"
    r"transaction[_-]?id|activity[_-]?id|span[_-]?id|token[_-]?id|client[_-]?id|"
    r"tenant[_-]?id|account[_-]?id|logon[_-]?id|alert[_-]?id|event[_-]?id|sid|id)\s*[:=]\s*$",
    re.IGNORECASE,
)
_HASH_ATTR_KEY_REGEX = re.compile(
    r"(?:hash|md5|digest|checksum|imphash)",
    re.IGNORECASE,
)
_NON_HASH_ATTR_KEY_REGEX = re.compile(
    r"(?:^id$|_id$|uuid|guid|session|trace|request|correlation|transaction|"
    r"activity|span|nonce|token|raw_key|ingested_raw_keys)",
    re.IGNORECASE,
)
_RFC1918_OR_LOCAL_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
)
_SC_SERVICE_MOD_REGEX = re.compile(r"\bsc(?:\.exe)?\s+(?:config|create)\b", re.IGNORECASE)
_SMB_ADMIN_SHARE_REGEX = re.compile(r"\\\\[^\\\s]+\\(?:admin|c)\$", re.IGNORECASE)
_WINDOWS_EVENT_BOILERPLATE_PREFIXES = (
    "the handle to an object was closed",
    "a handle to an object was requested",
    "an attempt was made to access an object",
    "a process has exited",
    "a privileged service was called",
    "a token right was adjusted",
    "process accessed:",
    "the windows filtering platform has permitted",
    "special privileges assigned to new logon",
    "an account was successfully logged on",
    "group membership information",
    "an account was logged off",
)
_GENERIC_MITRE_NAME_WORDS = {
    "system", "binary", "proxy", "execution", "command", "scripting",
    "interpreter", "windows", "linux", "service", "services", "account",
    "accounts", "discovery", "remote", "local", "network", "file", "files",
    "process", "registry", "access", "control", "inhibit", "recovery",
    "indicator", "removal", "clear", "event", "logs", "data", "encrypted",
    "impact", "valid", "domain", "tool", "transfer", "ingress", "obfuscated",
    "encoded", "information", "modify", "create", "capture", "input", "gui",
    "credential", "credentials", "dumping", "memory", "application", "layer",
    "protocol", "protocols", "scheduled", "task", "tasks", "empire", "userland",
    "security", "dataset", "breach", "bank", "cloud", "exploit", "public",
    "facing", "brute", "force", "elevation", "mechanism", "abuse", "theft",
    "external", "internal", "native", "standard", "other", "using", "from",
    "with", "host", "client", "server", "session", "interactive", "script",
    "scripts", "shell", "software", "hardware", "device", "user", "users",
    "group", "groups", "permission", "permissions", "privilege", "privileges",
    "signed", "indirect", "automated", "default", "caching", "share", "shares",
    "admin", "admins", "net",
}


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
    HEX_SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")

    def __init__(
        self,
        system_prompt: Optional[str] = None,
        tools: Optional[Any] = None,
        max_workers: int = 4,
        rag_kb: Optional[Any] = None,
        enable_rag: bool = True,
        enable_rag_matching: Optional[bool] = None,
        rag_mitre_threshold: float = 0.28,
        enable_security_guard: bool = True,
        llm_provider: Optional[Any] = None,
        llm_enabled: bool = False,
    ):
        self.system_prompt = system_prompt or THREAT_INTEL_AGENT_SYSTEM_PROMPT
        self.tools = tools or ThreatIntelTools
        self.max_workers = max_workers
        self.name = "ThreatIntelAgent"
        self.enable_rag = bool(enable_rag_matching) if enable_rag_matching is not None else bool(enable_rag)
        self.enable_rag_matching = self.enable_rag
        self.rag_kb = rag_kb
        self.rag_mitre_threshold = float(rag_mitre_threshold)
        self.enable_security_guard = bool(enable_security_guard)
        self.llm_provider = llm_provider
        self.llm_enabled = bool(llm_enabled)
        self._rag_init_attempted = False

    def set_llm_provider(self, llm_provider: Any) -> None:
        """Cập nhật LLM Provider dùng chung cho ThreatIntelAgent."""
        self.llm_provider = llm_provider

    def _get_rag_kb(self) -> Optional[Any]:
        """Lazy-init RAGKnowledgeBaseTool chỉ khi RAG được bật và rag_kb chưa được truyền vào."""
        if not self.enable_rag:
            return None
        if self.rag_kb is not None:
            return self.rag_kb
        if self._rag_init_attempted:
            return None
        self._rag_init_attempted = True
        try:
            from src.tools.rag_knowledge_base import RAGKnowledgeBaseTool
            self.rag_kb = RAGKnowledgeBaseTool()
        except Exception as ex:
            logger.debug(f"[ThreatIntelAgent] Bỏ qua lazy-init RAGKnowledgeBaseTool: {ex}")
            self.rag_kb = None
        return self.rag_kb

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

            # 2. Thu thập văn bản tự do để quét regex (tách riêng kênh hash để tránh nhầm UUID/session ID thành MD5)
            text_corpus = []
            explicit_hash_attr_texts: List[str] = []
            general_attr_texts: List[str] = []
            if evt.command_line:
                text_corpus.append(evt.command_line)
            if evt.process_path:
                text_corpus.append(evt.process_path)
            for k, v in evt.raw_attributes.items():
                key_str = str(k or "")
                is_non_hash_key = bool(_NON_HASH_ATTR_KEY_REGEX.search(key_str))
                is_hash_key = bool(_HASH_ATTR_KEY_REGEX.search(key_str)) and not is_non_hash_key
                str_items: List[str] = []
                if isinstance(v, str):
                    str_items.append(v)
                elif isinstance(v, (list, tuple)):
                    for item in v:
                        if isinstance(item, str):
                            str_items.append(item)
                for s_val in str_items:
                    text_corpus.append(s_val)
                    if is_hash_key:
                        explicit_hash_attr_texts.append(s_val)
                    elif not is_non_hash_key:
                        general_attr_texts.append(s_val)

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

            # Quét Hashes từ văn bản (SHA256 toàn phần; MD5 chỉ từ key hash, nhãn tường minh md5=/hash=, hoặc command_line không mang tiền tố UUID/session)
            for h_candidate in self.HEX_SHA256_REGEX.findall(combined_text):
                hashes.add(h_candidate.lower())

            def _add_md5_if_valid(cand: str) -> None:
                c_low = cand.lower()
                if not any(c_low in long_h for long_h in hashes if len(long_h) > 32):
                    hashes.add(c_low)

            for h_txt in explicit_hash_attr_texts:
                for h_candidate in self.HEX_MD5_REGEX.findall(h_txt):
                    _add_md5_if_valid(h_candidate)

            for g_txt in general_attr_texts:
                for h_candidate in _EXPLICIT_MD5_REGEX.findall(g_txt):
                    _add_md5_if_valid(h_candidate)

            if evt.command_line:
                for h_candidate in _EXPLICIT_MD5_REGEX.findall(evt.command_line):
                    _add_md5_if_valid(h_candidate)
                for m_md5 in self.HEX_MD5_REGEX.finditer(evt.command_line):
                    cand = m_md5.group(0).lower()
                    if cand.isdigit() or cand.isalpha():
                        continue
                    prefix_slice = evt.command_line[max(0, m_md5.start() - 32):m_md5.start()]
                    if _UUID_OR_ID_PREFIX_REGEX.search(prefix_slice):
                        continue
                    _add_md5_if_valid(cand)

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
                    # Nếu CTI mặc định trả về clean_or_unknown, đối chiếu thêm với RAG threat_feed (exact match)
                    if (
                        self.enable_rag
                        and isinstance(res.details, dict)
                        and res.details.get("status") == "clean_or_unknown"
                    ):
                        kb = self._get_rag_kb()
                        if kb is not None:
                            try:
                                feed_hits = kb.query_threat_feed(val, n_results=1)
                                for hit in feed_hits or []:
                                    hit_val = str(hit.get("value") or "").strip()
                                    if hit_val and hit_val.lower() == str(val).strip().lower():
                                        rep = int(hit.get("reputation_score", 90 if hit.get("is_malicious", True) else 0))
                                        is_mal = bool(hit.get("is_malicious", rep >= 50)) or rep >= 50
                                        res.reputation_score = rep
                                        res.is_malicious = is_mal
                                        actor = hit.get("threat_actor") or hit.get("description") or hit.get("source")
                                        if actor and not res.threat_actor:
                                            res.threat_actor = str(actor)
                                        updated_details = dict(res.details)
                                        updated_details.update({
                                            "status": "rag_threat_feed_match",
                                            "source": hit.get("source", "RAGThreatFeed"),
                                            "description": hit.get("description", ""),
                                            "severity": hit.get("severity", "HIGH"),
                                            "mitre_ids": hit.get("mitre_ids", []),
                                            "rag_score": hit.get("score"),
                                        })
                                        res.details = updated_details
                                        break
                            except Exception as rag_ex:
                                logger.debug(f"[ThreatIntelAgent] Bỏ qua lỗi query_threat_feed cho {val}: {rag_ex}")
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

    @staticmethod
    def _is_trivial_benign_event(evt: ParsedEvent, has_malicious_iocs: bool) -> bool:
        """Nhận diện sự kiện lành tính tầm thường (vd: `ping 8.8.8.8`, logon thường nhật) để bỏ qua RAG."""
        raw_attrs = evt.raw_attributes or {}
        cmd = (evt.command_line or "").strip()
        decoded = str(raw_attrs.get("decoded_command") or "").strip()
        desc = str(raw_attrs.get("wazuh_rule_description") or "").strip()
        rule_id = str(raw_attrs.get("wazuh_rule_id") or "").strip()
        try:
            lvl = int(raw_attrs.get("wazuh_rule_level") or 0)
        except (TypeError, ValueError):
            lvl = 0
        groups = [str(g).lower() for g in (raw_attrs.get("wazuh_groups") or []) if g]

        if has_malicious_iocs or lvl >= 5 or decoded:
            return False
        if rule_id in {"60100", "5715"} and 1 <= lvl <= 4:
            return True
        if 1 <= lvl <= 4 and "routine" in desc.lower() and (
            "authentication_success" in groups or any(g in {"windows", "system", "antivirus", "dns", "sysmon", "sshd"} for g in groups)
        ):
            return True
        if desc:
            return False
        if not cmd:
            return True
        cmd_lower = cmd.lower()
        if "[notice]" in cmd_lower or "session opened for user" in cmd_lower or "accepted publickey" in cmd_lower:
            return True
        if re.match(
            r"^(?:ping|tracert|traceroute|nslookup|dig|ipconfig|ifconfig|hostname|echo|date|pwd|ls|dir)(?:\s+[\w\.\-:\/]+){0,3}$",
            cmd_lower,
        ):
            return True
        return False

    @staticmethod
    def _match_behavioral_mitre_ids(evt: ParsedEvent) -> Set[str]:
        """Ánh xạ hành vi chuẩn (Mordor/LogHub/Windows/Linux) sang MITRE ATT&CK ID."""
        matched: Set[str] = set()
        raw_attrs = evt.raw_attributes or {}
        target_obj = str(raw_attrs.get("target_object") or "")
        share_name = str(raw_attrs.get("share_name") or "")
        rel_target = str(raw_attrs.get("relative_target_name") or "")
        rule_desc = str(raw_attrs.get("wazuh_rule_description") or "")
        decoded_cmd = str(raw_attrs.get("decoded_command") or "")

        proc_lower = (evt.process_name or "").strip().lower()
        parent_lower = (evt.parent_process or "").strip().lower()
        eid_str = str(evt.event_id or "").strip()
        src_lower = (evt.source_type or "").strip().lower()
        granted_access = str(raw_attrs.get("granted_access") or "").strip().lower()

        evt_blob = " ".join(
            str(p)
            for p in (
                evt.process_name,
                evt.process_path,
                evt.command_line,
                decoded_cmd,
                target_obj,
                share_name,
                rel_target,
                rule_desc,
            )
            if p
        ).lower()

        if not evt_blob:
            return matched

        # 1. NTDS.dit / AD database extraction (Mordor ntdsutil / ESENT VSS, tránh recovery startup thường nhật)
        if "ntdsutil" in evt_blob or (
            ("ntds.dit" in evt_blob or "\\windows\\ntds\\" in evt_blob)
            and any(k in evt_blob for k in ("shadow", "ifm", "esedb", "copy"))
        ):
            matched.add("T1003.003")

        # 2. LSASS memory dumping (Dumpert, Mimikatz, ProcDump, comsvcs, suspicious Sysmon 10)
        suspicious_lsass_access = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f3fff"}
        if (
            "dumpert" in evt_blob
            or "outflank-dumpert" in evt_blob
            or "mimikatz" in evt_blob
            or "sekurlsa" in evt_blob
            or "lsass.dmp" in evt_blob
            or ("comsvcs" in evt_blob and "minidump" in evt_blob)
            or ("procdump" in evt_blob and "lsass" in evt_blob)
            or (
                eid_str == "10"
                and "targetimage:" in evt_blob
                and "lsass.exe" in evt_blob
                and granted_access in suspicious_lsass_access
            )
        ):
            matched.add("T1003.001")

        # 3. BITSAdmin tool transfer
        if "bitsadmin" in evt_blob:
            matched.add("T1197")
            if any(k in evt_blob for k in ("/transfer", "/download", "/addfile", "http://", "https://")):
                matched.add("T1105")

        # 4. Windows Service creation / modification (sc config/create, Event 7045/4697, services.exe child shell)
        if (
            _SC_SERVICE_MOD_REGEX.search(evt_blob)
            or ("services.exe" in parent_lower and any(s in proc_lower for s in ("powershell", "cmd", "pwsh")))
            or eid_str in {"7045", "4697"}
        ):
            matched.add("T1543.003")

        # 5. Active Directory discovery (SharpView / PowerView / Get-ObjectAcl)
        if (
            "sharpview" in evt_blob
            or "powerview" in evt_blob
            or "get-objectacl" in evt_blob
            or "get-netuser" in evt_blob
            or "get-domainuser" in evt_blob
            or "get-netcomputer" in evt_blob
            or "get-domaincomputer" in evt_blob
            or ("samaccountname" in evt_blob and "domain admins" in evt_blob)
        ):
            matched.update({"T1087.002", "T1087", "T1018"})

        # 6. Logon script persistence (UserInitMprLogonScript)
        if "userinitmprlogonscript" in evt_blob:
            matched.add("T1037.001")

        # 7. Registry Run / RunOnce persistence
        if "currentversion\\run" in evt_blob or "currentversion\\runonce" in evt_blob:
            matched.add("T1547.001")

        # 8. SMB Admin share lateral movement (ADMIN$ / C$)
        share_lower = share_name.strip().lower()
        if _SMB_ADMIN_SHARE_REGEX.search(evt_blob) or share_lower.endswith(("\\admin$", "\\c$")):
            matched.add("T1021.002")

        # 9. WinRM / WSMan lateral movement
        if (
            "wsmprovhost" in evt_blob
            or ("wsman" in evt_blob and eid_str != "4656")
            or "enter-pssession" in evt_blob
            or ("invoke-command" in evt_blob and ("-computername" in evt_blob or "winrm" in evt_blob))
            or (eid_str == "4672" and "seenabledelegationprivilege" in evt_blob)
        ):
            matched.add("T1021.006")

        # 10. GUI credential prompt / CredUI capture
        if (
            "promptforcredential" in evt_blob
            or "creduiprompt" in evt_blob
            or ("powershell" in proc_lower and ("credui.dll" in evt_blob or "wincredui.dll" in evt_blob))
        ):
            matched.add("T1056.002")

        # 11. PowerShell HttpListener / WebClient C2
        if "httplistener" in evt_blob or "system.net.httplistener" in evt_blob:
            matched.update({"T1059.001", "T1071.001"})
        elif "powershell" in proc_lower and any(
            k in evt_blob for k in ("system.net.webclient", "downloadstring", "invoke-webrequest", "invoke-restmethod")
        ):
            matched.update({"T1059.001", "T1071.001"})

        # 12. SSH & Linux PAM brute force / credential abuse
        auth_fail_markers = (
            "failed password",
            "invalid user",
            "possible break-in attempt",
            "authentication failure",
            "authentication error",
            "maximum authentication attempts",
            "bad username",
            "user unknown",
        )
        if any(k in evt_blob for k in auth_fail_markers):
            matched.add("T1110")
            if any(k in evt_blob for k in ("for root", "user=root", "for admin", "user=admin", "uid=0")):
                matched.add("T1078")
        if "sudo" in evt_blob and any(
            k in evt_blob for k in ("authentication failure", "incorrect password", "not in sudoers", "command=")
        ):
            matched.add("T1548.003")

        # 13. Apache / Web server exploit & worker anomaly
        if (
            ("mod_jk" in evt_blob and "error" in evt_blob and ("workerenv" in evt_blob or "child init" in evt_blob))
            or (
                (src_lower in {"webserver", "apache", "nginx", "http"} or any(w in proc_lower for w in ("httpd", "apache", "nginx", "webserver")))
                and any(
                    w in evt_blob
                    for w in ("union select", "../", "<script", "eval(", "cmd=", "/etc/passwd", "sql injection", "xss", "jndi:", "workerenv in error")
                )
            )
        ):
            matched.add("T1190")

        return matched

    @staticmethod
    def _rag_hit_matches_query(
        hit: Dict[str, Any],
        behavior_query: str,
    ) -> bool:
        """Kiểm tra hit RAG có từ khóa đặc trưng thực sự khớp ngữ cảnh truy vấn hành vi hay không."""
        q_lower = (behavior_query or "").lower()
        if not q_lower:
            return False
        tid = str(hit.get("technique_id") or "").strip().lower()
        if tid and re.search(rf"(?<![a-z0-9]){re.escape(tid)}(?![a-z0-9])", q_lower):
            return True
        raw_name = str(hit.get("name") or "")
        clean_name = re.sub(r"\([^)]*\)", " ", raw_name).lower()
        tokens = [
            tok
            for tok in re.findall(r"[a-z0-9_.\-]{4,}", clean_name)
            if tok not in _GENERIC_MITRE_NAME_WORDS
        ]
        if not tokens:
            return False
        return any(
            re.search(rf"(?<![a-z0-9]){re.escape(tok)}(?![a-z0-9])", q_lower)
            for tok in tokens
        )

    @staticmethod
    def _extract_concise_behavior_parts(evt: ParsedEvent) -> List[str]:
        """Rút trích thông tin hành vi ngắn gọn (loại bỏ boilerplate Windows Event Log)."""
        raw_attrs = evt.raw_attributes or {}
        decoded_cmd = str(raw_attrs.get("decoded_command") or "").strip()
        rule_desc = str(raw_attrs.get("wazuh_rule_description") or "").strip()
        target_obj = str(raw_attrs.get("target_object") or "").strip()
        share_name = str(raw_attrs.get("share_name") or "").strip()
        eid_str = str(evt.event_id or "").strip()
        proc_lower = (evt.process_name or "").strip().lower()

        if (
            eid_str in {"4656", "4658", "4663", "4670", "4672", "4673", "4689", "4690", "5154", "5156", "5158"}
            and proc_lower in {"lsass.exe", "svchost.exe", "services.exe", "explorer.exe", "windowsazureguestagent.exe", "waappagent.exe", "system", ""}
            and not (target_obj or share_name or decoded_cmd or rule_desc)
        ):
            return []

        if (
            eid_str in {"3", "13"}
            and proc_lower == "lsass.exe"
            and not any(
                k in f"{target_obj} {evt.command_line or ''}".lower()
                for k in ("wdigest", "\\control\\lsa", "sekurlsa", "dumpert", "mimikatz", "logonscript", "\\run")
            )
        ):
            return []

        if (
            eid_str == "18"
            and proc_lower in {"dns.exe", "svchost.exe", "services.exe"}
            and "pipename: \\lsass" in (evt.command_line or "").lower()
        ):
            return []

        parts: List[str] = []
        for candidate in (evt.process_name, decoded_cmd, rule_desc, target_obj, share_name, evt.parent_process):
            if candidate and str(candidate).strip():
                parts.append(str(candidate).strip())

        cmd = (evt.command_line or "").strip()
        if cmd:
            cmd_lower = cmd.lower()
            if not cmd_lower.startswith(_WINDOWS_EVENT_BOILERPLATE_PREFIXES):
                first_line = cmd.splitlines()[0].strip()
                if first_line:
                    parts.append(first_line[:220])
        return parts

    @staticmethod
    def _is_external_ipv4(ip_str: str) -> bool:
        """Trả về True nếu IPv4 nằm ngoài dải nội bộ RFC 1918 / loopback / link-local (bao gồm cả TEST-NET)."""
        try:
            ip_obj = ipaddress.ip_address(str(ip_str).strip())
            if ip_obj.version != 4:
                return False
            return not any(ip_obj in net for net in _RFC1918_OR_LOCAL_NETS)
        except ValueError:
            return False

    def _collect_allowed_ipv4s(
        self,
        events: List[ParsedEvent],
        ioc_items: List[IoCItem],
    ) -> Set[str]:
        """Thu thập toàn bộ địa chỉ IPv4 có mặt trong bằng chứng sự kiện & IoCs để kiểm chứng grounding."""
        allowed: Set[str] = set()
        for ioc in ioc_items or []:
            if ioc.value:
                for ip in self.IPV4_REGEX.findall(str(ioc.value)):
                    allowed.add(ip)
        for evt in events or []:
            for field_val in (
                evt.source_ip,
                evt.dest_ip,
                evt.command_line,
                evt.process_path,
                evt.parent_command_line,
            ):
                if field_val:
                    for ip in self.IPV4_REGEX.findall(str(field_val)):
                        allowed.add(ip)
            for v in (evt.raw_attributes or {}).values():
                if isinstance(v, str):
                    for ip in self.IPV4_REGEX.findall(v):
                        allowed.add(ip)
                elif isinstance(v, (list, tuple)):
                    for item in v:
                        if isinstance(item, str):
                            for ip in self.IPV4_REGEX.findall(item):
                                allowed.add(ip)
        return allowed

    def _has_fabricated_external_ipv4(self, text: str, allowed_ips: Set[str]) -> bool:
        """Kiểm tra xem văn bản LLM có tự bịa địa chỉ IPv4 ngoại lai không có trong bằng chứng hay không."""
        for ip in self.IPV4_REGEX.findall(text or ""):
            if self._is_external_ipv4(ip) and ip not in allowed_ips:
                return True
        return False

    def _analyze_cti_with_llm(
        self,
        events: List[ParsedEvent],
        ioc_items: List[IoCItem],
        deterministic_mitre: List[str],
        behavior_query: str,
        rag_mitre_context: List[Dict[str, Any]],
        incident_state: Optional[IncidentState] = None,
    ) -> Tuple[Optional[ThreatIntelLLMAnalysis], bool, List[Dict[str, str]]]:
        """
        Gọi LLM structured (`ThreatIntelLLMAnalysis`, fast tier) để bổ sung ánh xạ MITRE ATT&CK
        và nhận định CTI ngắn gọn bám sát bằng chứng cho các ca OOD / mơ hồ.
        IoCs và điểm uy tín CTI vẫn giữ 100% deterministic từ công cụ.
        """
        if not self.llm_enabled or self.llm_provider is None:
            return None, False, []
        prov_mode = str(getattr(self.llm_provider, "provider_mode", "") or "").strip().lower()
        if prov_mode == "deterministic":
            return None, False, []
        if not (behavior_query or "").strip():
            return None, False, []

        security_flags: List[Dict[str, str]] = []
        if self.enable_security_guard:
            safe_behavior, is_inj, reason = inspect_and_wrap_untrusted(
                behavior_query,
                field_name="cti_behavior_query",
                max_len=600,
                include_notice=False,
            )
            if is_inj:
                security_flags.append(
                    {
                        "field": "cti_behavior_query",
                        "reason": reason or "prompt_injection_detected",
                    }
                )
        else:
            safe_behavior = str(behavior_query)[:600]

        rag_parts: List[str] = []
        for c in (rag_mitre_context or [])[:3]:
            if isinstance(c, dict) and c.get("technique_id"):
                tid_s = sanitize_prompt_text(str(c.get("technique_id")), max_len=24)
                name_s = sanitize_prompt_text(str(c.get("name", "")), max_len=80)
                tactic_s = sanitize_prompt_text(str(c.get("tactic", "")), max_len=40)
                rag_parts.append(
                    f"{tid_s} ({name_s}" + (f" / {tactic_s}" if tactic_s else "") + ")"
                )
        rag_hint = ", ".join(rag_parts)

        ioc_parts: List[str] = []
        for ioc in (ioc_items or [])[:6]:
            val_s = sanitize_prompt_text(str(ioc.value or ""), max_len=120)
            type_s = sanitize_prompt_text(str(ioc.ioc_type or ""), max_len=20)
            score_v = ioc.reputation_score if ioc.reputation_score is not None else 0
            actor_s = (
                sanitize_prompt_text(str(ioc.threat_actor or ""), max_len=60)
                if ioc.threat_actor
                else ""
            )
            entry = f"{type_s}:{val_s} (malicious={bool(ioc.is_malicious)}, score={score_v}"
            if actor_s:
                entry += f", actor={actor_s}"
            entry += ")"
            ioc_parts.append(entry)
        ioc_hint = "; ".join(ioc_parts) if ioc_parts else "None"

        det_mitre_hint = (
            ", ".join(
                sorted(
                    {
                        str(t).strip().upper()
                        for t in (deterministic_mitre or [])
                        if isinstance(t, str) and t.strip()
                    }
                )
            )
            or "None"
        )

        header_block = (
            f"{UNTRUSTED_LOG_SECURITY_HEADER}\n\n"
            if self.enable_security_guard
            else ""
        )
        prompt = (
            f"{header_block}"
            "Analyze the observed security event behavior, deterministic CTI results, and RAG MITRE candidates.\n"
            "Return ONLY valid JSON matching ThreatIntelLLMAnalysis with fields:\n"
            "- mitre_techniques: list of up to 3 valid MITRE ATT&CK IDs (format Txxxx or Txxxx.xxx) grounded in evidence.\n"
            "- mitre_rationale: concise rationale explaining the mapped techniques.\n"
            "- threat_assessment_summary: concise 1-2 sentence threat assessment grounded strictly in the provided data "
            "(never invent external IPs, hashes, threat actors, or reputation scores).\n"
            "- evidence_citations: short list of observed evidence fields.\n\n"
            f"Deterministic MITRE already mapped: {det_mitre_hint}\n"
            f"Deterministic CTI IoCs: {ioc_hint}\n"
            + (f"RAG MITRE candidates: {rag_hint}\n" if rag_hint else "")
            + f"Observed behavior:\n{safe_behavior}\n"
        )

        structured_obj, used_real_llm, info = invoke_structured_llm(
            self.llm_provider,
            prompt,
            ThreatIntelLLMAnalysis,
            system_prompt=self.system_prompt,
            incident_state=incident_state,
            model_tier="fast",
            temperature=0.1,
            max_tokens=600,
            agent_name="ThreatIntelAgent",
        )

        raw_analysis: Optional[ThreatIntelLLMAnalysis] = None
        if used_real_llm and isinstance(structured_obj, ThreatIntelLLMAnalysis):
            raw_analysis = structured_obj
        elif used_real_llm and isinstance(structured_obj, dict):
            try:
                raw_analysis = ThreatIntelLLMAnalysis.model_validate(structured_obj)
            except Exception:
                raw_analysis = None
        elif used_real_llm and structured_obj is None and isinstance(info, str) and info.strip():
            json_text = info.strip()
            if "```" in json_text:
                m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", json_text, re.DOTALL)
                if m:
                    json_text = m.group(1)
            try:
                raw_analysis = ThreatIntelLLMAnalysis.model_validate_json(json_text)
            except Exception:
                extracted_ids: List[str] = []
                for tok in re.split(r"[\s,;]+", info.strip()):
                    clean_tok = tok.strip(".,;:\"'()[]{}<>").upper()
                    if _STRICT_MITRE_ID_REGEX.fullmatch(clean_tok) and clean_tok not in extracted_ids:
                        extracted_ids.append(clean_tok)
                if extracted_ids:
                    raw_analysis = ThreatIntelLLMAnalysis(mitre_techniques=extracted_ids)

        if raw_analysis is None:
            return None, False, security_flags

        existing_set = {
            str(t).strip().upper()
            for t in (deterministic_mitre or [])
            if isinstance(t, str) and t.strip()
        }
        validated_additions: List[str] = []
        for raw_tid in raw_analysis.mitre_techniques or []:
            if not isinstance(raw_tid, str):
                continue
            cand = raw_tid.strip().upper()
            if not _STRICT_MITRE_ID_REGEX.fullmatch(cand):
                continue
            if cand in existing_set or cand in validated_additions:
                continue
            validated_additions.append(cand)
            if len(validated_additions) >= 3:
                break

        allowed_ips = self._collect_allowed_ipv4s(events, ioc_items)

        summary_clean = re.sub(
            r"\s+", " ", str(raw_analysis.threat_assessment_summary or "")
        ).strip()[:400]
        if summary_clean and self._has_fabricated_external_ipv4(summary_clean, allowed_ips):
            logger.warning(
                "[ThreatIntelAgent] Từ chối threat_assessment_summary do phát hiện IPv4 ngoại lai bịa đặt."
            )
            summary_clean = ""

        rationale_clean = re.sub(
            r"\s+", " ", str(raw_analysis.mitre_rationale or "")
        ).strip()[:400]
        if rationale_clean and self._has_fabricated_external_ipv4(rationale_clean, allowed_ips):
            rationale_clean = ""

        citations_clean: List[str] = []
        for cite in raw_analysis.evidence_citations or []:
            if not isinstance(cite, str):
                continue
            c_clean = re.sub(r"\s+", " ", cite).strip()[:160]
            if not c_clean or self._has_fabricated_external_ipv4(c_clean, allowed_ips):
                continue
            if c_clean not in citations_clean:
                citations_clean.append(c_clean)
            if len(citations_clean) >= 6:
                break

        validated = ThreatIntelLLMAnalysis(
            mitre_techniques=validated_additions,
            mitre_rationale=rationale_clean,
            threat_assessment_summary=summary_clean,
            evidence_citations=citations_clean,
        )
        return validated, True, security_flags

    def _refine_mitre_with_llm(
        self,
        behavior_query: str,
        rag_mitre_context: List[Dict[str, Any]],
        incident_state: Optional[IncidentState] = None,
    ) -> List[str]:
        """Hook tương thích ngược gọi _analyze_cti_with_llm() và trả về danh sách mã MITRE hợp lệ."""
        analysis, _, _ = self._analyze_cti_with_llm(
            events=[],
            ioc_items=[],
            deterministic_mitre=[],
            behavior_query=behavior_query,
            rag_mitre_context=rag_mitre_context,
            incident_state=incident_state,
        )
        return list(analysis.mitre_techniques) if analysis else []

    def _extract_mitre_and_analyze_llm(
        self,
        events: List[ParsedEvent],
        ioc_items: List[IoCItem],
        incident_state: Optional[IncidentState] = None,
    ) -> Tuple[
        List[str],
        List[Dict[str, Any]],
        int,
        Optional[ThreatIntelLLMAnalysis],
        bool,
        List[Dict[str, str]],
    ]:
        """
        Ánh xạ kỹ thuật MITRE ATT&CK từ SIEM metadata, từ khóa hành vi, CTI IoCs,
        RAG Knowledge Base và (khi phù hợp) structured LLM CTI analysis.
        """
        techniques: Set[str] = set()
        malicious_iocs = [ioc for ioc in ioc_items if ioc.is_malicious]
        has_malicious_iocs = bool(malicious_iocs)
        has_explicit_siem_mitre = False
        behavior_parts: List[str] = []
        seen_behavior_parts: Set[str] = set()
        max_rule_level = 0

        # 1. Ánh xạ từ các sự kiện log (tiến trình, dòng lệnh, decoded_command, thuộc tính raw)
        for evt in events:
            raw_attrs = evt.raw_attributes or {}
            try:
                lvl = int(raw_attrs.get("wazuh_rule_level") or 0)
            except (TypeError, ValueError):
                lvl = 0
            if lvl > max_rule_level:
                max_rule_level = lvl

            # Kiểm tra tag MITRE có sẵn từ SIEM (hỗ trợ cả mitre_ids và wazuh_mitre_ids)
            for attr_key in ("mitre_ids", "wazuh_mitre_ids"):
                w_mitre = raw_attrs.get(attr_key) or []
                if isinstance(w_mitre, list):
                    for m_id in w_mitre:
                        if isinstance(m_id, str) and m_id.strip().upper().startswith("T"):
                            techniques.add(m_id.strip().upper())
                            has_explicit_siem_mitre = True

            decoded_cmd = str(raw_attrs.get("decoded_command") or "").strip()

            # Ánh xạ qua từ khóa hành vi từ ThreatIntelTools
            text_targets = [
                evt.process_name or "",
                evt.command_line or "",
                decoded_cmd,
                evt.parent_process or "",
            ]
            combined = " ".join(part for part in text_targets if part)
            if combined:
                matches = self.tools.match_mitre_technique(combined)
                for m in matches:
                    mid = m["mitre_id"]
                    if (
                        mid == "T1071.001"
                        and self.tools is ThreatIntelTools
                        and "beacon" not in combined.lower()
                        and not re.search(r"(?<![a-z0-9])c2(?![a-z0-9])", combined.lower())
                    ):
                        continue
                    techniques.add(mid)

            # Ánh xạ hành vi ID chuẩn cho Mordor & LogHub
            techniques.update(self._match_behavioral_mitre_ids(evt))

            if not self._is_trivial_benign_event(evt, has_malicious_iocs):
                for part in self._extract_concise_behavior_parts(evt):
                    part_key = part.lower()
                    if part_key not in seen_behavior_parts:
                        seen_behavior_parts.add(part_key)
                        behavior_parts.append(part)

        # 2. Ánh xạ từ thông tin CTI của các IoC độc hại
        for ioc in malicious_iocs:
            cats = ioc.details.get("categories", []) if isinstance(ioc.details, dict) else []
            actor = (ioc.threat_actor or "").lower()

            if isinstance(ioc.details, dict):
                feed_mitre = ioc.details.get("mitre_ids") or []
                if isinstance(feed_mitre, list):
                    for m_id in feed_mitre:
                        if isinstance(m_id, str) and m_id.strip().upper().startswith("T"):
                            techniques.add(m_id.strip().upper())

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

            if ioc.threat_actor and str(ioc.threat_actor).lower() not in seen_behavior_parts:
                seen_behavior_parts.add(str(ioc.threat_actor).lower())
                behavior_parts.append(str(ioc.threat_actor))
            for cat in cats:
                if cat and str(cat).lower() not in seen_behavior_parts:
                    seen_behavior_parts.add(str(cat).lower())
                    behavior_parts.append(str(cat))

        # 3. Semantic RAG MITRE Matching cho bằng chứng hành vi không tầm thường
        rag_mitre_context: List[Dict[str, Any]] = []
        rag_techniques_added = 0
        had_deterministic_techniques = bool(techniques)
        existing_bases = {t.split(".")[0] for t in techniques}
        raw_behavior_query = " ".join(behavior_parts).strip()
        behavior_query = ""

        if self.enable_rag and (behavior_parts or has_malicious_iocs or max_rule_level >= 5):
            if self.enable_security_guard and raw_behavior_query:
                behavior_query = sanitize_prompt_text(raw_behavior_query, max_len=600)
            else:
                behavior_query = raw_behavior_query[:600]

            if behavior_query:
                kb = self._get_rag_kb()
                if kb is not None:
                    try:
                        hits = kb.query_mitre_technique(behavior_query, n_results=3)
                    except Exception as ex:
                        logger.debug(f"[ThreatIntelAgent] Lỗi query_mitre_technique: {ex}")
                        hits = []

                    seen_rag_ids: Set[str] = set()
                    for hit_idx, hit in enumerate(hits or []):
                        if len(rag_mitre_context) >= 3:
                            break
                        if not isinstance(hit, dict):
                            continue
                        score_val = float(hit.get("score", 0.0) or 0.0)
                        if score_val < self.rag_mitre_threshold:
                            continue
                        tid = str(hit.get("technique_id") or "").strip().upper()
                        if not tid.startswith("T") or tid in seen_rag_ids:
                            continue
                        seen_rag_ids.add(tid)

                        tid_base = tid.split(".")[0]
                        should_promote = False
                        if tid not in techniques and rag_techniques_added < 1:
                            if not had_deterministic_techniques:
                                # Khi chưa có kỹ thuật deterministic nào, chỉ thăng hạng tối đa 1 hit RAG có điểm cao (>= 0.72)
                                # hoặc đạt ngưỡng (>= 0.55) kèm khớp từ khóa đặc trưng với hành vi.
                                if score_val >= max(self.rag_mitre_threshold, 0.72) or (
                                    score_val >= max(self.rag_mitre_threshold, 0.55)
                                    and self._rag_hit_matches_query(hit, behavior_query)
                                ):
                                    should_promote = True
                            else:
                                # Khi đã có kỹ thuật từ SIEM/rule, tránh làm loãng precision bằng hit phụ/nhiễu:
                                # chỉ bổ sung tối đa 1 kỹ thuật mới có điểm cao và thực sự khớp bằng chứng hành vi.
                                if (
                                    tid_base not in existing_bases
                                    and (
                                        score_val >= max(self.rag_mitre_threshold, 0.75)
                                        or (hit_idx == 0 and score_val >= max(self.rag_mitre_threshold, 0.55))
                                    )
                                    and (score_val >= 0.90 or self._rag_hit_matches_query(hit, behavior_query))
                                ):
                                    should_promote = True

                        if should_promote:
                            techniques.add(tid)
                            existing_bases.add(tid_base)
                            rag_techniques_added += 1

                        rag_mitre_context.append({
                            "technique_id": tid,
                            "name": str(hit.get("name") or ""),
                            "tactic": str(hit.get("tactic") or ""),
                            "detection": str(hit.get("detection") or ""),
                            "mitigations": str(hit.get("mitigations") or ""),
                            "score": round(score_val, 4),
                        })

        # 4. Structured LLM CTI Analysis cho các ca OOD / mơ hồ (chỉ chạy khi live LLM bật và không phải deterministic)
        llm_analysis: Optional[ThreatIntelLLMAnalysis] = None
        llm_cti_executed = False
        security_guard_flags: List[Dict[str, str]] = []
        prov_mode = str(getattr(self.llm_provider, "provider_mode", "") or "").strip().lower()
        should_run_llm = (
            self.llm_enabled
            and self.llm_provider is not None
            and prov_mode != "deterministic"
            and bool(behavior_parts)
            and (not techniques or (not has_explicit_siem_mitre and len(techniques) < 2))
        )
        if should_run_llm:
            llm_analysis, llm_cti_executed, security_guard_flags = self._analyze_cti_with_llm(
                events=events,
                ioc_items=ioc_items,
                deterministic_mitre=sorted(list(techniques)),
                behavior_query=raw_behavior_query,
                rag_mitre_context=rag_mitre_context,
                incident_state=incident_state,
            )
            if llm_analysis is not None:
                for llm_tid in llm_analysis.mitre_techniques:
                    techniques.add(llm_tid)

        return (
            sorted(list(techniques)),
            rag_mitre_context,
            rag_techniques_added,
            llm_analysis,
            llm_cti_executed,
            security_guard_flags,
        )

    def _extract_mitre_with_rag(
        self,
        events: List[ParsedEvent],
        ioc_items: List[IoCItem],
    ) -> Tuple[List[str], List[Dict[str, Any]], int]:
        """
        Ánh xạ kỹ thuật MITRE ATT&CK từ SIEM metadata, từ khóa hành vi, CTI IoCs
        và đối chiếu ngữ nghĩa qua RAG Knowledge Base.
        Trả về (mitre_techniques, rag_mitre_context, rag_techniques_added).
        """
        techniques, rag_mitre_context, rag_techniques_added, _, _, _ = (
            self._extract_mitre_and_analyze_llm(events, ioc_items, incident_state=None)
        )
        return techniques, rag_mitre_context, rag_techniques_added

    def extract_mitre_techniques(
        self,
        events: List[ParsedEvent],
        ioc_items: List[IoCItem]
    ) -> List[str]:
        """
        Ánh xạ kỹ thuật MITRE ATT&CK dựa trên các sự kiện, dấu hiệu CTI và RAG Knowledge Base.
        """
        techniques, _, _ = self._extract_mitre_with_rag(events, ioc_items)
        return techniques

    # =====================================================================
    # 4. LÀM GIÀU DỮ LIỆU & TẠO ENRICHMENT OBJECT (ENRICHMENT PIPELINE)
    # =====================================================================
    def _enrich_events_with_meta(
        self,
        events: List[ParsedEvent],
        incident_state: Optional[IncidentState] = None,
    ) -> Tuple[ThreatIntelEnrichment, int, Dict[str, Any]]:
        """Thực thi pipeline làm giàu CTI + RAG + LLM structured và trả về (ThreatIntelEnrichment, rag_techniques_added, llm_meta)."""
        # Bước 1: Trích xuất IoCs
        extracted = self.extract_iocs(events)

        # Bước 2: Tra cứu song song uy tín CTI (+ dynamic threat feed trong RAG)
        ioc_items = self.lookup_iocs_parallel(extracted)

        # Bước 3: Tính toán điểm đe dọa tổng hợp
        threat_score, is_incident_malicious = self.compute_threat_score(ioc_items)

        # Bước 4: Ánh xạ kỹ thuật MITRE ATT&CK + RAG MITRE Context + Structured LLM CTI (khi OOD/mơ hồ)
        (
            mitre_techniques,
            rag_mitre_context,
            rag_techniques_added,
            llm_analysis,
            llm_cti_executed,
            security_guard_flags,
        ) = self._extract_mitre_and_analyze_llm(
            events,
            ioc_items,
            incident_state=incident_state,
        )

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

        if llm_analysis is not None and llm_analysis.threat_assessment_summary:
            summary = f"{summary} Nhận định CTI (LLM): {llm_analysis.threat_assessment_summary}"

        enrichment = ThreatIntelEnrichment(
            extracted_iocs=ioc_items,
            related_threat_actors=threat_actors,
            mitre_techniques=mitre_techniques,
            enrichment_summary=summary,
            rag_mitre_context=rag_mitre_context,
        )
        llm_meta: Dict[str, Any] = {
            "llm_cti_executed": bool(llm_cti_executed),
            "llm_mitre_added": len(llm_analysis.mitre_techniques) if llm_analysis else 0,
            "security_guard_flags": list(security_guard_flags),
        }
        return enrichment, rag_techniques_added, llm_meta

    def enrich_events(self, events: List[ParsedEvent]) -> ThreatIntelEnrichment:
        """
        Tiếp nhận danh sách ParsedEvent và trả về đối tượng ThreatIntelEnrichment chuẩn Pydantic v2.
        """
        enrichment, _, _ = self._enrich_events_with_meta(events, incident_state=None)
        return enrichment

    def enrich_state(self, state: IncidentState) -> IncidentState:
        """
        Tích hợp và cập nhật trực tiếp vào đối tượng IncidentState của LangGraph.
        Lưu vết StateTransition đầy đủ kèm metadata RAG & LLM CTI.
        """
        enrichment, rag_techniques_added, llm_meta = self._enrich_events_with_meta(
            state.parsed_events,
            incident_state=state,
        )
        state.threat_intel = enrichment

        malicious_count = sum(1 for ioc in enrichment.extracted_iocs if ioc.is_malicious)
        threat_score, is_malicious = self.compute_threat_score(enrichment.extracted_iocs)

        if not self.enable_rag:
            rag_backend = "disabled"
        elif self.rag_kb is not None:
            rag_backend = str(getattr(self.rag_kb, "backend", "custom"))
        else:
            rag_backend = "not_queried"

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
                "mitre_count": len(enrichment.mitre_techniques),
                "rag_techniques_added": rag_techniques_added,
                "rag_backend": rag_backend,
                "llm_cti_executed": bool(llm_meta.get("llm_cti_executed", False)),
                "security_guard_flags": list(llm_meta.get("security_guard_flags") or []),
            }
        )
        return state
