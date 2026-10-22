# -*- coding: utf-8 -*-
"""
src/tools/threat_intel.py
Bộ công cụ tra cứu Cyber Threat Intelligence (CTI).
Hỗ trợ tra cứu uy tín IP, Domain, URL, Hash (VirusTotal, AbuseIPDB)
với cơ chế Caching in-memory, lọc IP Private RFC 1918 và ánh xạ kỹ thuật MITRE ATT&CK.
"""

import os
import re
import json
import ipaddress
import threading
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, Any, List, Optional, Set

from src.core.schemas import IoCItem


class ThreatIntelTools:
    """Công cụ CTI phục vụ Threat Intelligence Agent."""

    # Thread-safe in-memory cache cho các kết quả tra cứu
    _cache: Dict[str, IoCItem] = {}
    _cache_lock: threading.Lock = threading.Lock()

    # =====================================================================
    # 1. CƠ SỞ DỮ LIỆU CTI MẪU (MOCK CTI DATABASE CHO MÔI TRƯỜNG OFFLINE/LAB)
    # =====================================================================
    KNOWN_MALICIOUS_IPS: Dict[str, Dict[str, Any]] = {
        "194.26.29.112": {
            "reputation_score": 92,
            "threat_actor": "Cobalt Strike Team / RedLine Stealer",
            "country": "RU",
            "isp": "BadHost Ltd",
            "categories": ["C2", "Botnet"]
        },
        "185.220.101.5": {
            "reputation_score": 88,
            "threat_actor": "Phishing-Group-04",
            "country": "NL",
            "isp": "Tor Exit Node",
            "categories": ["Phishing", "Proxy"]
        },
        "45.33.32.156": {
            "reputation_score": 95,
            "threat_actor": "Emotet Gang",
            "country": "US",
            "isp": "Linode LLC",
            "categories": ["C2", "Trojan"]
        },
        "103.203.57.18": {
            "reputation_score": 90,
            "threat_actor": "QakBot Infrastructure",
            "country": "VN",
            "isp": "Viettel Corp",
            "categories": ["C2", "Banking Trojan"]
        },
        "198.51.100.42": {
            "reputation_score": 85,
            "threat_actor": "Phishing-Kit-Operator",
            "country": "DE",
            "isp": "HostEurope",
            "categories": ["Phishing", "Credential Harvesting"]
        },
        "198.51.100.99": {
            "reputation_score": 78,
            "threat_actor": "Mirai Botnet Operator",
            "country": "BR",
            "isp": "Telecom Provider",
            "categories": ["Scanner", "Botnet"]
        }
    }

    KNOWN_CLEAN_IPS: Set[str] = {
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "208.67.222.222",
        "9.9.9.9",
        "13.107.21.200"
    }

    KNOWN_MALICIOUS_DOMAINS: Dict[str, Dict[str, Any]] = {
        "evil-malware-c2.com": {
            "reputation_score": 95,
            "threat_actor": "APT29 / Cozy Bear",
            "registrar": "NameCheap Inc",
            "categories": ["C2", "Malware Delivery"]
        },
        "phishing-bank-login.xyz": {
            "reputation_score": 90,
            "threat_actor": "Phishing-Group-04",
            "registrar": "Hostinger",
            "categories": ["Phishing", "Credential Harvesting"]
        },
        "update-microsoft-security.net": {
            "reputation_score": 88,
            "threat_actor": "Lazarus Group",
            "registrar": "Porkbun LLC",
            "categories": ["Impersonation", "Malware Delivery"]
        },
        "c2-stealer-service.top": {
            "reputation_score": 92,
            "threat_actor": "RedLine Stealer Team",
            "registrar": "RegRu",
            "categories": ["Stealer", "C2"]
        },
        "login-office365-verify.com": {
            "reputation_score": 89,
            "threat_actor": "Storm-0558",
            "registrar": "NameSilo",
            "categories": ["Phishing", "Credential Harvesting"]
        }
    }

    KNOWN_CLEAN_DOMAINS: Set[str] = {
        "google.com",
        "microsoft.com",
        "github.com",
        "cloudflare.com",
        "apple.com",
        "amazon.com"
    }

    KNOWN_MALICIOUS_URLS: Dict[str, Dict[str, Any]] = {
        "http://evil-malware-c2.com/payload.exe": {
            "reputation_score": 95,
            "threat_actor": "APT29 / Cozy Bear",
            "categories": ["Trojan-Downloader", "Payload Delivery"]
        },
        "https://phishing-bank-login.xyz/login.php": {
            "reputation_score": 90,
            "threat_actor": "Phishing-Group-04",
            "categories": ["Phishing Page", "Credential Harvesting"]
        },
        "http://update-microsoft-security.net/patch.ps1": {
            "reputation_score": 88,
            "threat_actor": "Lazarus Group",
            "categories": ["Malicious Script", "Execution"]
        },
        "http://194.26.29.112:8080/download/beacon.bin": {
            "reputation_score": 96,
            "threat_actor": "Cobalt Strike Team / RedLine Stealer",
            "categories": ["C2 Beacon", "Stager"]
        },
        "https://login-office365-verify.com/auth": {
            "reputation_score": 89,
            "threat_actor": "Storm-0558",
            "categories": ["Phishing", "OAuth Abuse"]
        }
    }

    KNOWN_CLEAN_URLS: Set[str] = {
        "https://www.google.com",
        "https://github.com",
        "https://microsoft.com",
        "https://www.cloudflare.com"
    }

    KNOWN_MALICIOUS_HASHES: Dict[str, Dict[str, Any]] = {
        # Mimikatz memory dumper (MD5)
        "e1112136104dd25e1f30d37f202f6f51": {
            "reputation_score": 98,
            "threat_actor": "Various APTs / Mimikatz",
            "hash_type": "MD5",
            "file_name": "mimikatz.exe",
            "categories": ["Credential Dumper", "HackTool"]
        },
        # RedLine Stealer executable (SHA256)
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
            "reputation_score": 94,
            "threat_actor": "RedLine Stealer Team",
            "hash_type": "SHA256",
            "file_name": "redline_payload.exe",
            "categories": ["InfoStealer", "Trojan"]
        },
        # WannaCry Ransomware sample (SHA256)
        "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": {
            "reputation_score": 100,
            "threat_actor": "Lazarus Group",
            "hash_type": "SHA256",
            "file_name": "tasksche.exe",
            "categories": ["Ransomware", "Worm"]
        },
        # Cobalt Strike Stager Beacon DLL (MD5)
        "c3ab8ff13720e8ad9047dd39466b3c89": {
            "reputation_score": 95,
            "threat_actor": "Cobalt Strike Team / RedLine Stealer",
            "hash_type": "MD5",
            "file_name": "beacon.dll",
            "categories": ["C2", "Beacon"]
        },
        # Emotet payload dropper (SHA1)
        "7d0eb0b36c2a412b1d035650bf6998634fb685c4": {
            "reputation_score": 92,
            "threat_actor": "Emotet Gang",
            "hash_type": "SHA1",
            "file_name": "doc_payload.vbs",
            "categories": ["Dropper", "Trojan"]
        }
    }

    KNOWN_CLEAN_HASHES: Set[str] = {
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5 empty
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 empty
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # SHA256 empty
    }

    # =====================================================================
    # 2. MITRE ATT&CK PATTERNS & BEHAVIOR MAPPING
    # =====================================================================
    KNOWN_ATTACK_PATTERNS: Dict[str, Dict[str, str]] = {
        "powershell.exe": {
            "mitre_id": "T1059.001",
            "technique": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution"
        },
        "cmd.exe": {
            "mitre_id": "T1059.003",
            "technique": "Command and Scripting Interpreter: Windows Command Shell",
            "tactic": "Execution"
        },
        "scheduled_task": {
            "mitre_id": "T1053.005",
            "technique": "Scheduled Task/Job: Scheduled Task",
            "tactic": "Persistence"
        },
        "schtasks": {
            "mitre_id": "T1053.005",
            "technique": "Scheduled Task/Job: Scheduled Task",
            "tactic": "Persistence"
        },
        "port_scan_syn": {
            "mitre_id": "T1046",
            "technique": "Network Service Discovery",
            "tactic": "Discovery"
        },
        "port_scan": {
            "mitre_id": "T1046",
            "technique": "Network Service Discovery",
            "tactic": "Discovery"
        },
        "phishing_link": {
            "mitre_id": "T1566.002",
            "technique": "Phishing: Spearphishing Link",
            "tactic": "Initial Access"
        },
        "phishing": {
            "mitre_id": "T1566.002",
            "technique": "Phishing: Spearphishing Link",
            "tactic": "Initial Access"
        },
        "mimikatz": {
            "mitre_id": "T1003.001",
            "technique": "OS Credential Dumping: LSASS Memory",
            "tactic": "Credential Access"
        },
        "rundll32": {
            "mitre_id": "T1218.011",
            "technique": "System Binary Proxy Execution: Rundll32",
            "tactic": "Defense Evasion"
        },
        "certutil": {
            "mitre_id": "T1105",
            "technique": "Ingress Tool Transfer",
            "tactic": "Command and Control"
        },
        "whoami": {
            "mitre_id": "T1033",
            "technique": "System Owner/User Discovery",
            "tactic": "Discovery"
        },
        "net user": {
            "mitre_id": "T1087.002",
            "technique": "Account Discovery: Domain Account",
            "tactic": "Discovery"
        },
        "nltest": {
            "mitre_id": "T1018",
            "technique": "Remote System Discovery",
            "tactic": "Discovery"
        },
        "vssadmin": {
            "mitre_id": "T1490",
            "technique": "Inhibit System Recovery",
            "tactic": "Impact"
        },
        "wmic shadowcopy": {
            "mitre_id": "T1490",
            "technique": "Inhibit System Recovery",
            "tactic": "Impact"
        },
        "reg add": {
            "mitre_id": "T1112",
            "technique": "Modify Registry",
            "tactic": "Defense Evasion"
        },
        "bitsadmin": {
            "mitre_id": "T1197",
            "technique": "BITS Jobs",
            "tactic": "Persistence"
        },
        "beacon": {
            "mitre_id": "T1071.001",
            "technique": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control"
        },
        "c2": {
            "mitre_id": "T1071.001",
            "technique": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control"
        }
    }

    # =====================================================================
    # 3. HELPER FUNCTIONS: IP RFC 1918 FILTER & CACHING
    # =====================================================================
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Kiểm tra địa chỉ IP có thuộc dải nội bộ RFC 1918 hoặc Loopback/Link-Local hay không.
        Dải RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, Loopback 127.0.0.1, ::1
        """
        if not ip or not isinstance(ip, str):
            return False
        cleaned_ip = ip.strip()
        # Loại bỏ cổng nếu có dạng 192.168.1.1:8080
        if ":" in cleaned_ip and not cleaned_ip.startswith("[") and cleaned_ip.count(":") == 1:
            cleaned_ip = cleaned_ip.split(":")[0]
        try:
            ip_obj = ipaddress.ip_address(cleaned_ip)
            return bool(
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
            )
        except ValueError:
            return False

    @classmethod
    def _cache_key(cls, ioc_type: str, value: str) -> str:
        """Tạo khóa chuẩn hóa cho bộ nhớ đệm."""
        return f"{ioc_type.strip().upper()}:{value.strip().lower()}"

    @classmethod
    def get_cached(cls, ioc_type: str, value: str) -> Optional[IoCItem]:
        """Lấy kết quả từ bộ nhớ đệm in-memory."""
        key = cls._cache_key(ioc_type, value)
        with cls._cache_lock:
            cached = cls._cache.get(key)
            if cached is not None:
                # Trả về bản sao để tránh đột biến ngoài ý muốn
                return cached.model_copy(deep=True)
            return None

    @classmethod
    def set_cache(cls, ioc_type: str, value: str, item: IoCItem) -> None:
        """Lưu kết quả vào bộ nhớ đệm in-memory."""
        key = cls._cache_key(ioc_type, value)
        with cls._cache_lock:
            cls._cache[key] = item.model_copy(deep=True)

    @classmethod
    def clear_cache(cls) -> None:
        """Xóa toàn bộ bộ nhớ đệm in-memory (phục vụ test)."""
        with cls._cache_lock:
            cls._cache.clear()

    @classmethod
    def get_cache_size(cls) -> int:
        """Lấy số lượng bản ghi hiện có trong cache."""
        with cls._cache_lock:
            return len(cls._cache)

    # =====================================================================
    # 4. LIVE CTI API QUERY (VIRUSTOTAL & ABUSEIPDB) VỚI FALLBACK
    # =====================================================================
    @classmethod
    def _query_virustotal_live(cls, resource_type: str, resource_val: str) -> Optional[Dict[str, Any]]:
        """Tra cứu trực tiếp qua VirusTotal v3 REST API (nếu có API Key trong env)."""
        vt_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
        if not vt_key:
            return None

        endpoint_map = {
            "IP": f"https://www.virustotal.com/api/v3/ip_addresses/{resource_val}",
            "DOMAIN": f"https://www.virustotal.com/api/v3/domains/{resource_val}",
            "HASH": f"https://www.virustotal.com/api/v3/files/{resource_val}",
            "URL": f"https://www.virustotal.com/api/v3/urls/{urllib.parse.quote(resource_val, safe='')}"
        }
        url = endpoint_map.get(resource_type.upper())
        if not url:
            return None

        req = urllib.request.Request(url, headers={"x-apikey": vt_key, "User-Agent": "TLCN-MultiAgent-SOC"})
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else 1
                    rep_score = min(100, int((malicious / max(1, total)) * 100))
                    return {
                        "source": "VirusTotal",
                        "reputation_score": rep_score,
                        "is_malicious": rep_score >= 50 or malicious >= 3,
                        "malicious_votes": malicious,
                        "total_votes": total,
                        "categories": list(attrs.get("categories", {}).values())[:5]
                    }
        except Exception:
            # Fallback im lặng nếu mạng lỗi hoặc API key hết quota
            return None
        return None

    @classmethod
    def _query_abuseipdb_live(cls, ip: str) -> Optional[Dict[str, Any]]:
        """Tra cứu uy tín IP qua AbuseIPDB v2 REST API (nếu có API Key trong env)."""
        abuse_key = os.getenv("ABUSEIPDB_API_KEY")
        if not abuse_key:
            return None

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90"
        req = urllib.request.Request(
            url,
            headers={
                "Key": abuse_key,
                "Accept": "application/json",
                "User-Agent": "TLCN-MultiAgent-SOC"
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8")).get("data", {})
                    abuse_score = int(data.get("abuseConfidenceScore", 0))
                    return {
                        "source": "AbuseIPDB",
                        "reputation_score": abuse_score,
                        "is_malicious": abuse_score >= 50,
                        "country": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "usage_type": data.get("usageType"),
                        "total_reports": data.get("totalReports", 0)
                    }
        except Exception:
            return None
        return None

    # =====================================================================
    # 5. CÁC HÀM TRA CỨU DANH TIẾNG ĐA NGUỒN (LOOKUP FUNCTIONS)
    # =====================================================================
    @classmethod
    def lookup_ip(cls, ip: str, use_cache: bool = True) -> IoCItem:
        """
        Tra cứu danh tiếng IP từ CTI feeds.
        Tự động bỏ qua và đánh dấu an toàn đối với IP Private RFC 1918.
        Hỗ trợ cache in-memory, live API và Mock CTI database.
        """
        cleaned_ip = ip.strip() if ip else ""
        if not cleaned_ip:
            return IoCItem(
                ioc_type="IP",
                value="",
                reputation_score=0,
                is_malicious=False,
                details={"status": "empty_ip"}
            )

        # Kiểm tra tính hợp lệ của định dạng IP
        try:
            ipaddress.ip_address(cleaned_ip)
        except ValueError:
            return IoCItem(
                ioc_type="IP",
                value=cleaned_ip,
                reputation_score=0,
                is_malicious=False,
                details={"status": "invalid_format", "error": f"'{cleaned_ip}' không phải địa chỉ IP hợp lệ"}
            )

        # 1. Kiểm tra cache
        if use_cache:
            cached = cls.get_cached("IP", cleaned_ip)
            if cached is not None:
                return cached

        # 2. Bộ lọc IP Private RFC 1918 (10.x, 192.168.x, 172.16-31.x, Loopback)
        if cls.is_private_ip(cleaned_ip):
            res = IoCItem(
                ioc_type="IP",
                value=cleaned_ip,
                reputation_score=0,
                is_malicious=False,
                details={
                    "status": "private_ip_rfc1918",
                    "is_private": True,
                    "description": "Địa chỉ IP nội bộ RFC 1918 / Loopback. Bỏ qua tra cứu CTI bên ngoài."
                }
            )
            if use_cache:
                cls.set_cache("IP", cleaned_ip, res)
            return res

        # 3. Tra cứu Mock Database
        if cleaned_ip in cls.KNOWN_MALICIOUS_IPS:
            info = cls.KNOWN_MALICIOUS_IPS[cleaned_ip]
            rep_score = info.get("reputation_score", 0)
            res = IoCItem(
                ioc_type="IP",
                value=cleaned_ip,
                reputation_score=rep_score,
                is_malicious=rep_score >= 50,
                threat_actor=info.get("threat_actor"),
                details=info
            )
            if use_cache:
                cls.set_cache("IP", cleaned_ip, res)
            return res

        if cleaned_ip in cls.KNOWN_CLEAN_IPS:
            res = IoCItem(
                ioc_type="IP",
                value=cleaned_ip,
                reputation_score=0,
                is_malicious=False,
                details={"status": "known_clean_ip", "provider": "Whitelisted Public DNS / CDN"}
            )
            if use_cache:
                cls.set_cache("IP", cleaned_ip, res)
            return res

        # 4. Thử tra cứu Live API nếu có cấu hình
        live_res = cls._query_abuseipdb_live(cleaned_ip) or cls._query_virustotal_live("IP", cleaned_ip)
        if live_res is not None:
            res = IoCItem(
                ioc_type="IP",
                value=cleaned_ip,
                reputation_score=live_res.get("reputation_score", 0),
                is_malicious=live_res.get("is_malicious", False),
                threat_actor=live_res.get("threat_actor"),
                details=live_res
            )
            if use_cache:
                cls.set_cache("IP", cleaned_ip, res)
            return res

        # 5. Mặc định IP lạ hoặc chưa có trong CTI feed
        res = IoCItem(
            ioc_type="IP",
            value=cleaned_ip,
            reputation_score=0,
            is_malicious=False,
            details={"status": "clean_or_unknown"}
        )
        if use_cache:
            cls.set_cache("IP", cleaned_ip, res)
        return res

    @classmethod
    def lookup_domain(cls, domain: str, use_cache: bool = True) -> IoCItem:
        """
        Tra cứu danh tiếng Domain từ CTI feeds.
        Hỗ trợ cache in-memory, live API và Mock CTI database.
        """
        cleaned_domain = domain.strip().lower() if domain else ""
        if not cleaned_domain:
            return IoCItem(
                ioc_type="DOMAIN",
                value="",
                reputation_score=0,
                is_malicious=False,
                details={"status": "empty_domain"}
            )

        # Kiểm tra tính hợp lệ của định dạng Domain / URL (không cho phép chuỗi thuần Hash lọt vào)
        domain_pattern = r"^(https?:\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(:\d+)?(\/.*)?$"
        is_hex_hash = (len(cleaned_domain) in (32, 40, 64)) and all(c in "0123456789abcdef" for c in cleaned_domain)
        if is_hex_hash or not re.match(domain_pattern, cleaned_domain):
            return IoCItem(
                ioc_type="DOMAIN",
                value=cleaned_domain,
                reputation_score=0,
                is_malicious=False,
                details={"status": "invalid_format", "error": f"'{cleaned_domain}' không phải định dạng tên miền hoặc URL hợp lệ"}
            )

        if use_cache:
            cached = cls.get_cached("DOMAIN", cleaned_domain)
            if cached is not None:
                return cached

        # Mock lookup
        if cleaned_domain in cls.KNOWN_MALICIOUS_DOMAINS:
            info = cls.KNOWN_MALICIOUS_DOMAINS[cleaned_domain]
            rep_score = info.get("reputation_score", 0)
            res = IoCItem(
                ioc_type="DOMAIN",
                value=cleaned_domain,
                reputation_score=rep_score,
                is_malicious=rep_score >= 50,
                threat_actor=info.get("threat_actor"),
                details=info
            )
            if use_cache:
                cls.set_cache("DOMAIN", cleaned_domain, res)
            return res

        if cleaned_domain in cls.KNOWN_CLEAN_DOMAINS:
            res = IoCItem(
                ioc_type="DOMAIN",
                value=cleaned_domain,
                reputation_score=0,
                is_malicious=False,
                details={"status": "known_clean_domain"}
            )
            if use_cache:
                cls.set_cache("DOMAIN", cleaned_domain, res)
            return res

        # Live API
        live_res = cls._query_virustotal_live("DOMAIN", cleaned_domain)
        if live_res is not None:
            res = IoCItem(
                ioc_type="DOMAIN",
                value=cleaned_domain,
                reputation_score=live_res.get("reputation_score", 0),
                is_malicious=live_res.get("is_malicious", False),
                threat_actor=live_res.get("threat_actor"),
                details=live_res
            )
            if use_cache:
                cls.set_cache("DOMAIN", cleaned_domain, res)
            return res

        res = IoCItem(
            ioc_type="DOMAIN",
            value=cleaned_domain,
            reputation_score=0,
            is_malicious=False,
            details={"status": "clean_or_unknown"}
        )
        if use_cache:
            cls.set_cache("DOMAIN", cleaned_domain, res)
        return res

    @classmethod
    def lookup_url(cls, url: str, use_cache: bool = True) -> IoCItem:
        """
        Tra cứu danh tiếng URL từ CTI feeds.
        Hỗ trợ cache in-memory, live API và Mock CTI database.
        """
        cleaned_url = url.strip() if url else ""
        if not cleaned_url:
            return IoCItem(
                ioc_type="URL",
                value="",
                reputation_score=0,
                is_malicious=False,
                details={"status": "empty_url"}
            )

        if use_cache:
            cached = cls.get_cached("URL", cleaned_url)
            if cached is not None:
                return cached

        # Mock lookup
        if cleaned_url in cls.KNOWN_MALICIOUS_URLS:
            info = cls.KNOWN_MALICIOUS_URLS[cleaned_url]
            rep_score = info.get("reputation_score", 0)
            res = IoCItem(
                ioc_type="URL",
                value=cleaned_url,
                reputation_score=rep_score,
                is_malicious=rep_score >= 50,
                threat_actor=info.get("threat_actor"),
                details=info
            )
            if use_cache:
                cls.set_cache("URL", cleaned_url, res)
            return res

        if cleaned_url in cls.KNOWN_CLEAN_URLS:
            res = IoCItem(
                ioc_type="URL",
                value=cleaned_url,
                reputation_score=0,
                is_malicious=False,
                details={"status": "known_clean_url"}
            )
            if use_cache:
                cls.set_cache("URL", cleaned_url, res)
            return res

        # Live API
        live_res = cls._query_virustotal_live("URL", cleaned_url)
        if live_res is not None:
            res = IoCItem(
                ioc_type="URL",
                value=cleaned_url,
                reputation_score=live_res.get("reputation_score", 0),
                is_malicious=live_res.get("is_malicious", False),
                threat_actor=live_res.get("threat_actor"),
                details=live_res
            )
            if use_cache:
                cls.set_cache("URL", cleaned_url, res)
            return res

        res = IoCItem(
            ioc_type="URL",
            value=cleaned_url,
            reputation_score=0,
            is_malicious=False,
            details={"status": "clean_or_unknown"}
        )
        if use_cache:
            cls.set_cache("URL", cleaned_url, res)
        return res

    @classmethod
    def lookup_hash(cls, file_hash: str, use_cache: bool = True) -> IoCItem:
        """
        Tra cứu danh tiếng File Hash (MD5, SHA1, SHA256) từ CTI feeds.
        Hỗ trợ cache in-memory, live API và Mock CTI database.
        """
        cleaned_hash = file_hash.strip().lower() if file_hash else ""
        if cleaned_hash.startswith("sha256="):
            cleaned_hash = cleaned_hash[7:].strip()
        elif cleaned_hash.startswith("md5="):
            cleaned_hash = cleaned_hash[4:].strip()
        elif cleaned_hash.startswith("sha1="):
            cleaned_hash = cleaned_hash[5:].strip()

        if not cleaned_hash:
            return IoCItem(
                ioc_type="MD5",
                value="",
                reputation_score=0,
                is_malicious=False,
                details={"status": "empty_hash"}
            )

        # Kiểm tra tính hợp lệ của định dạng mã băm hex
        if len(cleaned_hash) not in (32, 40, 64) or not all(c in "0123456789abcdef" for c in cleaned_hash):
            return IoCItem(
                ioc_type="HASH",
                value=cleaned_hash,
                reputation_score=0,
                is_malicious=False,
                details={"status": "invalid_format", "error": f"'{cleaned_hash}' không phải mã băm MD5, SHA1 hoặc SHA256 hợp lệ"}
            )

        # Định dạng loại hash dựa trên độ dài
        if len(cleaned_hash) == 32:
            h_type = "MD5"
        elif len(cleaned_hash) == 40:
            h_type = "SHA1"
        elif len(cleaned_hash) == 64:
            h_type = "SHA256"
        else:
            h_type = "HASH"

        if use_cache:
            cached = cls.get_cached(h_type, cleaned_hash)
            if cached is not None:
                return cached

        # Mock lookup
        if cleaned_hash in cls.KNOWN_MALICIOUS_HASHES:
            info = cls.KNOWN_MALICIOUS_HASHES[cleaned_hash]
            rep_score = info.get("reputation_score", 0)
            res = IoCItem(
                ioc_type=info.get("hash_type", h_type),
                value=cleaned_hash,
                reputation_score=rep_score,
                is_malicious=rep_score >= 50,
                threat_actor=info.get("threat_actor"),
                details=info
            )
            if use_cache:
                cls.set_cache(h_type, cleaned_hash, res)
            return res

        if cleaned_hash in cls.KNOWN_CLEAN_HASHES:
            res = IoCItem(
                ioc_type=h_type,
                value=cleaned_hash,
                reputation_score=0,
                is_malicious=False,
                details={"status": "known_clean_hash"}
            )
            if use_cache:
                cls.set_cache(h_type, cleaned_hash, res)
            return res

        # Live API
        live_res = cls._query_virustotal_live("HASH", cleaned_hash)
        if live_res is not None:
            res = IoCItem(
                ioc_type=h_type,
                value=cleaned_hash,
                reputation_score=live_res.get("reputation_score", 0),
                is_malicious=live_res.get("is_malicious", False),
                threat_actor=live_res.get("threat_actor"),
                details=live_res
            )
            if use_cache:
                cls.set_cache(h_type, cleaned_hash, res)
            return res

        res = IoCItem(
            ioc_type=h_type,
            value=cleaned_hash,
            reputation_score=0,
            is_malicious=False,
            details={"status": "clean_or_unknown"}
        )
        if use_cache:
            cls.set_cache(h_type, cleaned_hash, res)
        return res

    # =====================================================================
    # 6. ÁNH XẠ KỸ THUẬT MITRE ATT&CK
    # =====================================================================
    @classmethod
    def match_mitre_technique(cls, keyword: str) -> List[Dict[str, str]]:
        """Ánh xạ từ khóa hành vi / tiến trình sang kỹ thuật MITRE ATT&CK."""
        if not keyword:
            return []
        results = []
        kw_lower = keyword.lower()
        seen_ids = set()
        for key, pattern in cls.KNOWN_ATTACK_PATTERNS.items():
            if key in kw_lower:
                m_id = pattern["mitre_id"]
                if m_id not in seen_ids:
                    seen_ids.add(m_id)
                    results.append(pattern)
        return results
