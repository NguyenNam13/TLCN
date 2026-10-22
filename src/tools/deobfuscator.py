# -*- coding: utf-8 -*-
"""
src/tools/deobfuscator.py
Module giải mã chuyên sâu và khử obfuscation cho dòng lệnh PowerShell độc hại.
Hỗ trợ:
1. Khử backtick (`) và caret (^) làm rối chữ.
2. Xử lý phép nối chuỗi ('a' + 'b') và toán tử định dạng chuỗi PowerShell ("-f").
3. Giải mã đệ quy Nested Base64 (UTF-16LE, UTF-8, ASCII).
4. Nhận diện và giải nén GzipStream / Deflate Stream nhúng trong Base64 (magic header H4sI... / 1f 8b).
5. Tự động trích xuất các chỉ số xâm phạm (IoCs: IPs, URLs, Domains, Hashes).
"""

import re
import gzip
import zlib
import base64
import ipaddress
from typing import List, Dict, Any, Optional, Tuple, Set
from pydantic import BaseModel, Field


class DeobfuscationResult(BaseModel):
    """Kết quả phân tích và khử làm rối dòng lệnh."""
    original_command: str
    deobfuscated_command: str
    has_obfuscation: bool = False
    layers: List[Dict[str, Any]] = Field(default_factory=list)
    extracted_iocs: Dict[str, List[Dict[str, Any]]] = Field(
        default_factory=lambda: {"ips": [], "urls": [], "domains": [], "hashes": []}
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    def __str__(self) -> str:
        return self.deobfuscated_command


class AdvancedPowerShellDeobfuscator:
    """
    Bộ giải mã làm rối PowerShell chuyên sâu phục vụ điều tra số (Forensic Analysis).
    """

    # Danh sách phần mở rộng tệp tin không phải Domain
    EXCLUDED_DOMAIN_EXTENSIONS = {
        "exe", "dll", "ps1", "bat", "vbs", "cmd", "sh", "py", "tmp",
        "json", "xml", "txt", "log", "zip", "tar", "gz", "rar", "csv", "sys", "bin"
    }

    # Danh sách namespace .NET và keyword phổ biến tránh nhận nhầm là domain
    EXCLUDED_DOMAIN_NAMESPACES = {
        "system.management", "system.net", "system.io", "io.compression",
        "net.webclient", "convert.frombase64string", "net.servicepointmanager",
        "security.cryptography", "webclient.downloadstring", "webclient.downloadfile",
        "windows.forms", "microsoft.win32"
    }

    @classmethod
    def remove_backticks(cls, text: str) -> Tuple[str, bool]:
        """
        Khử ký tự backtick (`) và caret (^) chèn vào giữa các từ khóa PowerShell.
        Ví dụ: p`o`w`e`r`s`h`e`l`l -> powershell, I`E`X -> IEX, d`o`w`n`l`o`a`d -> download.
        """
        if not text:
            return text, False

        modified = False
        result = text

        # 1. Backtick trước chữ cái, số, gạch nối, dollar
        pattern_letter = r"`([a-zA-Z0-9_\-\$])"
        if re.search(pattern_letter, result):
            result = re.sub(pattern_letter, r"\1", result)
            modified = True

        # 2. Backtick trước dấu nháy kép hoặc đơn không chuẩn
        pattern_quotes = r"`(['\"])"
        if re.search(pattern_quotes, result):
            result = re.sub(pattern_quotes, r"\1", result)
            modified = True

        # 3. Caret (^) nếu gọi qua cmd.exe wrapper
        pattern_caret = r"\^([a-zA-Z0-9_\-\$])"
        if re.search(pattern_caret, result):
            result = re.sub(pattern_caret, r"\1", result)
            modified = True

        return result, modified

    @classmethod
    def resolve_string_concatenation(cls, text: str) -> Tuple[str, bool]:
        """
        Nối các chuỗi ký tự bị bẻ nhỏ bằng dấu cộng (+).
        Ví dụ: 'dow' + 'nload' + 'string' -> 'downloadstring'
               "d" + "own" + "load" -> "download"
        """
        if not text or "+" not in text:
            return text, False

        modified = False
        current = text

        # Lặp nối chuỗi cho đến khi không còn cặp nối nào
        for _ in range(10):
            # Nháy đơn với nháy đơn: 'abc' + 'def' -> 'abcdef'
            sub_single = re.sub(r"'([^'\\]*)'\s*\+\s*'([^'\\]*)'", r"'\1\2'", current)
            # Nháy kép với nháy kép: "abc" + "def" -> "abcdef"
            sub_double = re.sub(r'"([^"\\]*)"\s*\+\s*"([^"\\]*)"', r'"\1\2"', sub_single)
            # Nháy đơn với nháy kép: 'abc' + "def" -> 'abcdef'
            sub_mix1 = re.sub(r"'([^'\\]*)'\s*\+\s*\"([^\"\\]*)\"", r"'\1\2'", sub_double)
            # Nháy kép với nháy đơn: "abc" + 'def' -> "abcdef"
            sub_mix2 = re.sub(r"\"([^\"\\]*)\"\s*\+\s*'([^'\\]*)'", r'"\1\2"', sub_mix1)

            if sub_mix2 != current:
                current = sub_mix2
                modified = True
            else:
                break

        return current, modified

    @classmethod
    def resolve_format_operator(cls, text: str) -> Tuple[str, bool]:
        """
        Giải mã toán tử định dạng chuỗi PowerShell (-f).
        Ví dụ: ("{1}{0}" -f 'World','Hello ') -> 'Hello World'
               ("{0}{1}" -f 'down','load') -> 'download'
        """
        if not text or "-f" not in text.lower():
            return text, False

        modified = False
        current = text

        # Pattern: ("{0}{1}..." -f 'arg0', 'arg1', ...)
        format_pattern = r'\(\s*["\']((?:\{[0-9]+\})+?)["\']\s+-f\s+((?:[\'"][^"]*?[\'"]\s*,?\s*)+)\)'

        def replace_format(match: re.Match) -> str:
            nonlocal modified
            template = match.group(1)
            raw_args = match.group(2)

            # Tách các đối số trong dấu nháy
            arg_matches = re.findall(r'[\'"]([^\'"]*?)[\'"]', raw_args)
            if not arg_matches:
                return match.group(0)

            try:
                # Thay thế từng {i} bằng arg tương ứng
                rendered = template
                for idx, val in enumerate(arg_matches):
                    rendered = rendered.replace(f"{{{idx}}}", val)
                modified = True
                return f"'{rendered}'"
            except Exception:
                return match.group(0)

        new_text = re.sub(format_pattern, replace_format, current, flags=re.IGNORECASE)
        return new_text, modified

    @classmethod
    def decompress_stream(cls, raw_bytes: bytes) -> Optional[bytes]:
        """
        Nhận diện và giải nén dữ liệu nén Gzip hoặc Deflate Stream.
        Hỗ trợ:
        - Gzip magic header (0x1f 0x8b)
        - Zlib / Deflate Stream
        - Raw Deflate (không có zlib header - zlib.MAX_WBITS)
        """
        if not raw_bytes or len(raw_bytes) < 4:
            return None

        # 1. Gzip Header Magic Bytes: 1F 8B
        if raw_bytes[:2] == b"\x1f\x8b":
            try:
                return gzip.decompress(raw_bytes)
            except Exception:
                pass

        # 2. Zlib Decompression
        try:
            return zlib.decompress(raw_bytes)
        except Exception:
            pass

        # 3. Raw Deflate (.NET DeflateStream standard: -MAX_WBITS)
        try:
            return zlib.decompress(raw_bytes, -zlib.MAX_WBITS)
        except Exception:
            pass

        # 4. Zlib with Gzip wrapper (16 + MAX_WBITS)
        try:
            return zlib.decompress(raw_bytes, 16 + zlib.MAX_WBITS)
        except Exception:
            pass

        return None

    @classmethod
    def decode_bytes_to_str(cls, raw_bytes: bytes) -> Optional[str]:
        """
        Giải mã chuỗi bytes sang string, tự động phân biệt chuẩn PowerShell (UTF-16LE) và UTF-8/Latin-1.
        """
        if not raw_bytes:
            return None

        # 1. Nếu có chứa null bytes, ưu tiên UTF-16LE (Chuẩn Windows PowerShell)
        if b"\x00" in raw_bytes:
            try:
                decoded = raw_bytes.decode("utf-16le").strip()
                if decoded and any(c.isalnum() for c in decoded):
                    clean = decoded.replace("\x00", "")
                    if clean and all(32 <= ord(c) <= 126 or ord(c) > 127 or c in "\r\n\t" for c in clean):
                        return clean
            except UnicodeDecodeError:
                pass

        # 2. Thử UTF-8 (Ưu tiên nếu không có null bytes)
        try:
            decoded = raw_bytes.decode("utf-8").strip()
            if decoded and any(c.isalnum() for c in decoded):
                printable_count = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
                if printable_count / len(decoded) > 0.8:
                    return decoded
        except UnicodeDecodeError:
            pass

        # 3. Thử UTF-16LE fallback nếu chuỗi hợp lệ
        try:
            decoded = raw_bytes.decode("utf-16le").strip()
            if decoded and any(c.isalnum() for c in decoded):
                printable_count = sum(1 for c in decoded if 32 <= ord(c) <= 126 or c in "\r\n\t")
                if printable_count / len(decoded) > 0.8:
                    return decoded
        except UnicodeDecodeError:
            pass

        # 4. Thử Latin-1 Fallback
        try:
            decoded = raw_bytes.decode("latin-1", errors="ignore").strip()
            printable_ratio = sum(1 for c in decoded if 32 <= ord(c) <= 126 or c in "\r\n\t") / max(len(decoded), 1)
            if printable_ratio > 0.7 and any(c.isalnum() for c in decoded):
                return decoded
        except Exception:
            pass

        return None

    @classmethod
    def decode_base64_string(cls, b64_str: str) -> Tuple[Optional[str], Optional[bytes], str]:
        """
        Giải mã chuỗi Base64 và tự động giải nén Gzip/Deflate nếu phát hiện.
        
        :param b64_str: Chuỗi Base64.
        :return: Tuple (decoded_text, raw_or_decompressed_bytes, type_tag)
        """
        clean_b64 = re.sub(r"\s+", "", b64_str.strip())
        if not clean_b64 or len(clean_b64) < 4:
            return None, None, "empty"

        # Bù padding '=' nếu thiếu
        missing_padding = (4 - len(clean_b64) % 4) % 4
        clean_b64 += "=" * missing_padding

        try:
            raw_bytes = base64.b64decode(clean_b64, validate=False)
        except Exception:
            return None, None, "invalid_base64"

        # Kiểm tra nén Gzip / Deflate
        decompressed_bytes = cls.decompress_stream(raw_bytes)
        if decompressed_bytes:
            decompressed_text = cls.decode_bytes_to_str(decompressed_bytes)
            if decompressed_text:
                return decompressed_text, decompressed_bytes, "gzip_deflate"

        # Giải mã chuỗi bytes thông thường
        plain_text = cls.decode_bytes_to_str(raw_bytes)
        if plain_text:
            return plain_text, raw_bytes, "base64"

        return None, raw_bytes, "binary"

    @classmethod
    def extract_iocs(cls, text: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Trích xuất tự động và toàn diện các chỉ số IoC từ dòng lệnh hoặc kết quả giải mã:
        - IP Addresses (phân loại Public / Private).
        - URLs (chuẩn hóa hxxp, http, https, ftp).
        - Domains (trích từ URL hoặc FQDN độc lập, loại bỏ false positives).
        - Hashes (MD5, SHA1, SHA256).
        """
        iocs: Dict[str, List[Dict[str, Any]]] = {
            "ips": [],
            "urls": [],
            "domains": [],
            "hashes": []
        }
        seen_keys: Set[Tuple[str, str]] = set()

        if not text:
            return iocs

        # 1. Trích xuất URLs (bao gồm cả defanged URLs hxxp://)
        url_pattern = r"(?:https?|ftp|hxxps?):\/\/[a-zA-Z0-9_\-\.:]+(?:\/[^\s'\"`\)\<\>\[\]]*)?"
        for url in re.findall(url_pattern, text, re.IGNORECASE):
            norm_url = re.sub(r"^hxxp", "http", url, flags=re.IGNORECASE).rstrip(".,;'\"`")
            key = ("URL", norm_url.lower())
            if key not in seen_keys:
                seen_keys.add(key)
                iocs["urls"].append({"type": "URL", "value": norm_url})

                # Trích xuất Host/Domain hoặc IP từ URL
                host_match = re.search(r":\/\/([a-zA-Z0-9_\-\.]+)(?::\d+)?", norm_url)
                if host_match:
                    host = host_match.group(1).strip().lower()
                    try:
                        ip_obj = ipaddress.ip_address(host)
                        is_pub = not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
                        ip_key = ("IP", host)
                        if ip_key not in seen_keys:
                            seen_keys.add(ip_key)
                            iocs["ips"].append({"type": "IP", "value": host, "is_public": is_pub})
                    except ValueError:
                        # Là domain
                        if "." in host and not host.endswith(tuple(cls.EXCLUDED_DOMAIN_EXTENSIONS)):
                            dom_key = ("DOMAIN", host)
                            if dom_key not in seen_keys and host not in cls.EXCLUDED_DOMAIN_NAMESPACES:
                                seen_keys.add(dom_key)
                                iocs["domains"].append({"type": "DOMAIN", "value": host})

        # 2. Trích xuất IPv4 độc lập
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        for ip_cand in re.findall(ip_pattern, text):
            try:
                ip_obj = ipaddress.ip_address(ip_cand)
                is_pub = not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast)
                key = ("IP", ip_cand)
                if key not in seen_keys:
                    seen_keys.add(key)
                    iocs["ips"].append({"type": "IP", "value": ip_cand, "is_public": is_pub})
            except ValueError:
                pass

        # 3. Trích xuất Domains độc lập (FQDNs kết thúc bằng TLD thông dụng)
        domain_pattern = r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|biz|info|ru|cn|cc|xyz|top|me|live|club|online|co|us|gov|edu)\b"
        for dom_match in re.finditer(domain_pattern, text, re.IGNORECASE):
            dom = dom_match.group(0).lower().strip()
            # Bỏ qua nếu là số IP hoặc nằm trong danh sách loại trừ
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", dom):
                continue
            ext = dom.split(".")[-1]
            if ext in cls.EXCLUDED_DOMAIN_EXTENSIONS or dom in cls.EXCLUDED_DOMAIN_NAMESPACES:
                continue

            key = ("DOMAIN", dom)
            if key not in seen_keys:
                seen_keys.add(key)
                iocs["domains"].append({"type": "DOMAIN", "value": dom})

        # 4. Trích xuất File Hashes (MD5: 32, SHA1: 40, SHA256: 64)
        hash_pattern = r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
        for h_cand in re.findall(hash_pattern, text):
            h_clean = h_cand.upper()
            h_len = len(h_clean)
            h_type = "MD5" if h_len == 32 else ("SHA1" if h_len == 40 else "SHA256")
            key = (h_type, h_clean)
            if key not in seen_keys:
                seen_keys.add(key)
                iocs["hashes"].append({"type": h_type, "value": h_clean})

        return iocs

    @classmethod
    def deobfuscate(cls, command_line: Optional[str], max_depth: int = 5) -> DeobfuscationResult:
        """
        Quy trình khử làm rối đa tầng hoàn chỉnh:
        1. Khử backticks / carets.
        2. Giải toán tử nối chuỗi (+) và định dạng (-f).
        3. Nhận diện và giải mã đệ quy Base64 / GzipStream / Deflate.
        4. Trích xuất tổng hợp IoCs từ toàn bộ các tầng phân tích.

        :param command_line: Câu lệnh PowerShell ban đầu.
        :param max_depth: Số vòng đệ quy tối đa để tránh vòng lặp vô tận.
        :return: Đối tượng DeobfuscationResult.
        """
        if not command_line:
            return DeobfuscationResult(
                original_command="",
                deobfuscated_command="",
                has_obfuscation=False,
                layers=[],
                extracted_iocs={"ips": [], "urls": [], "domains": [], "hashes": []}
            )

        orig_cmd = command_line.strip()
        current_text = orig_cmd
        layers: List[Dict[str, Any]] = []
        overall_obfuscated = False

        # Thu thập toàn bộ văn bản xuất hiện ở mọi tầng để trích xuất IoCs triệt để
        all_texts_for_iocs = [orig_cmd]

        for depth in range(1, max_depth + 1):
            layer_actions: List[str] = []
            layer_start_text = current_text

            # --- Bước 1: Khử backticks & carets ---
            text_no_ticks, modified_ticks = cls.remove_backticks(current_text)
            if modified_ticks:
                layer_actions.append("remove_backticks")
                current_text = text_no_ticks
                overall_obfuscated = True

            # --- Bước 2: Giải toán tử định dạng (-f) ---
            text_no_fmt, modified_fmt = cls.resolve_format_operator(current_text)
            if modified_fmt:
                layer_actions.append("resolve_format_operator")
                current_text = text_no_fmt
                overall_obfuscated = True

            # --- Bước 3: Nối chuỗi (+) ---
            text_no_concat, modified_concat = cls.resolve_string_concatenation(current_text)
            if modified_concat:
                layer_actions.append("resolve_string_concatenation")
                current_text = text_no_concat
                overall_obfuscated = True

            # --- Bước 4: Phát hiện và giải mã Base64 / GzipStream ---
            decoded_payload: Optional[str] = None
            encoding_type: Optional[str] = None

            # 4a. PowerShell CLI flags: -e, -enc, -encodedcommand, /enc, etc.
            enc_cli_match = re.search(
                r"(?:-|\/)(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]{8,})",
                current_text,
                re.IGNORECASE
            )
            if enc_cli_match:
                b64_candidate = enc_cli_match.group(1)
                dec_str, _, enc_tag = cls.decode_base64_string(b64_candidate)
                if dec_str:
                    decoded_payload = dec_str
                    encoding_type = f"cli_{enc_tag}"

            # 4b. .NET FromBase64String call: FromBase64String('...')
            if not decoded_payload:
                from_b64_match = re.search(
                    r"(?:\[(?:System\.)?Convert\]::)?FromBase64String\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)",
                    current_text,
                    re.IGNORECASE
                )
                if from_b64_match:
                    b64_candidate = from_b64_match.group(1)
                    dec_str, _, enc_tag = cls.decode_base64_string(b64_candidate)
                    if dec_str:
                        decoded_payload = dec_str
                        encoding_type = f"dotnet_{enc_tag}"

            # 4c. Gzip Magic Base64 pattern (H4sI...) độc lập
            if not decoded_payload:
                h4si_match = re.search(r"\b(H4sI[A-Za-z0-9+/=]{16,})\b", current_text)
                if h4si_match:
                    b64_candidate = h4si_match.group(1)
                    dec_str, _, enc_tag = cls.decode_base64_string(b64_candidate)
                    if dec_str:
                        decoded_payload = dec_str
                        encoding_type = f"standalone_{enc_tag}"

            # Nếu phát hiện và giải mã thành công payload Base64 / Gzip
            if decoded_payload and decoded_payload != current_text:
                layer_actions.append(f"decode_{encoding_type}")
                current_text = decoded_payload
                overall_obfuscated = True

            # Ghi nhận log layer nếu có thay đổi
            if layer_actions:
                layers.append({
                    "depth": depth,
                    "actions": layer_actions,
                    "result_snippet": current_text[:200] + ("..." if len(current_text) > 200 else "")
                })
                all_texts_for_iocs.append(current_text)

            # Nếu không có bất kỳ hành động nào trong vòng lặp này, dừng sớm
            if current_text == layer_start_text:
                break

        # Trích xuất IoCs tổng hợp từ toàn bộ chuỗi ban đầu và mọi tầng giải mã
        combined_text = "\n".join(all_texts_for_iocs)
        extracted_iocs = cls.extract_iocs(combined_text)

        return DeobfuscationResult(
            original_command=orig_cmd,
            deobfuscated_command=current_text,
            has_obfuscation=overall_obfuscated,
            layers=layers,
            extracted_iocs=extracted_iocs
        )
