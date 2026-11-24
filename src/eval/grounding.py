# -*- coding: utf-8 -*-
"""
src/eval/grounding.py
100% deterministic, zero-LLM-judge grounding & hallucination auditor for IncidentState.

Scans all agent/LLM-authored narrative fields and action targets:
- `triage_result.summary`
- `rca_result.root_cause_summary`
- `response_strategy_summary`
- `final_report.executive_summary`
- `final_report.detailed_findings`
- `recommended_actions[*].target`

Verifies cited IPv4 addresses, process names / PIDs, MITRE ATT&CK IDs, and file hashes
against observed evidence in `parsed_events`, `raw_logs`, `threat_intel`, `rca_result`,
and optional `rag_kb`, and flags known forbidden fabrications and mismatched severity labels.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from src.core.schemas import ActionType, IncidentStatus
from src.core.state import IncidentState
from src.eval.schemas import GroundingAuditResult

_IPV4_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])"
)
_MITRE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
_PROCESS_EXT_RE = re.compile(
    r"\b([A-Za-z0-9_\-]+\.(?:exe|dll|ps1|bat|cmd|vbs))\b", re.IGNORECASE
)
_PID_RE = re.compile(r"\bPID\s*[:=#]?\s*(\d{2,7})\b", re.IGNORECASE)
_HASH_SHA256_RE = re.compile(r"\b([a-fA-F0-9]{64})\b")
_HASH_SHA1_RE = re.compile(r"\b([a-fA-F0-9]{40})\b")
_HASH_MD5_RE = re.compile(r"\b([a-fA-F0-9]{32})\b")

_SEVERITY_TAG_RE = re.compile(r"\[(CRITICAL|HIGH|MEDIUM|LOW)\]", re.IGNORECASE)
_SEVERITY_LABEL_RE = re.compile(
    r"(?:mức\s*độ(?:\s+nghiêm\s+trọng)?|severity)\s*[:=]\s*\*{0,2}(CRITICAL|HIGH|MEDIUM|LOW)\b",
    re.IGNORECASE,
)

_NEGATION_PREFIX_RE = re.compile(
    r"(?:không(?:\s+(?:có|phát\s+hiện|ghi\s+nhận|liên\s+quan|chứa|bị))?|"
    r"chưa(?:\s+(?:có|phát\s+hiện|ghi\s+nhận))?|"
    r"\bno\b|\bwithout\b|\bnot\b|\bnon-)\s*(?:\w+\s+){0,3}$",
    re.IGNORECASE,
)

_FORBIDDEN_MTTA_8_RE = re.compile(
    r"MTTA\*{0,2}\s*[:=]?\s*\*{0,2}\s*8\s*phút", re.IGNORECASE
)
_LSASS_RE = re.compile(r"\blsass(?:\.exe)?\b", re.IGNORECASE)

# Generic host/process placeholders that do not represent specific fabricated binaries
_BENIGN_PLACEHOLDER_PROCS = {
    "generic_process",
}


def _collect_text_blobs_from_value(val: Any, out: List[str]) -> None:
    if val is None:
        return
    if isinstance(val, str):
        if val.strip():
            out.append(val)
    elif isinstance(val, dict):
        for v in val.values():
            _collect_text_blobs_from_value(v, out)
    elif isinstance(val, (list, tuple, set)):
        for item in val:
            _collect_text_blobs_from_value(item, out)
    elif hasattr(val, "model_dump"):
        _collect_text_blobs_from_value(val.model_dump(), out)


def _normalize_proc_basename(value: str) -> str:
    cleaned = str(value).strip().strip("\"'`")
    cleaned = cleaned.replace("\\", "/")
    if "/" in cleaned:
        cleaned = cleaned.split("/")[-1]
    return cleaned.lower()


def _is_trivial_hex_or_non_hash(token: str) -> bool:
    low = token.lower()
    if len(set(low)) <= 2:
        return True
    if low.isdigit():
        return True
    return False


def _collect_grounding_reference(
    state: IncidentState,
) -> Dict[str, Any]:
    """Collect all grounded evidence sets directly from IncidentState inputs & CTI/RCA."""
    source_texts: List[str] = []
    allowed_ips: Set[str] = set()
    allowed_procs: Set[str] = set()
    allowed_pids: Set[str] = set()
    allowed_mitre_ids: Set[str] = set()
    allowed_hashes: Set[str] = set()

    def _scan_text(txt: Optional[str], include_procs: bool = True) -> None:
        if not txt:
            return
        s = str(txt)
        source_texts.append(s)
        for ip in _IPV4_RE.findall(s):
            allowed_ips.add(ip)
        for mid in _MITRE_RE.findall(s):
            up = mid.upper()
            allowed_mitre_ids.add(up)
            if "." in up:
                allowed_mitre_ids.add(up.split(".")[0])
        if include_procs:
            for proc in _PROCESS_EXT_RE.findall(s):
                allowed_procs.add(proc.lower())
        for pid in _PID_RE.findall(s):
            allowed_pids.add(pid)
        for pid_m in re.findall(r"\[(\d{2,7})\]", s):
            allowed_pids.add(pid_m)
        for h in _HASH_SHA256_RE.findall(s):
            if not _is_trivial_hex_or_non_hash(h):
                allowed_hashes.add(h.lower())
        for h in _HASH_SHA1_RE.findall(s):
            if not _is_trivial_hex_or_non_hash(h):
                allowed_hashes.add(h.lower())
        for h in _HASH_MD5_RE.findall(s):
            if not _is_trivial_hex_or_non_hash(h):
                allowed_hashes.add(h.lower())

    # 1. Raw logs (untrusted input evidence)
    for rlog in state.raw_logs:
        _scan_text(rlog.raw_payload)

    # 2. Parsed events
    for ev in state.parsed_events:
        if ev.source_ip:
            _scan_text(ev.source_ip, include_procs=False)
        if ev.dest_ip:
            _scan_text(ev.dest_ip, include_procs=False)
        if ev.process_name:
            allowed_procs.add(_normalize_proc_basename(ev.process_name))
            source_texts.append(ev.process_name)
        if ev.process_path:
            allowed_procs.add(_normalize_proc_basename(ev.process_path))
            _scan_text(ev.process_path)
        if ev.parent_process:
            allowed_procs.add(_normalize_proc_basename(ev.parent_process))
            source_texts.append(ev.parent_process)
        _scan_text(ev.command_line)
        _scan_text(ev.parent_command_line)
        if ev.file_hash:
            _scan_text(ev.file_hash, include_procs=False)

        raw_attrs = ev.raw_attributes or {}
        attr_blobs: List[str] = []
        _collect_text_blobs_from_value(raw_attrs, attr_blobs)
        for blob in attr_blobs:
            _scan_text(blob)
        for pid_key in (
            "process_id",
            "pid",
            "parent_pid",
            "ppid",
            "mordorProcessId",
            "mordorClientProcessId",
        ):
            pval = raw_attrs.get(pid_key)
            if pval is not None and str(pval).strip():
                allowed_pids.add(str(pval).strip())

    raw_evidence_blob = "\n".join(source_texts)

    # 3. Threat Intel enrichment (IoCs + MITRE techniques + RAG MITRE context)
    if state.threat_intel:
        for ioc in state.threat_intel.extracted_iocs or []:
            _scan_text(ioc.value, include_procs=False)
            det_blobs: List[str] = []
            _collect_text_blobs_from_value(ioc.details, det_blobs)
            for b in det_blobs:
                for ip in _IPV4_RE.findall(b):
                    allowed_ips.add(ip)
                for h in _HASH_SHA256_RE.findall(b) + _HASH_SHA1_RE.findall(b) + _HASH_MD5_RE.findall(b):
                    if not _is_trivial_hex_or_non_hash(h):
                        allowed_hashes.add(h.lower())
        for tid in state.threat_intel.mitre_techniques or []:
            up = str(tid).strip().upper()
            if up:
                allowed_mitre_ids.add(up)
                if "." in up:
                    allowed_mitre_ids.add(up.split(".")[0])
        for ctx in state.threat_intel.rag_mitre_context or []:
            if isinstance(ctx, dict) and ctx.get("technique_id"):
                up = str(ctx["technique_id"]).strip().upper()
                allowed_mitre_ids.add(up)
                if "." in up:
                    allowed_mitre_ids.add(up.split(".")[0])

    # 4. RCA process trees (observed processes & PIDs)
    if state.rca_result:
        for node in state.rca_result.process_tree or []:
            if node.process_name:
                allowed_procs.add(_normalize_proc_basename(node.process_name))
            if node.process_id:
                allowed_pids.add(str(node.process_id).strip())
            if node.parent_id:
                allowed_pids.add(str(node.parent_id).strip())
            _scan_text(node.command_line)
        for hnode in state.rca_result.high_fidelity_tree or []:
            if hnode.process_name:
                allowed_procs.add(_normalize_proc_basename(hnode.process_name))
            if hnode.process_id:
                allowed_pids.add(str(hnode.process_id).strip())
            if hnode.parent_id:
                allowed_pids.add(str(hnode.parent_id).strip())
            _scan_text(hnode.command_line)
            for tid in hnode.mitre_techniques or []:
                up = str(tid).strip().upper()
                if up:
                    allowed_mitre_ids.add(up)

    # 5. Final report mitre mapping? Only if grounded in state evidence, NOT self-bootstrapping unverified IDs.
    return {
        "raw_evidence_blob": raw_evidence_blob,
        "raw_evidence_lower": raw_evidence_blob.lower(),
        "allowed_ips": allowed_ips,
        "allowed_procs": allowed_procs,
        "allowed_pids": allowed_pids,
        "allowed_mitre_ids": allowed_mitre_ids,
        "allowed_hashes": allowed_hashes,
    }


def _mitre_exists_in_rag(tid: str, rag_kb: Optional[Any]) -> bool:
    if rag_kb is None:
        return False
    getter = getattr(rag_kb, "get_mitre_technique", None)
    if callable(getter):
        try:
            if getter(tid) is not None:
                return True
            if "." in tid and getter(tid.split(".")[0]) is not None:
                return True
        except Exception:
            pass
    known = getattr(rag_kb, "known_mitre_ids", None)
    if known and tid in known:
        return True
    return False


def audit_case_grounding(
    state: IncidentState,
    rag_kb: Optional[Any] = None,
) -> GroundingAuditResult:
    """
    100% deterministic, zero-LLM-judge grounding & hallucination checker.

    Audits:
      - `triage_result.summary`
      - `rca_result.root_cause_summary`
      - `response_strategy_summary`
      - `final_report.executive_summary`
      - `final_report.detailed_findings`
      - `recommended_actions[*].target`
    """
    refs = _collect_grounding_reference(state)
    raw_lower: str = refs["raw_evidence_lower"]
    allowed_ips: Set[str] = refs["allowed_ips"]
    allowed_procs: Set[str] = refs["allowed_procs"]
    allowed_pids: Set[str] = refs["allowed_pids"]
    allowed_mitre_ids: Set[str] = refs["allowed_mitre_ids"]
    allowed_hashes: Set[str] = refs["allowed_hashes"]

    # Collect target text segments to audit: (field_label, text)
    segments: List[Tuple[str, str]] = []
    if state.triage_result and state.triage_result.summary:
        segments.append(("triage_result.summary", state.triage_result.summary))
    if state.rca_result and state.rca_result.root_cause_summary:
        segments.append(("rca_result.root_cause_summary", state.rca_result.root_cause_summary))
    if state.response_strategy_summary:
        segments.append(("response_strategy_summary", state.response_strategy_summary))
    if state.final_report:
        if state.final_report.executive_summary:
            segments.append(("final_report.executive_summary", state.final_report.executive_summary))
        if state.final_report.detailed_findings:
            segments.append(("final_report.detailed_findings", state.final_report.detailed_findings))

    action_targets: List[Tuple[str, ActionType, str]] = []
    for idx, act in enumerate(state.recommended_actions or []):
        if act.target and str(act.target).strip():
            action_targets.append((f"recommended_actions[{idx}].target", act.action_type, str(act.target).strip()))

    total_cited = 0
    verified = 0
    ungrounded: List[Dict[str, str]] = []
    forbidden_fabrications: List[str] = []

    seen_citations: Set[Tuple[str, str, str]] = set()

    def _record_entity(field: str, etype: str, value: str, is_ok: bool) -> None:
        nonlocal total_cited, verified
        key = (field, etype, value.lower())
        if key in seen_citations:
            return
        seen_citations.add(key)
        total_cited += 1
        if is_ok:
            verified += 1
        else:
            ungrounded.append({"field": field, "entity_type": etype, "value": value})

    # Audit narrative text segments
    for field, text in segments:
        # 1. IPv4 addresses
        for ip in _IPV4_RE.findall(text):
            _record_entity(field, "ipv4", ip, ip in allowed_ips)

        # 2. Process / executable names (.exe, .dll, .ps1, .bat, .cmd, .vbs)
        for proc in _PROCESS_EXT_RE.findall(text):
            proc_low = proc.lower()
            if proc_low in _BENIGN_PLACEHOLDER_PROCS:
                continue
            # Ignore negated lsass checks handled separately
            is_verified = proc_low in allowed_procs
            _record_entity(field, "process", proc, is_verified)

        # 3. PIDs
        for pid in _PID_RE.findall(text):
            _record_entity(field, "pid", pid, pid in allowed_pids)

        # 4. MITRE IDs
        for mid in _MITRE_RE.findall(text):
            up = mid.upper()
            is_verified = (up in allowed_mitre_ids) or _mitre_exists_in_rag(up, rag_kb)
            _record_entity(field, "mitre_id", up, is_verified)

        # 5. File hashes (64 / 40 / 32 hex) - scan longest first to avoid substring collisions
        matched_spans: List[Tuple[int, int]] = []
        for regex, htype in (
            (_HASH_SHA256_RE, "sha256"),
            (_HASH_SHA1_RE, "sha1"),
            (_HASH_MD5_RE, "md5"),
        ):
            for m in regex.finditer(text):
                span = m.span()
                if any(s <= span[0] and span[1] <= e for s, e in matched_spans):
                    continue
                matched_spans.append(span)
                hval = m.group(1)
                if _is_trivial_hex_or_non_hash(hval):
                    continue
                hlow = hval.lower()
                is_verified = hlow in allowed_hashes or any(hlow in ah for ah in allowed_hashes)
                _record_entity(field, f"hash_{htype}", hval, is_verified)

    # Audit recommended_actions[*].target
    for field, act_type, target in action_targets:
        if _IPV4_RE.fullmatch(target):
            _record_entity(field, "ipv4", target, target in allowed_ips)
        else:
            for ip in _IPV4_RE.findall(target):
                _record_entity(field, "ipv4", ip, ip in allowed_ips)

        if act_type == ActionType.KILL_PROCESS:
            if target.isdigit():
                _record_entity(field, "pid", target, target in allowed_pids)
            else:
                norm_t = _normalize_proc_basename(target)
                if norm_t and norm_t not in _BENIGN_PLACEHOLDER_PROCS:
                    # Check either direct match or process extension match
                    is_ok = (norm_t in allowed_procs) or (norm_t in raw_lower)
                    _record_entity(field, "process", target, is_ok)

    # Forbidden Fabrications Check across all audited text
    all_audited_text = "\n".join(txt for _, txt in segments)
    all_audited_lower = all_audited_text.lower()

    # 1. Hardcoded fabricated currency amounts
    for phrase in ("450.000.000", "450 triệu"):
        if phrase in all_audited_lower and phrase not in raw_lower:
            forbidden_fabrications.append(f"forbidden_currency:{phrase}")

    # 2. Hardcoded fabricated internal IP 172.16.65.143
    if "172.16.65.143" in all_audited_text and "172.16.65.143" not in raw_lower:
        forbidden_fabrications.append("forbidden_ip:172.16.65.143")

    # 3. Hardcoded fabricated MTTA: 8 phút (when not actually in raw evidence or operational_metrics)
    if _FORBIDDEN_MTTA_8_RE.search(all_audited_text):
        op_mtta = ""
        if state.final_report and state.final_report.operational_metrics:
            om = state.final_report.operational_metrics
            op_mtta = str(
                om.get("mtta_display", "")
                if isinstance(om, dict)
                else getattr(om, "mtta_display", "")
            ).lower()
        if "8 phút" not in raw_lower and "8 phút" not in op_mtta:
            forbidden_fabrications.append("forbidden_mtta:MTTA 8 phút")

    # 4. Hardcoded fabricated duration 3h45m
    if "3h45m" in all_audited_lower and "3h45m" not in raw_lower:
        forbidden_fabrications.append("forbidden_duration:3h45m")

    # 5. lsass.exe when absent from events (and no T1003 evidence)
    has_lsass_evidence = (
        "lsass" in raw_lower
        or "lsass.exe" in allowed_procs
        or any(m == "T1003" or m.startswith("T1003.") for m in allowed_mitre_ids)
    )
    if not has_lsass_evidence:
        for m in _LSASS_RE.finditer(all_audited_text):
            prefix = all_audited_text[max(0, m.start() - 48) : m.start()]
            if not _NEGATION_PREFIX_RE.search(prefix):
                forbidden_fabrications.append("forbidden_process:lsass.exe")
                break

    # 6. Mismatched severity labels vs triage_result.severity
    if state.triage_result and state.final_report:
        expected_sev = state.triage_result.severity.value.upper()
        is_closed_fp = (
            state.status == IncidentStatus.CLOSED_FALSE_POSITIVE
            or state.triage_result.is_incident is False
        )
        if state.final_report.severity:
            rep_sev = str(state.final_report.severity).strip().upper()
            if rep_sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} and rep_sev != expected_sev:
                forbidden_fabrications.append(
                    f"mismatched_severity:report={rep_sev}!=triage={expected_sev}"
                )
        if not is_closed_fp:
            title_and_exec = " ".join(
                p
                for p in (
                    state.final_report.incident_title or "",
                    state.final_report.executive_summary or "",
                )
                if p
            )
            for tag_m in _SEVERITY_TAG_RE.finditer(title_and_exec):
                found_sev = tag_m.group(1).upper()
                if found_sev != expected_sev:
                    forbidden_fabrications.append(
                        f"mismatched_severity_tag:[{found_sev}]!=triage={expected_sev}"
                    )
                    break
            for lbl_m in _SEVERITY_LABEL_RE.finditer(title_and_exec):
                found_sev = lbl_m.group(1).upper()
                if found_sev != expected_sev:
                    forbidden_fabrications.append(
                        f"mismatched_severity_label:{found_sev}!=triage={expected_sev}"
                    )
                    break

    if total_cited > 0:
        grounding_rate = round(verified / float(total_cited), 4)
    else:
        grounding_rate = 0.0 if forbidden_fabrications else 1.0

    has_hallucination = bool(ungrounded or forbidden_fabrications)

    return GroundingAuditResult(
        total_cited_entities=total_cited,
        verified_entities=verified,
        ungrounded_entities=ungrounded,
        forbidden_fabrications=forbidden_fabrications,
        grounding_rate=grounding_rate,
        has_hallucination=has_hallucination,
    )
