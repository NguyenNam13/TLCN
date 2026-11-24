# -*- coding: utf-8 -*-
"""
src/eval/dataset_builder.py
Deterministic stratified builder for the 126-case Phase 4 (P2) SOC Evaluation Benchmark.

Splits (Total = 126 cases):
  1. `wazuh_known` (16 cases, ID): 4 multi-step scenarios from `data/raw/wazuh/*.json`
     + 12 realistic benign / alert-fatigue Wazuh events.
  2. `mordor_public` (22 cases, ID): 1 attack episode window + 1 background benign window
     from each of all 11 files in `data/raw/mordor/*.json` via `PublicDatasetTrainer.load_mordor_file()`.
  3. `loghub_public` (18 cases, ID): 3 attack bursts + 3 normal bursts from each of
     `OpenSSH_2k.log`, `Linux_2k.log`, and `Apache_2k.log` via `PublicDatasetTrainer.load_loghub_file()`.
  4. `ood_unseen` (40 cases, OOD): loaded from `data/eval/ood_unseen_benchmark.jsonl`
     (12 unseen LOLBins, 6 non-enc obfuscation, 4 unseen multi-step chains,
     12 hard benign confounders, and 6 hard-benign SecurityGuard control cases).
  5. `adversarial_injection` (30 cases, OOD/Adversarial): loaded from
     `data/eval/adversarial_injection_benchmark.jsonl`.
"""

from __future__ import annotations

import glob
import json
import os
import random
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Union

from src.core.schemas import (
    ActionType,
    AttackCategory,
    ParsedEvent,
    RawLogInput,
    SeverityLevel,
)
from src.eval.schemas import BenchmarkCase, BenchmarkSplit, GroundTruthLabel
from src.tools.dataset_trainer import PublicDatasetTrainer
from src.tools.dataset_validator import DatasetValidator
from src.tools.wazuh_client import WazuhClientTool

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_FIXED_TS = datetime(2026, 10, 15, 9, 0, 0, tzinfo=timezone.utc)

# Events in Mordor setup/teardown that are noisy or pre-clear artifacts rather than clean background
_MORDOR_BENIGN_SKIP_EIDS = {
    "1",
    "7",
    "8",
    "10",
    "11",
    "12",
    "13",
    "104",
    "1102",
    "4103",
    "4104",
    "4688",
    "4697",
    "4698",
    "7045",
}
_MORDOR_ATTACK_KEYWORDS = (
    "bitsadmin",
    "ntdsutil",
    "vssadmin",
    "dumpert",
    "lsass",
    "fax",
    "sharpview",
    "userinitmprlogonscript",
    "wsman",
    "wsmprovhost",
    "admin$",
    "c$",
    "currentversion\\run",
    "promptforcredential",
    "creduiprompt",
    "httplistener",
    "invoke-",
    "powershell",
    "encodedcommand",
)
_MORDOR_BENIGN_EXCLUDE_KEYWORDS = _MORDOR_ATTACK_KEYWORDS + (
    "mimikatz",
    "cmd.exe",
    "audit log",
    "runonce",
)


def _normalize_splits(
    splits: Optional[Sequence[Union[BenchmarkSplit, str]]],
) -> List[BenchmarkSplit]:
    if splits is None:
        return list(BenchmarkSplit)
    normalized: List[BenchmarkSplit] = []
    for item in splits:
        sp = item if isinstance(item, BenchmarkSplit) else BenchmarkSplit(str(item).strip())
        if sp not in normalized:
            normalized.append(sp)
    return normalized


def _build_wazuh_known_cases(root_dir: str) -> List[BenchmarkCase]:
    """Build 16 ID cases: 4 multi-step scenarios from data/raw/wazuh + 12 benign alert-fatigue events."""
    wazuh_dir = os.path.join(root_dir, "data", "raw", "wazuh")
    scenario_specs: Dict[str, Dict[str, Any]] = {
        "wazuh_alerts_scenario1_phishing.json": {
            "case_id": "WAZUH-ID-01",
            "title": "Wazuh Scenario 1: Password Spray & Domain Credential Access",
            "is_incident": True,
            "severity": SeverityLevel.HIGH,
            "category": AttackCategory.CREDENTIAL_ACCESS,
            "mitre_ids": ["T1110.003", "T1078.002", "T1078", "T1087.002"],
            "patient_zero": None,
            "keywords": ["4625", "4624", "185.220.101.5"],
            "actions": [ActionType.BLOCK_IP, ActionType.REVOKE_USER, ActionType.RESET_PASSWORD],
        },
        "wazuh_alerts_scenario2_malware.json": {
            "case_id": "WAZUH-ID-02",
            "title": "Wazuh Scenario 2: Office Macro PowerShell Encoded Payload & Schtasks Persistence",
            "is_incident": True,
            "severity": SeverityLevel.CRITICAL,
            "category": AttackCategory.MALWARE,
            "mitre_ids": ["T1059.001", "T1027", "T1105", "T1071.001", "T1053.005"],
            "patient_zero": "powershell.exe",
            "keywords": ["winword", "powershell", "schtasks", "194.26.29.112"],
            "actions": [ActionType.ISOLATE_HOST, ActionType.BLOCK_IP, ActionType.KILL_PROCESS],
        },
        "wazuh_alerts_scenario3_network_scan.json": {
            "case_id": "WAZUH-ID-03",
            "title": "Wazuh Scenario 3: Network Sweep, Port Scan & SharpView AD Recon",
            "is_incident": True,
            "severity": SeverityLevel.HIGH,
            "category": AttackCategory.RECONNAISSANCE,
            "mitre_ids": ["T1018", "T1046", "T1595.002"],
            "patient_zero": None,
            "keywords": ["icmp", "syn", "192.168.100.10"],
            "actions": [ActionType.BLOCK_IP, ActionType.ISOLATE_HOST],
        },
        "wazuh_alerts_scenario4_benign.json": {
            "case_id": "WAZUH-ID-04",
            "title": "Wazuh Scenario 4: Routine Interactive Windows Logon (Benign)",
            "is_incident": False,
            "severity": SeverityLevel.LOW,
            "category": AttackCategory.BENIGN,
            "mitre_ids": [],
            "patient_zero": None,
            "keywords": [],
            "actions": [],
        },
    }

    cases: List[BenchmarkCase] = []
    for fname in sorted(scenario_specs.keys()):
        spec = scenario_specs[fname]
        fpath = os.path.join(wazuh_dir, fname)
        val_res = DatasetValidator.validate_file(fpath)
        alerts = val_res.get("alerts", [])
        if not val_res.get("is_valid") or not alerts:
            raise RuntimeError(f"Invalid or empty Wazuh dataset file: {fpath} ({val_res.get('errors')})")

        raw_logs = [
            RawLogInput(
                log_source="WazuhSIEM",
                raw_payload=a.model_dump_json(),
                collected_at=a.timestamp,
            )
            for a in alerts
        ]
        parsed_events = [WazuhClientTool.convert_to_parsed_event(a) for a in alerts]

        cases.append(
            BenchmarkCase(
                case_id=spec["case_id"],
                split=BenchmarkSplit.WAZUH_KNOWN,
                title=spec["title"],
                source_ref=f"data/raw/wazuh/{fname}",
                raw_logs=raw_logs,
                parsed_events=parsed_events,
                ground_truth=GroundTruthLabel(
                    is_incident=spec["is_incident"],
                    expected_severity=spec["severity"],
                    expected_attack_category=spec["category"],
                    expected_mitre_ids=spec["mitre_ids"],
                    expected_patient_zero_process=spec["patient_zero"],
                    expected_initial_access_keywords=spec["keywords"],
                    expected_action_types=spec["actions"],
                ),
                is_in_distribution=True,
                metadata={"alert_count": len(alerts), "source_type": "wazuh_scenario"},
            )
        )

    # 12 realistic benign / alert-fatigue Wazuh events
    benign_templates = [
        ("WAZUH-BEN-01", "Routine Interactive Logon Type 2 (Rule 60100)", "60100", 3,
         "Windows logon success - routine user interactive session", ["windows", "authentication_success"],
         "4624", "WIN10-FIN-02", "CORP\\lminh", "C:\\Windows\\System32\\winlogon.exe",
         "winlogon.exe interactive logon Type 2", "10.10.1.42", None),
        ("WAZUH-BEN-02", "Workstation Unlock Logon Type 7 (Rule 60100)", "60100", 3,
         "Windows logon success - routine workstation unlock", ["windows", "authentication_success"],
         "4624", "WIN10-HR-04", "CORP\\tlan", "C:\\Windows\\System32\\lsass.exe",
         "Routine session unlock LogonType 7", "10.10.1.58", None),
        ("WAZUH-BEN-03", "Windows Update Client Routine Sync", "60100", 3,
         "Routine Windows Update check (wuauclt.exe)", ["windows", "system"],
         "1", "WIN10-WS-11", "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\wuauclt.exe",
         "wuauclt.exe /DetectNow /RunHandlerComServer", "10.10.2.11", None),
        ("WAZUH-BEN-04", "Windows Defender Signature Update", "60100", 3,
         "Routine Windows Defender definition update", ["windows", "antivirus"],
         "1", "WIN10-WS-12", "NT AUTHORITY\\SYSTEM", "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
         "MpCmdRun.exe -SignatureUpdate -MMPC", "10.10.2.12", None),
        ("WAZUH-BEN-05", "Internal File Server Robocopy Backup", "60100", 3,
         "Routine scheduled internal robocopy backup", ["windows", "sysmon"],
         "1", "SRV-FILE-01", "CORP\\svc_backup", "C:\\Windows\\System32\\robocopy.exe",
         "robocopy.exe D:\\Shares\\Finance \\\\10.10.5.10\\Backup\\Finance /MIR /NP", "10.10.5.5", "10.10.5.10"),
        ("WAZUH-BEN-06", "Routine DNS Resolution to Public Resolver 8.8.8.8", "60100", 3,
         "Routine DNS lookup to corporate secondary resolver 8.8.8.8", ["windows", "dns"],
         "22", "WIN10-DEV-03", "CORP\\nhai", "C:\\Windows\\System32\\dns-client.exe",
         "DNS query updates.example.com -> 8.8.8.8", "10.10.4.21", "8.8.8.8"),
        ("WAZUH-BEN-07", "Routine DNS Resolution to Cloudflare 1.1.1.1", "60100", 3,
         "Routine DNS lookup to resolver 1.1.1.1", ["windows", "dns"],
         "22", "WIN10-DEV-06", "CORP\\pthao", "C:\\Windows\\System32\\svchost.exe",
         "DNS query ntp.ubuntu.com -> 1.1.1.1", "10.10.4.29", "1.1.1.1"),
        ("WAZUH-BEN-08", "SSH Key Authentication Success (Rule 5715)", "5715", 3,
         "SSHD authentication success with authorized publickey", ["syslog", "sshd", "authentication_success"],
         "5715", "APP-LNX-01", "deploy", "/usr/sbin/sshd",
         "Accepted publickey for deploy from 10.10.2.15 port 50122 ssh2", "10.10.2.15", None),
        ("WAZUH-BEN-09", "Scheduled Group Policy Refresh (gpupdate)", "60100", 3,
         "Routine Group Policy background refresh", ["windows", "sysmon"],
         "1", "WIN10-WS-18", "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\gpupdate.exe",
         "gpupdate.exe /Target:Computer /Wait:0", "10.10.1.77", None),
        ("WAZUH-BEN-10", "Routine NTP Time Sync Service", "60100", 3,
         "Routine Windows Time Service synchronization", ["windows", "system"],
         "3", "WIN10-WS-22", "NT AUTHORITY\\LOCAL SERVICE", "C:\\Windows\\System32\\svchost.exe",
         "svchost.exe -k LocalService -p -s W32Time", "10.10.1.82", "10.10.0.2"),
        ("WAZUH-BEN-11", "Internal Git Fetch from Corporate GitLab", "60100", 3,
         "Routine developer git fetch from internal repository", ["windows", "sysmon"],
         "1", "DEV-WS-09", "CORP\\vkhanh", "C:\\Program Files\\Git\\cmd\\git.exe",
         "git.exe fetch origin main --prune", "10.10.4.45", "10.10.3.20"),
        ("WAZUH-BEN-12", "Routine User Logoff Event 4634 (Rule 60100)", "60100", 3,
         "Windows user logoff - routine end of shift", ["windows", "authentication_success"],
         "4634", "WIN10-ACC-01", "CORP\\mchau", "C:\\Windows\\System32\\winlogon.exe",
         "Event 4634: An account was logged off", "10.10.1.91", None),
    ]

    for (
        cid,
        title,
        rule_id,
        lvl,
        desc,
        groups,
        eid,
        host,
        user,
        img,
        cmd,
        sip,
        dip,
    ) in benign_templates:
        alert_dict: Dict[str, Any] = {
            "id": f"eval-{cid}",
            "timestamp": _FIXED_TS.isoformat(),
            "rule": {"id": rule_id, "level": lvl, "description": desc, "groups": groups},
            "agent": {"id": "050", "name": host, "ip": sip},
            "full_log": cmd,
            "data": {
                "win": {
                    "system": {"eventID": eid, "computer": host},
                    "eventdata": {
                        "image": img,
                        "commandLine": cmd,
                        "user": user,
                        "sourceIp": sip,
                        **({"destinationIp": dip} if dip else {}),
                    },
                }
            },
        }
        alert_obj = WazuhClientTool.parse_alert_dict(alert_dict)
        parsed_evt = WazuhClientTool.convert_to_parsed_event(alert_obj)
        cases.append(
            BenchmarkCase(
                case_id=cid,
                split=BenchmarkSplit.WAZUH_KNOWN,
                title=title,
                source_ref=f"synthetic_wazuh_benign:{cid}",
                raw_logs=[
                    RawLogInput(
                        log_source="WazuhSIEM",
                        raw_payload=json.dumps(alert_dict, ensure_ascii=False),
                        collected_at=_FIXED_TS,
                    )
                ],
                parsed_events=[parsed_evt],
                ground_truth=GroundTruthLabel(
                    is_incident=False,
                    expected_severity=SeverityLevel.LOW,
                    expected_attack_category=AttackCategory.BENIGN,
                    expected_mitre_ids=[],
                ),
                is_in_distribution=True,
                metadata={"alert_count": 1, "source_type": "wazuh_benign_fatigue"},
            )
        )

    assert len(cases) == 16, f"Expected 16 wazuh_known cases, got {len(cases)}"
    return cases


def _event_blob(ev: ParsedEvent) -> str:
    return " ".join(
        [
            ev.command_line or "",
            ev.process_name or "",
            ev.process_path or "",
            str(ev.raw_attributes.get("target_object", "")),
            str(ev.raw_attributes.get("share_name", "")),
        ]
    ).lower()


def _build_mordor_public_cases(root_dir: str) -> List[BenchmarkCase]:
    """Build 22 ID cases: 1 attack window + 1 benign background window per Mordor file (11 files)."""
    mordor_dir = os.path.join(root_dir, "data", "raw", "mordor")
    mordor_files = sorted(glob.glob(os.path.join(mordor_dir, "*.json")))
    if len(mordor_files) != 11:
        raise RuntimeError(f"Expected 11 Mordor JSONL files in {mordor_dir}, found {len(mordor_files)}")

    cases: List[BenchmarkCase] = []
    for idx, fpath in enumerate(mordor_files, start=1):
        fname = os.path.basename(fpath)
        meta = PublicDatasetTrainer._infer_mordor_scenario_meta(fname)
        all_events = PublicDatasetTrainer.load_mordor_file(fpath, max_events=0, only_suspicious=False)

        atk_events = [
            e
            for e in all_events
            if str(e.event_id) not in {"1102", "104"}
            and any(kw in _event_blob(e) for kw in _MORDOR_ATTACK_KEYWORDS)
        ][:10]
        if not atk_events:
            atk_events = PublicDatasetTrainer.load_mordor_file(fpath, max_events=10, only_suspicious=True)

        ben_events = [
            e
            for e in all_events
            if str(e.event_id) not in _MORDOR_BENIGN_SKIP_EIDS
            and not any(kw in _event_blob(e) for kw in _MORDOR_BENIGN_EXCLUDE_KEYWORDS)
        ][:6]
        if not ben_events:
            ben_events = [e for e in all_events if str(e.event_id) not in {"1102", "104"}][:6]

        cat_str = str(meta.get("attack_category", AttackCategory.MALWARE.value))
        try:
            exp_cat = AttackCategory(cat_str)
        except ValueError:
            exp_cat = AttackCategory.UNKNOWN

        sev = (
            SeverityLevel.CRITICAL
            if any(k in fname.lower() for k in ("lsass", "ntds", "httplistener", "service_mod"))
            else SeverityLevel.HIGH
        )

        # Attack episode window case
        cases.append(
            BenchmarkCase(
                case_id=f"MORDOR-ATK-{idx:02d}",
                split=BenchmarkSplit.MORDOR_PUBLIC,
                title=f"Mordor Attack Window: {meta['scenario_name']}",
                source_ref=f"data/raw/mordor/{fname}",
                raw_logs=[
                    RawLogInput(
                        log_source=e.source_type,
                        raw_payload=json.dumps(
                            {
                                "EventID": e.event_id,
                                "Computer": e.host_name or "WORKSTATION",
                                "User": e.user_name or "SYSTEM",
                                "Image": e.process_path or e.process_name or "",
                                "CommandLine": e.command_line or "",
                                "ParentImage": e.parent_process or "",
                                "SourceIp": e.source_ip,
                                "DestinationIp": e.dest_ip,
                                "Hashes": e.file_hash,
                            },
                            ensure_ascii=False,
                        ),
                        collected_at=e.timestamp,
                    )
                    for e in atk_events
                ],
                parsed_events=atk_events,
                ground_truth=GroundTruthLabel(
                    is_incident=True,
                    expected_severity=sev,
                    expected_attack_category=exp_cat,
                    expected_mitre_ids=list(meta.get("mitre_techniques", [])),
                    expected_patient_zero_process=atk_events[0].process_name if atk_events else None,
                    expected_action_types=[ActionType.KILL_PROCESS, ActionType.ISOLATE_HOST],
                ),
                is_in_distribution=True,
                metadata={"window": "attack_episode", "event_count": len(atk_events), "filename": fname},
            )
        )

        # Background benign window case
        cases.append(
            BenchmarkCase(
                case_id=f"MORDOR-BEN-{idx:02d}",
                split=BenchmarkSplit.MORDOR_PUBLIC,
                title=f"Mordor Background Benign Window ({fname})",
                source_ref=f"data/raw/mordor/{fname}",
                raw_logs=[
                    RawLogInput(
                        log_source=e.source_type,
                        raw_payload=json.dumps(
                            {
                                "EventID": e.event_id,
                                "Computer": e.host_name or "WORKSTATION",
                                "User": e.user_name or "SYSTEM",
                                "Image": e.process_path or e.process_name or "",
                                "CommandLine": e.command_line or "",
                            },
                            ensure_ascii=False,
                        ),
                        collected_at=e.timestamp,
                    )
                    for e in ben_events
                ],
                parsed_events=ben_events,
                ground_truth=GroundTruthLabel(
                    is_incident=False,
                    expected_severity=SeverityLevel.LOW,
                    expected_attack_category=AttackCategory.BENIGN,
                    expected_mitre_ids=[],
                ),
                is_in_distribution=True,
                metadata={"window": "background_benign", "event_count": len(ben_events), "filename": fname},
            )
        )

    assert len(cases) == 22, f"Expected 22 mordor_public cases, got {len(cases)}"
    return cases


def _read_nonempty_lines(fpath: str) -> List[str]:
    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f if ln.strip()]


def _build_loghub_public_cases(root_dir: str) -> List[BenchmarkCase]:
    """Build 18 ID cases: 3 attack bursts + 3 normal bursts per file across OpenSSH, Linux, Apache."""
    loghub_dir = os.path.join(root_dir, "data", "raw", "loghub")
    specs = [
        ("OpenSSH_2k.log", "LinuxSyslog", "SSH"),
        ("Linux_2k.log", "LinuxSyslog", "LNX"),
        ("Apache_2k.log", "WebServer", "WEB"),
    ]

    cases: List[BenchmarkCase] = []
    burst_size = 6

    for fname, log_source, code in specs:
        fpath = os.path.join(loghub_dir, fname)
        meta = PublicDatasetTrainer._infer_loghub_scenario_meta(fname)
        all_events = PublicDatasetTrainer.load_loghub_file(fpath, max_events=0, only_suspicious=False)
        susp_events = PublicDatasetTrainer.load_loghub_file(fpath, max_events=0, only_suspicious=True)
        raw_lines = _read_nonempty_lines(fpath)

        # Partition suspicious events into 3 deterministic attack bursts
        if len(susp_events) < burst_size * 3:
            raise RuntimeError(f"Insufficient suspicious events in {fpath}: {len(susp_events)}")

        step_atk = max(burst_size, len(susp_events) // 3)
        for b_idx in range(3):
            start = b_idx * step_atk
            burst_ev = susp_events[start : start + burst_size]
            burst_raw = [
                RawLogInput(
                    log_source=log_source,
                    raw_payload=(e.command_line or ""),
                    collected_at=e.timestamp,
                )
                for e in burst_ev
            ]
            cat_str = str(meta.get("attack_category", AttackCategory.UNKNOWN.value))
            try:
                exp_cat = AttackCategory(cat_str)
            except ValueError:
                exp_cat = AttackCategory.UNKNOWN

            cases.append(
                BenchmarkCase(
                    case_id=f"LOGHUB-{code}-ATK-{b_idx + 1:02d}",
                    split=BenchmarkSplit.LOGHUB_PUBLIC,
                    title=f"LogHub {fname} Attack Burst #{b_idx + 1}",
                    source_ref=f"data/raw/loghub/{fname}",
                    raw_logs=burst_raw,
                    parsed_events=burst_ev,
                    ground_truth=GroundTruthLabel(
                        is_incident=True,
                        expected_severity=SeverityLevel.HIGH if code != "WEB" else SeverityLevel.MEDIUM,
                        expected_attack_category=exp_cat,
                        expected_mitre_ids=list(meta.get("mitre_techniques", [])),
                        expected_patient_zero_process=burst_ev[0].process_name if burst_ev else None,
                        expected_action_types=[ActionType.BLOCK_IP] if code == "SSH" else [ActionType.PATCH_SYSTEM],
                    ),
                    is_in_distribution=True,
                    metadata={"burst": "attack", "burst_index": b_idx + 1, "filename": fname},
                )
            )

        # Partition normal operational events into 3 deterministic normal bursts
        susp_set = {e.command_line for e in susp_events}
        if code == "SSH":
            # Prefer clean session / non-attack lines when available, else non-suspicious lines
            norm_events = [
                e for e in all_events
                if e.command_line not in susp_set
                and "ignoring max retries" not in (e.command_line or "").lower()
            ]
        elif code == "WEB":
            norm_events = [
                e for e in all_events
                if e.command_line not in susp_set and "[notice]" in (e.command_line or "").lower()
            ]
        else:
            norm_events = [
                e for e in all_events
                if e.command_line not in susp_set
                and "session opened" in (e.command_line or "").lower()
            ]

        if len(norm_events) < burst_size * 3:
            norm_events = [e for e in all_events if e.command_line not in susp_set]

        step_norm = max(1, (len(norm_events) - burst_size) // 3)
        for b_idx in range(3):
            start = min(b_idx * step_norm, max(0, len(norm_events) - burst_size))
            burst_ev = norm_events[start : start + burst_size]
            burst_raw = [
                RawLogInput(
                    log_source=log_source,
                    raw_payload=(e.command_line or raw_lines[0]),
                    collected_at=e.timestamp,
                )
                for e in burst_ev
            ]
            cases.append(
                BenchmarkCase(
                    case_id=f"LOGHUB-{code}-BEN-{b_idx + 1:02d}",
                    split=BenchmarkSplit.LOGHUB_PUBLIC,
                    title=f"LogHub {fname} Normal Operational Burst #{b_idx + 1}",
                    source_ref=f"data/raw/loghub/{fname}",
                    raw_logs=burst_raw,
                    parsed_events=burst_ev,
                    ground_truth=GroundTruthLabel(
                        is_incident=False,
                        expected_severity=SeverityLevel.LOW,
                        expected_attack_category=AttackCategory.BENIGN,
                        expected_mitre_ids=[],
                    ),
                    is_in_distribution=True,
                    metadata={"burst": "normal", "burst_index": b_idx + 1, "filename": fname},
                )
            )

    assert len(cases) == 18, f"Expected 18 loghub_public cases, got {len(cases)}"
    return cases


def _load_jsonl_cases(fpath: str, expected_split: BenchmarkSplit) -> List[BenchmarkCase]:
    if not os.path.exists(fpath):
        raise FileNotFoundError(f"Benchmark JSONL file not found: {fpath}")
    cases: List[BenchmarkCase] = []
    with open(fpath, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            raw = line.strip()
            if not raw:
                continue
            case = BenchmarkCase.model_validate_json(raw)
            if case.split != expected_split:
                raise ValueError(
                    f"Line {line_no} in {fpath} has split={case.split.value}, expected {expected_split.value}"
                )
            cases.append(case)
    return cases


def build_benchmark_dataset(
    splits: Optional[Sequence[Union[BenchmarkSplit, str]]] = None,
    seed: int = 42,
    base_dir: Optional[str] = None,
    shuffle: bool = True,
) -> List[BenchmarkCase]:
    """
    Deterministically build the stratified 126-case benchmark dataset across 5 splits:
      - `wazuh_known`: 16 cases (ID)
      - `mordor_public`: 22 cases (ID)
      - `loghub_public`: 18 cases (ID)
      - `ood_unseen`: 40 cases (OOD, including 6 hard-benign SecurityGuard controls)
      - `adversarial_injection`: 30 cases (Adversarial)

    Supports filtering via `splits` and deterministic RNG shuffling via `seed`.
    """
    rng = random.Random(seed)
    root_dir = base_dir or _REPO_ROOT
    selected = _normalize_splits(splits)

    dataset: List[BenchmarkCase] = []
    for sp in selected:
        if sp == BenchmarkSplit.WAZUH_KNOWN:
            split_cases = _build_wazuh_known_cases(root_dir)
        elif sp == BenchmarkSplit.MORDOR_PUBLIC:
            split_cases = _build_mordor_public_cases(root_dir)
        elif sp == BenchmarkSplit.LOGHUB_PUBLIC:
            split_cases = _build_loghub_public_cases(root_dir)
        elif sp == BenchmarkSplit.OOD_UNSEEN:
            ood_path = os.path.join(root_dir, "data", "eval", "ood_unseen_benchmark.jsonl")
            split_cases = _load_jsonl_cases(ood_path, BenchmarkSplit.OOD_UNSEEN)
            if len(split_cases) != 40:
                raise RuntimeError(f"Expected 40 OOD cases, got {len(split_cases)}")
        elif sp == BenchmarkSplit.ADVERSARIAL_INJECTION:
            adv_path = os.path.join(root_dir, "data", "eval", "adversarial_injection_benchmark.jsonl")
            split_cases = _load_jsonl_cases(adv_path, BenchmarkSplit.ADVERSARIAL_INJECTION)
            if len(split_cases) != 30:
                raise RuntimeError(f"Expected 30 adversarial cases, got {len(split_cases)}")
        else:
            split_cases = []

        if shuffle and len(split_cases) > 1:
            rng.shuffle(split_cases)
        dataset.extend(split_cases)

    if shuffle and len(dataset) > 1:
        rng.shuffle(dataset)

    return dataset
