"""
kmcs.reporting.sarif
====================

SARIF 2.1.0 (Static Analysis Results Interchange Format) renderer for KMCS.

Purpose: feed real fuzzing findings into security-development toolchains —
GitHub Code Scanning, Azure DevOps, VS Code SARIF viewers, defectdojo, etc. —
without inventing anything those tools would display as fact.

Faithfulness contract
---------------------
* One ``run`` per campaign scope (or a single aggregate run), with the driver
  identified by *KMCS's own* name/version from the snapshot's tool block.
* Each **result** is derived from an actual crash/finding row:
  - ``ruleId``   → the recorded crash class (e.g. ``heap-buffer-overflow``)
  - ``level``    → mapped ONLY from the stored severity token
                   (critical/high → error, medium/moderate → warning,
                   low/informational → note, none/unknown → none)
  - locations    → source file/line from the stored sanitizer location or
                   first instrumented stack frame; if absent we attach the
                   *binary artifact* with no region rather than guess lines
  - partialFingerprints → KMCS fingerprint digest (dedup key)
  - codeFlows   → sanitizer stack trace frames (evidence, verbatim)
  - artifacts   → crash input referenced by URI + hash property (never bytes)
* ``originalUriBaseIds`` uses relative workspace roots; absolute machine
  paths are never emitted.
* Missing data ⇒ field omitted (valid SARIF), never fabricated.

Spec: https://sarifweb.azurewebsites.net/ (v2.1.0 OASIS).  This module emits
a strict subset and self-validates structural invariants before returning.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

from kmcs.reporting.common import (
    UNKNOWN,
    RenderResult,
    ReportError,
    ReportOptions,
    ReportSnapshot,
    content_hash,
    cvss_score_from_vector,
    load_snapshot,
    normalise_severity,
    resolve_out_path,
    short_path,
    stable_json,
    truncate,
    write_report,
)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
DRIVER_NAME = "KMCS"
DRIVER_INFO_URL = "https://kmcs.local/"
RULE_ID_PREFIX = "kmcs/"

# severity token -> SARIF result.level
_SEV_TO_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "moderate": "warning",
    "low": "note",
    "informational": "note",
    "none": "none",
}

# CWE ids for well-known memory-safety classes (public reference knowledge —
# this maps a *recorded* crash class to its standard taxonomy entry; it does
# not add any new claims about the finding itself).
_CRASH_CLASS_CWE: Dict[str, Tuple[int, str]] = {
    "heap-buffer-overflow": (787, "Out-of-bounds Write"),
    "heap-buffer-underflow": (125, "Out-of-bounds Read"),
    "stack-buffer-overflow": (787, "Out-of-bounds Write"),
    "stack-buffer-underflow": (125, "Out-of-bounds Read"),
    "global-buffer-overflow": (787, "Out-of-bounds Write"),
    "global-buffer-underflow": (125, "Out-of-bounds Read"),
    "use-after-free": (416, "Use After Free"),
    "use-after-return": (562, "Return of Stack Variable Address"),
    "use-after-scope": (762, "C dangling pointer / use after scope"),
    "double-free": (415, "Double Free"),
    "invalid-free": (590, "Free of Memory not on Heap"),
    "null-dereference": (476, "NULL Pointer Dereference"),
    "memory-leak": (401, "Missing Release of Memory after Effective Lifetime"),
    "integer-overflow": (190, "Integer Overflow or Wraparound"),
    "signed-integer-overflow": (190, "Integer Overflow or Wraparound"),
    "divide-by-zero": (369, "Divide By Zero"),
    "uninitialised-use": (457, "Use of Uninitialized Variable"),
    "data-race": (364, "Signal Handler Race Condition"),
    "timeout": (400, "Uncontrolled Resource Consumption"),
    "segv": (119, "Improper Restriction of Operations within the Bounds of a Memory Buffer"),
    "abort": (662, "Incorrect Synchronization"),  # heuristic taxonomy anchor only when recorded as abort class
    "unknown": (0, "Unknown"),
}


def _rule_id(crash_class: Any) -> str:
    cls = str(crash_class or "unknown").strip().lower().replace(" ", "-")
    cls = re.sub(r"[^a-z0-9\-_.]", "", cls) or "unknown"
    return f"{RULE_ID_PREFIX}{cls}"


def _artifact_uri(path: Any) -> Optional[str]:
    """Relative-style URI for evidence files; None when unrecorded."""

    if not path or str(path) == UNKNOWN:
        return None
    s = str(path)
    s = s.replace("\\", "/")
    if s.startswith(".../"):
        s = s[4:]
    if not s.startswith("/"):
        return s.lstrip("./")
    # absolute path leaked despite redaction: shorten aggressively
    return short_path(s, keep=2).replace(".../", "")


def _location_from_crash(crash: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    loc = crash.get("location")
    if isinstance(loc, dict):
        uri = _artifact_uri(loc.get("file"))
        line = loc.get("line")
        if uri:
            region: Dict[str, Any] = {}
            if isinstance(line, int) and line > 0:
                region["startLine"] = line
            if isinstance(loc.get("column"), int) and loc["column"] > 0:
                region["startColumn"] = loc["column"]
            l: Dict[str, Any] = {"artifactLocation": {"uri": uri}}
            if region:
                l["region"] = region
            fn = loc.get("function")
            if fn:
                l["message"] = {"text": f"recorded fault location in {fn}()"}
            return l
    st = crash.get("stack_trace")
    if isinstance(st, list):
        for fr in st:
            if not isinstance(fr, dict):
                continue
            uri = _artifact_uri(fr.get("file"))
            if uri:
                region = {}
                if isinstance(fr.get("line"), int) and fr["line"] > 0:
                    region["startLine"] = fr["line"]
                l = {"artifactLocation": {"uri": uri}}
                if region:
                    l["region"] = region
                if fr.get("function"):
                    l["message"] = {"text": f"top instrumented frame: {fr['function']}()"}
                return l
    return None


def _binary_location(crash: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    uri = _artifact_uri(crash.get("executable"))
    if not uri:
        return None
    return {"physicalLocation": {"artifactLocation": {"uri": uri}}}


def _thread_flows(crash: Mapping[str, Any], max_frames: int) -> Optional[List[Dict[str, Any]]]:
    st = crash.get("stack_trace")
    if not isinstance(st, list) or not st:
        return None
    locations: List[Dict[str, Any]] = []
    for fr in st[:max_frames]:
        if not isinstance(fr, dict):
            continue
        pl: Dict[str, Any] = {}
        uri = _artifact_uri(fr.get("file")) or _artifact_uri(fr.get("module"))
        if uri:
            pl["artifactLocation"] = {"uri": uri}
            if isinstance(fr.get("line"), int) and fr["line"] > 0:
                pl["region"] = {"startLine": fr["line"]}
        elif fr.get("address"):
            pl["address"] = {"absoluteAddress": int(fr["address"], 16)
                             if isinstance(fr["address"], str) and re.match(r"^0x[0-9a-fA-F]+$", fr["address"])
                             else None}
            pl["address"] = {k: v for k, v in pl["address"].items() if v is not None} or None
        if not pl:
            continue
        entry: Dict[str, Any] = {"location": pl}
        fn = fr.get("function")
        if fn:
            idx = fr.get("index", len(locations))
            entry["location"]["message"] = {"text": f"#{idx} {fn}"}
        locations.append(entry)
    if not locations:
        return None
    return [{"locations": locations}]


def build_sarif(snap: ReportSnapshot, options: Optional[ReportOptions] = None) -> Dict[str, Any]:
    """Compose the full SARIF log object from real snapshot rows."""

    options = options or ReportOptions()
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    artifacts: Dict[str, Dict[str, Any]] = {}

    def register_artifact(uri: Optional[str], role: str, sha: Optional[str] = None,
                          length: Optional[int] = None) -> None:
        if not uri:
            return
        a = artifacts.setdefault(uri, {"location": {"uri": uri}, "roles": set()})
        a["roles"].add(role)
        if sha and re.fullmatch(r"[0-9a-fA-F]{64}", str(sha)):
            a.setdefault("hashes", {})["sha-256"] = str(sha).lower()
        if isinstance(length, int) and length >= 0:
            a["length"] = length

    crashes_by_id = snap.crash_by_id()

    # ---- rules from observed crash classes (only what actually occurred) --
    seen_classes: Dict[str, Dict[str, Any]] = {}
    for c in snap.crashes:
        rid = _rule_id(c.get("crash_class"))
        seen_classes.setdefault(rid, {"class": str(c.get("crash_class") or "unknown"),
                                      "count": 0, "severities": set(), "sanitizers": set()})
        seen_classes[rid]["count"] += 1
        seen_classes[rid]["severities"].add(normalise_severity(c.get("severity")))
        if c.get("sanitizer"):
            seen_classes[rid]["sanitizers"].add(str(c["sanitizer"]))

    for rid, info in sorted(seen_classes.items()):
        cls = info["class"]
        cwe_entry = _CRASH_CLASS_CWE.get(cls.lower())
        rule: Dict[str, Any] = {
            "id": rid,
            "name": cls.upper().replace("-", "_")[:120],
            "shortDescription": {"text": f"Memory-safety crash class: {cls}"},
            "fullDescription": {
                "text": (
                    f"KMCS classified {info['count']} recorded crash(es) as '{cls}' using "
                    f"sanitizer evidence ({', '.join(sorted(info['sanitizers'])) or 'engine-reported'}). "
                    "Severity shown per result comes from KMCS analysis records."
                )
            },
            "helpUri": f"{DRIVER_INFO_URL}classes/{cls}",
            "help": {"text": "Classify remediation priority using the attached sanitizer evidence; "
                             "see KMCS analysis report for triage rationale."},
            "properties": {"tags": ["memory-safety", "fuzzing", "kmcs"]},
        }
        if cwe_entry and cwe_entry[0]:
            rule["properties"]["tags"].append(f"cwe-{cwe_entry[0]}")
            rule["properties"]["cwe"] = {
                "id": cwe_entry[0], "name": cwe_entry[1],
                "source": "MITRE CWE (taxonomy mapping of the recorded crash class)",
            }
        rules[rid] = rule

    # also include rules for findings whose class had no in-scope crash row
    for f in snap.findings:
        rid = _rule_id(f.get("crash_class"))
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": str(f.get("crash_class") or "unknown").upper().replace("-", "_")[:120],
                "shortDescription": {"text": f"Finding class: {f.get('crash_class')}"},
                "fullDescription": {"text": "Rule created from a finding record; no crash rows in current scope."},
                "properties": {"tags": ["memory-safety", "fuzzing", "kmcs"]},
            }

    # ---- results from crashes ---------------------------------------------
    for c in snap.crashes:
        rid = _rule_id(c.get("crash_class"))
        sev = normalise_severity(c.get("severity"))
        level = _SEV_TO_LEVEL.get(sev, "none")
        message_parts = [f"{c.get('crash_class') or 'uncategorised'} crash on target "
                         f"'{c.get('target_name') or UNKNOWN}'"]
        sig = c.get("signal")
        if isinstance(sig, dict) and sig.get("name"):
            message_parts.append(f"signal {sig['name']}")
        mem = c.get("memory_access")
        if isinstance(mem, dict) and mem.get("address"):
            message_parts.append(f"faulting access at {mem['address']}")
        if c.get("occurrence_count"):
            message_parts.append(f"observed {c['occurrence_count']} time(s)")
        res: Dict[str, Any] = {
            "ruleId": rid,
            "ruleIndex": None,  # fixed below
            "level": level,
            "message": {"text": "; ".join(message_parts)},
            "properties": {
                "kmcsCrashId": c.get("id"),
                "kmcsSeverity": sev,
                "kmcsState": c.get("state"),
                "kmcsEngine": c.get("engine"),
                "kmcsSanitizer": c.get("sanitizer"),
                "kmcsExitCode": c.get("exit_code"),
                "kmcsRuntimeMs": c.get("runtime_ms"),
                "confidence": c.get("confidence"),
            },
        }
        res["properties"] = {k: v for k, v in res["properties"].items() if v not in (None, "")}
        fp = c.get("fingerprint_digest")
        if fp:
            res["partialFingerprints"] = {"kmcsFingerprint/v1": str(fp)}
        loc = _location_from_crash(c)
        physical: List[Dict[str, Any]] = []
        if loc:
            physical.append({"physicalLocation": loc})
        binloc = _binary_location(c)
        if binloc:
            physical.append(binloc)
        if physical:
            res["locations"] = physical
        flows = _thread_flows(c, options.max_stack_frames)
        if flows:
            res["codeFlows"] = [{"threadFlows": flows}]
        input_uri = _artifact_uri(c.get("input_path"))
        if input_uri:
            register_artifact(input_uri, "analysisInputFile", c.get("input_hash"), c.get("input_size"))
            res["relatedLocations"] = [{
                "id": 1,
                "location": {"artifactLocation": {"uri": input_uri}},
                "message": {"text": "Reproducer input artefact (stored file; bytes intentionally not embedded)"},
            }]
        if c.get("first_seen_at"):
            res["baselineComplexity"] = None  # placeholder removed below
            res.pop("baselineComplexity", None)
            res["properties"]["firstSeenAt"] = c["first_seen_at"]
        results.append(res)

    # ---- results from findings (deduplicated canonical view) ---------------
    for f in snap.findings:
        rid = _rule_id(f.get("crash_class"))
        sev = normalise_severity(f.get("severity"))
        res: Dict[str, Any] = {
            "ruleId": rid,
            "ruleIndex": None,
            "level": _SEV_TO_LEVEL.get(sev, "none"),
            "message": {"text": truncate(f.get("summary") or f.get("title") or "KMCS finding", 1000)},
            "properties": {
                "kmcsFindingId": f.get("id"),
                "kmcsSeverity": sev,
                "kmcsState": f.get("state"),
                "confidence": f.get("confidence"),
                "canonical": True,
            },
        }
        res["properties"] = {k: v for k, v in res["properties"].items() if v not in (None, "")}
        if f.get("fingerprint_digest"):
            res["partialFingerprints"] = {"kmcsFingerprint/v1": str(f["fingerprint_digest"])}
        if f.get("cvss_vector_hint"):
            score = cvss_score_from_vector(f["cvss_vector_hint"])
            props = res["properties"]
            props["security-severity"] = f"{score:.1f}" if score is not None else "0.0"
            props["cvssVector"] = f["cvss_vector_hint"]
            if score is not None:
                res["rank"] = int(round((10.0 - score) * 10))
        loc = None
        if isinstance(f.get("location"), dict):
            fake = {"location": f["location"], "stack_trace": [], "executable": None}
            loc = _location_from_crash(fake)  # type: ignore[arg-type]
        if loc:
            res["locations"] = [{"physicalLocation": loc}]
        canon = str(f.get("canonical_crash_id") or "")
        if canon and canon in crashes_by_id:
            linked = crashes_by_id[canon]
            if loc is None:
                loc = _location_from_crash(linked)
                if loc:
                    res["locations"] = [{"physicalLocation": loc}]
            res["relatedLocations"] = [{
                "id": 1,
                "location": {"artifactLocation": {"uri": f"kmcs://crash/{canon}"}},
                "message": {"text": "Canonical crash record backing this finding"},
            }]
        if f.get("discovered_at"):
            res["properties"]["discoveredAt"] = f["discovered_at"]
        results.append(res)

    # fix ruleIndex ordering deterministically
    rule_ids = sorted(rules)
    index_of = {rid: i for i, rid in enumerate(rule_ids)}
    for r in results:
        r["index_note"] = None
        r.pop("index_note", None)
        rid = r.get("ruleId")
        if rid in index_of:
            r["ruleIndex"] = index_of[rid]
        else:  # defensive: should not happen
            raise ReportError(f"internal error: rule {rid!r} missing from rule table")

    artifact_list: List[Dict[str, Any]] = []
    for uri in sorted(artifacts):
        a = artifacts[uri]
        entry: Dict[str, Any] = {"location": a["location"]}
        if a.get("hashes"):
            entry["hashes"] = a["hashes"]
        if isinstance(a.get("length"), int):
            entry["length"] = a["length"]
        entry["roles"] = sorted(a["roles"])
        artifact_list.append(entry)

    campaigns = [str(c.get("id")) for c in snap.campaigns]
    invocation: Dict[str, Any] = {
        "commandLine": "kmcs report generate --format sarif",
        "startTimeUtc": None,
        "executionSuccessful": True,
        "toolExecutionNotifications": [
            {"level": "warning", "message": {"text": w}} for w in snap.warnings
        ],
    }
    invocation = {k: v for k, v in invocation.items() if v is not None}

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": DRIVER_NAME,
                "version": snap.tool.get("version", "0.0.0"),
                "semanticVersion": snap.tool.get("version", "0.0.0"),
                "informationUri": DRIVER_INFO_URL,
                "comments": "KMCS — defensive fuzzing & memory-safety research platform. "
                            "Results reflect recorded sanitizer evidence only.",
                "rules": [rules[rid] for rid in rule_ids],
                "supportedContractExtensions": {"microsoft.runSarifValidatorConfig": True},
            }
        },
        "automationDetails": {
            "id": f"kmcs/{(campaigns[0] if campaigns else 'aggregate')}/report",
            "description": {"text": f"KMCS report generated {snap.generated_at}"},
        },
        "results": results,
        "columnKind": "utf16Codes",
        "originalUriBaseIds": {
            "SRCROOT": {"uri": "src/", "description": {"text": "Target source root as recorded at capture time"}},
            "WORKDIR": {"uri": "work/", "description": {"text": "Campaign working directory (redacted layout)"}},
        },
    }
    if artifact_list:
        run["artifacts"] = artifact_list
    if snap.targets:
        run["automationDetails"]["properties"] = {
            "targets": [t.get("name") for t in snap.targets],
            "campaigns": campaigns,
        }
    if invocation.get("toolExecutionNotifications"):
        run["invocations"] = [invocation]

    log = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }
    return log


# ---------------------------------------------------------------------------
# Structural self-validation (subset of SARIF invariants we rely on)
# ---------------------------------------------------------------------------


def validate_sarif(log: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    if log.get("version") != SARIF_VERSION:
        problems.append(f"version must be {SARIF_VERSION!r}")
    if log.get("$schema") != SARIF_SCHEMA_URI:
        problems.append("missing/incorrect $schema")
    runs = log.get("runs")
    if not isinstance(runs, list) or not runs:
        problems.append("runs must be a non-empty array")
        return problems
    for ri, run in enumerate(runs):
        driver = ((run.get("tool") or {}).get("driver") or {})
        if not driver.get("name"):
            problems.append(f"run[{ri}].tool.driver.name missing")
        rules = driver.get("rules") or []
        results = run.get("results") or []
        rule_ids = {r.get("id") for r in rules}
        for x, res in enumerate(results):
            rid = res.get("ruleId")
            if rid not in rule_ids:
                problems.append(f"run[{ri}].result[{x}] references unknown rule {rid!r}")
            idx = res.get("ruleIndex")
            if isinstance(idx, int) and not (0 <= idx < len(rules)):
                problems.append(f"run[{ri}].result[{x}].ruleIndex out of range")
            if res.get("level") not in ("none", "note", "warning", "error"):
                problems.append(f"run[{ri}].result[{x}] bad level {res.get('level')!r}")
            if not (res.get("message") or {}).get("text"):
                problems.append(f"run[{ri}].result[{x}] empty message")
        for a in run.get("artifacts") or []:
            if not ((a.get("location") or {}).get("uri")):
                problems.append(f"run[{ri}] artifact without uri")
    return problems


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_sarif_report(
    snap: ReportSnapshot,
    *,
    path: Optional[Any] = None,
    options: Optional[ReportOptions] = None,
    indent: int = 2,
) -> RenderResult:
    """Render *snap* to SARIF 2.1.0; validates structure before returning."""

    options = options or ReportOptions()
    log = build_sarif(snap, options)
    problems = validate_sarif(log)
    if problems:
        raise ReportError("SARIF self-validation failed: " + "; ".join(problems))
    text = stable_json(log, indent=indent)
    out_path: Optional[str] = None
    size = len(text.encode("utf-8"))
    if path is not None:
        out_path = resolve_out_path(path, "sarif")
        size = write_report(out_path, text)
    return RenderResult(
        fmt="sarif",
        path=out_path,
        content_hash=content_hash(text),
        size_bytes=size,
        generated_at=snap.generated_at,
        snapshot_digest=snap.digest(),
        warnings=list(snap.warnings),
    )


def generate_sarif_report(
    db: Any,
    *,
    path: Optional[Any] = None,
    options: Optional[ReportOptions] = None,
) -> RenderResult:
    options = options or ReportOptions()
    snap = load_snapshot(db, options)
    return render_sarif_report(snap, path=path, options=options)


__all__ = [
    "SARIF_VERSION",
    "SARIF_SCHEMA_URI",
    "DRIVER_NAME",
    "build_sarif",
    "validate_sarif",
    "render_sarif_report",
    "generate_sarif_report",
]
