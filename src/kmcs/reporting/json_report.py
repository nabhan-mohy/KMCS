"""
kmcs.reporting.json_report
==========================

Machine-readable JSON report renderer — the canonical, lossless export of a
KMCS campaign/finding dataset.  Every other format (HTML, Markdown, CSV,
SARIF) is a *view* over data; this module is the full-fidelity document that
downstream tools should consume.

Guarantees
----------
* **Real data only** — built from :class:`~kmcs.reporting.common.ReportSnapshot`
  which is loaded from actual database rows.  Missing values stay ``null`` or
  carry the literal string ``"<unknown>"``; nothing is estimated.
* **Deterministic** — same snapshot + options ⇒ byte-identical output
  (sorted keys, pinned ``generated_at`` via options).
* **Versioned schema** — top level carries ``schema_version`` and
  ``tool`` provenance so consumers can detect drift.
* **Self-verifying** — the document embeds its own SHA-256 content digest
  under ``integrity.digest_of_payload`` computed over the payload with that
  field removed, so tampering is detectable.

Document layout::

    {
      "schema_version": "1.0",
      "tool": {...},
      "report": {"title","generated_at","options"},
      "summary": {...},              # compute_summary() aggregates
      "targets": [...],
      "campaigns": [...],
      "findings": [ {finding..., "crashes": [...] } ],
      "crashes": [...],              # all in-scope crashes (flat index)
      "reproductions": [...],
      "minimizations": [...],
      "corpora": [...],
      "telemetry": [...],
      "regression_tests": [...],
      "evidence_index": {...},
      "warnings": [...],
      "integrity": {"snapshot_digest","digest_of_payload"}
    }
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from kmcs.reporting.common import (
    UNKNOWN,
    RenderResult,
    ReportError,
    ReportOptions,
    ReportSnapshot,
    compute_summary,
    content_hash,
    load_snapshot,
    normalise_severity,
    resolve_out_path,
    stable_json,
    truncate,
    write_report,
)

JSON_SCHEMA_ID = "https://kmcs.local/schemas/report-1.0.json"


# ---------------------------------------------------------------------------
# Document construction
# ---------------------------------------------------------------------------


def _finding_document(finding: Dict[str, Any], crashes_by_id: Dict[str, Dict[str, Any]],
                      repros_by_crash: Dict[str, List[Dict[str, Any]]],
                      mins_by_crash: Dict[str, List[Dict[str, Any]]],
                      options: ReportOptions) -> Dict[str, Any]:
    """Assemble one finding with its linked crash evidence attached."""

    doc: Dict[str, Any] = dict(finding)
    canon = str(finding.get("canonical_crash_id") or "")
    linked_ids: List[str] = []
    if isinstance(finding.get("crash_ids"), list):
        linked_ids = [str(x) for x in finding["crash_ids"]]
    if canon:
        linked_ids.insert(0, canon)
    seen: set[str] = set()
    unique_ids = [i for i in linked_ids if not (i in seen or seen.add(i))]

    crash_views: List[Dict[str, Any]] = []
    for cid in unique_ids:
        c = crashes_by_id.get(cid)
        if c is None:
            crash_views.append({"id": cid, "note": "crash row not present in scope"})
            continue
        crash_views.append(_crash_view(c, options))

    doc["linked_crashes"] = crash_views
    doc["reproduction_records"] = [
        r for cid in unique_ids for r in repros_by_crash.get(cid, [])
    ]
    doc["minimization_records"] = [
        m for cid in unique_ids for m in mins_by_crash.get(cid, [])
    ]
    sev = normalise_severity(finding.get("severity"))
    doc["severity_normalised"] = sev
    return doc


def _crash_view(crash: Dict[str, Any], options: ReportOptions) -> Dict[str, Any]:
    """Crash dict trimmed according to options (stack depth / log preview)."""

    v = dict(crash)
    st = v.get("stack_trace")
    if isinstance(st, list):
        total = len(st)
        v["stack_trace"] = st[: options.max_stack_frames]
        v["stack_frames_total"] = total
        v["stack_frames_truncated"] = max(0, total - options.max_stack_frames)
    if not options.include_raw_sanitizer_output:
        rep = v.get("sanitizer_report")
        if isinstance(rep, dict):
            txt = rep.get("raw_text") or rep.get("text")
            if txt:
                rep = dict(rep)
                rep["raw_text"] = "<omitted by options.include_raw_sanitizer_output=False>"
                rep["raw_text_length"] = len(str(txt))
                v["sanitizer_report"] = rep
    else:
        rep = v.get("sanitizer_report")
        if isinstance(rep, dict):
            for key in ("raw_text", "text"):
                if isinstance(rep.get(key), str):
                    rep[key] = truncate(rep[key], options.max_log_preview)
    return v


def build_document(snap: ReportSnapshot, options: Optional[ReportOptions] = None) -> Dict[str, Any]:
    """Compose the complete JSON report document from *snap*."""

    options = options or ReportOptions()
    summary = compute_summary(snap)

    crashes_by_id = snap.crash_by_id()
    repros_by_crash: Dict[str, List[Dict[str, Any]]] = {}
    for r in snap.reproductions:
        repros_by_crash.setdefault(str(r.get("crash_id")), []).append(dict(r))
    mins_by_crash: Dict[str, List[Dict[str, Any]]] = {}
    for m in snap.minimizations:
        mins_by_crash.setdefault(str(m.get("crash_id")), []).append(dict(m))

    findings_docs = [
        _finding_document(f, crashes_by_id, repros_by_crash, mins_by_crash, options)
        for f in snap.findings
    ]
    crash_docs = [_crash_view(c, options) for c in snap.crashes]

    # evidence index: every file reference mentioned anywhere, deduplicated
    evidence_index: Dict[str, Dict[str, Any]] = {}

    def _note_ref(path: Any, kind: str, owner: str) -> None:
        if not path or str(path) == UNKNOWN:
            return
        key = str(path)
        entry = evidence_index.setdefault(
            key, {"path": key, "kinds": set(), "referenced_by": set()}
        )
        entry["kinds"].add(kind)
        entry["referenced_by"].add(owner)

    for c in snap.crashes:
        _note_ref(c.get("input_path"), "crash-input", f"crash:{c.get('id')}")
        _note_ref(c.get("reproducer_path"), "reproducer", f"crash:{c.get('id')}")
        _note_ref(c.get("minimized_path"), "minimized-input", f"crash:{c.get('id')}")
        _note_ref(c.get("raw_log_path"), "raw-log", f"crash:{c.get('id')}")
    for m in snap.minimizations:
        _note_ref(m.get("original_path"), "original-input", f"minimization:{m.get('id')}")
        _note_ref(m.get("minimized_path"), "minimized-input", f"minimization:{m.get('id')}")
    for t in snap.targets:
        _note_ref(t.get("binary_path"), "target-binary", f"target:{t.get('id')}")
    for ev_list in (f.get("evidence") or [] for f in snap.findings):
        if isinstance(ev_list, list):
            for e in ev_list:
                if isinstance(e, dict):
                    _note_ref(e.get("path"), str(e.get("kind") or "evidence"), "finding-evidence")

    flat_evidence = []
    for entry in sorted(evidence_index.values(), key=lambda x: x["path"]):
        flat_evidence.append(
            {
                "path": entry["path"],
                "kinds": sorted(entry["kinds"]),
                "referenced_by": sorted(entry["referenced_by"]),
            }
        )

    doc: Dict[str, Any] = {
        "schema_version": snap.schema_version,
        "json_schema_id": JSON_SCHEMA_ID,
        "tool": dict(snap.tool),
        "report": {
            "title": options.title or "KMCS Fuzzing & Memory-Safety Report",
            "generated_at": snap.generated_at,
            "format": "json",
            "options": options.model_dump() if hasattr(options, "model_dump") else dict(vars(options)),
        },
        "summary": summary,
        "database_stats": dict(snap.stats),
        "targets": [dict(t) for t in snap.targets],
        "campaigns": [dict(c) for c in snap.campaigns],
        "findings": findings_docs,
        "crashes": crash_docs,
        "reproductions": [dict(r) for r in snap.reproductions],
        "minimizations": [dict(m) for m in snap.minimizations],
        "corpora": [dict(c) for c in snap.corpora],
        "telemetry": [dict(t) for t in snap.telemetry],
        "regression_tests": [dict(r) for r in snap.regressions],
        "evidence_index": flat_evidence,
        "warnings": list(snap.warnings),
        "integrity": {
            "snapshot_digest": snap.digest(),
            "algorithm": "sha256",
        },
    }
    payload_for_digest = stable_json(doc)
    digest = content_hash(payload_for_digest)
    doc["integrity"]["digest_of_payload"] = digest
    return doc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_json_report(
    snap: ReportSnapshot,
    *,
    path: Optional[Any] = None,
    options: Optional[ReportOptions] = None,
    indent: int = 2,
) -> RenderResult:
    """Render *snap* as a JSON document; optionally write atomically to *path*."""

    options = options or ReportOptions()
    doc = build_document(snap, options)
    text = json.dumps(doc, sort_keys=True, indent=indent, ensure_ascii=False,
                      default=lambda o: stable_json.__wrapped__(o) if hasattr(stable_json, "__wrapped__") else str(o))
    # stable_json already handles KMCS types; re-dump using it for fallback parity
    try:
        text = stable_json(doc, indent=indent)
    except (TypeError, ValueError) as exc:
        raise ReportError(f"JSON serialisation failed: {exc}") from exc

    size = len(text.encode("utf-8"))
    out_path: Optional[str] = None
    if path is not None:
        out_path = resolve_out_path(path, "json")
        size = write_report(out_path, text)
    return RenderResult(
        fmt="json",
        path=out_path,
        content_hash=content_hash(text),
        size_bytes=size,
        generated_at=snap.generated_at,
        snapshot_digest=snap.digest(),
        warnings=list(snap.warnings),
    )


def generate_json_report(
    db: Any,
    *,
    path: Optional[Any] = None,
    options: Optional[ReportOptions] = None,
    indent: int = 2,
) -> RenderResult:
    """One-shot: load snapshot from *db*, render JSON, optionally save."""

    options = options or ReportOptions()
    snap = load_snapshot(db, options)
    return render_json_report(snap, path=path, options=options, indent=indent)


def validate_report_document(doc: Dict[str, Any]) -> List[str]:
    """Structural self-check returning a list of problems ([] == valid).

    Verifies required sections, version fields, and recomputes the embedded
    integrity digest.
    """

    problems: List[str] = []
    required = (
        "schema_version", "tool", "report", "summary", "targets", "campaigns",
        "findings", "crashes", "integrity",
    )
    for key in required:
        if key not in doc:
            problems.append(f"missing top-level section: {key!r}")
    integ = doc.get("integrity") or {}
    claimed = integ.get("digest_of_payload")
    if claimed:
        probe = json.loads(json.dumps(doc))
        probe.get("integrity", {}).pop("digest_of_payload", None)
        recomputed = content_hash(stable_json(probe))
        if recomputed != claimed:
            problems.append("integrity digest mismatch — document may be altered")
    for coll in ("findings", "crashes", "targets", "campaigns"):
        items = doc.get(coll)
        if items is not None and not isinstance(items, list):
            problems.append(f"{coll} must be a list")
    counts = (doc.get("summary") or {}).get("counts") or {}
    if isinstance(doc.get("crashes"), list) and counts.get("crashes") != len(doc["crashes"]):
        problems.append(
            f"summary.crashes ({counts.get('crashes')}) != len(crashes) ({len(doc['crashes'])})"
        )
    return problems


__all__ = [
    "JSON_SCHEMA_ID",
    "build_document",
    "render_json_report",
    "generate_json_report",
    "validate_report_document",
]
