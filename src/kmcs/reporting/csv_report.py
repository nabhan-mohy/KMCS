"""
kmcs.reporting.csv_report
=========================

Spreadsheet-oriented CSV export of KMCS results.  Designed for triage in
Excel / LibreOffice / Google Sheets and for scripted analysis with pandas or
plain :mod:`csv`.

Layout
------
A single ``.csv`` file is produced per invocation containing **one logical
table**.  Which table is chosen by ``dataset``:

* ``crashes``       — one row per crash record (default; the analyst worklist)
* ``findings``      — one row per security finding
* ``campaigns``     — one row per fuzzing campaign
* ``targets``       — one row per authorised target
* ``reproductions`` — one row per reproduction attempt-set
* ``minimizations`` — one row per minimisation run
* ``corpora``       — one row per corpus
* ``telemetry``     — one row per stored telemetry sample
* ``regressions``   — one row per regression guard test
* ``evidence``      — one row per referenced evidence artefact

Use :func:`generate_csv_bundle` to write *all* datasets at once into a
directory (one file each) plus a ``manifest.json`` describing every file's
SHA-256, size, and row count — useful as an evidence package.

Content rules: values come verbatim from the snapshot (which comes from real
database rows); missing data becomes empty cells; nested structures are
flattened with stable key ordering; all text fields are credential-redacted
and long blobs truncated.  No numbers are ever synthesised.
"""

from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from kmcs.reporting.common import (
    UNKNOWN,
    RenderResult,
    ReportError,
    ReportOptions,
    ReportSnapshot,
    compute_summary,
    content_hash,
    csv_cell,
    load_snapshot,
    normalise_severity,
    resolve_out_path,
    truncate,
    utcnow_iso,
)

# ---------------------------------------------------------------------------
# Dataset schemas: name -> list of (column header, extractor)
# ---------------------------------------------------------------------------

Extractor = Callable[[Dict[str, Any]], Any] if False else Any  # forward alias


def _g(*keys: str, default: Any = "") -> Callable[[Mapping[str, Any]], Any]:
    """Build an extractor that walks alternative keys with fallback."""

    def get(item: Mapping[str, Any]) -> Any:
        for k in keys:
            v = item.get(k)
            if v not in (None, "", [], {}):
                return v
        return default

    return get


def _nested(path: str, sep: str = ".") -> Callable[[Mapping[str, Any]], Any]:
    """Extract ``a.b.c`` from nested dicts, returning '' when absent."""

    parts = path.split(sep)

    def get(item: Mapping[str, Any]) -> Any:
        cur: Any = item
        for p in parts:
            if isinstance(cur, Mapping):
                cur = cur.get(p)
            elif isinstance(cur, (list, tuple)) and p.isdigit():
                idx = int(p)
                cur = cur[idx] if 0 <= idx < len(cur) else None
            else:
                return ""
        return cur if cur is not None else ""

    return get


def _bool(value: Any) -> str:
    if value is None:
        return ""
    return "yes" if bool(value) else "no"


DATASETS: Dict[str, Tuple[str, List[Tuple[str, Extractor]]]] = {
    "crashes": (
        "crash_id",
        [
            ("crash_id", _g("id")),
            ("campaign_id", _g("campaign_id")),
            ("target_id", _g("target_id")),
            ("target_name", _g("target_name")),
            ("executable", _g("executable")),
            ("engine", _g("engine")),
            ("sanitizer", _g("sanitizer")),
            ("crash_class", _g("crash_class")),
            ("state", _g("state")),
            ("severity", lambda i: normalise_severity(i.get("severity"))),
            ("confidence", _g("confidence")),
            ("signal_name", _nested("signal.name")),
            ("signal_number", _nested("signal.number")),
            ("exit_code", _g("exit_code")),
            ("runtime_ms", _g("runtime_ms")),
            ("input_path", _g("input_path")),
            ("input_sha256", _g("input_hash")),
            ("input_size_bytes", _g("input_size")),
            ("fingerprint_digest", _g("fingerprint_digest")),
            ("duplicate_of", _g("duplicate_of")),
            ("occurrence_count", _g("occurrence_count", default=1)),
            ("location_file", _nested("location.file")),
            ("location_line", _nested("location.line")),
            ("location_function", _nested("location.function")),
            ("access_type", _nested("memory_access.access_type")),
            ("access_address", _nested("memory_access.address")),
            ("top_frame", lambda i: (i.get("stack_trace") or [{}])[0].get("function", "")
             if isinstance(i.get("stack_trace"), list) and i.get("stack_trace") else ""),
            ("stack_depth", lambda i: len(i.get("stack_trace") or [])
             if isinstance(i.get("stack_trace"), list) else ""),
            ("finding_id", _g("finding_id")),
            ("reproducer_path", _g("reproducer_path")),
            ("minimized_path", _g("minimized_path")),
            ("raw_log_path", _g("raw_log_path")),
            ("first_seen_at", _g("first_seen_at")),
            ("last_seen_at", _g("last_seen_at")),
            ("notes", lambda i: truncate(i.get("notes") or "", 2000)),
            ("labels", lambda i: ";".join(map(str, i.get("labels") or []))),
        ],
    ),
    "findings": (
        "finding_id",
        [
            ("finding_id", _g("id")),
            ("title", _g("title")),
            ("summary", lambda i: truncate(i.get("summary") or "", 4000)),
            ("target_id", _g("target_id")),
            ("target_name", _g("target_name")),
            ("crash_class", _g("crash_class")),
            ("severity", lambda i: normalise_severity(i.get("severity"))),
            ("confidence", _g("confidence")),
            ("state", _g("state")),
            ("canonical_crash_id", _g("canonical_crash_id")),
            ("crash_ids", lambda i: ";".join(map(str, i.get("crash_ids") or []))),
            ("campaign_ids", lambda i: ";".join(map(str, i.get("campaign_ids") or []))),
            ("fingerprint_digest", _g("fingerprint_digest")),
            ("stack_signature", lambda i: truncate(i.get("stack_signature") or "", 500)),
            ("cvss_vector_hint", _g("cvss_vector_hint")),
            ("affected_versions", lambda i: ";".join(map(str, i.get("affected_versions") or []))),
            ("fixed_in", _g("fixed_in")),
            ("assignee", _g("assignee")),
            ("analyst", _g("analyst")),
            ("discovered_at", _g("discovered_at")),
            ("confirmed_at", _g("confirmed_at")),
            ("reported_at", _g("reported_at")),
            ("closed_at", _g("closed_at")),
            ("updated_at", _g("updated_at")),
            ("labels", lambda i: ";".join(map(str, i.get("labels") or []))),
            ("disclosure_notes", lambda i: truncate(i.get("disclosure_notes") or "", 2000)),
        ],
    ),
    "campaigns": (
        "campaign_id",
        [
            ("campaign_id", _g("id")),
            ("name", _g("name")),
            ("target_id", _g("target_id")),
            ("engine", _g("engine")),
            ("status", _g("status")),
            ("worker_count", _g("worker_count")),
            ("max_runtime_seconds", _g("max_runtime_seconds")),
            ("sanitizers", lambda i: ";".join(map(str, i.get("sanitizers") or []))),
            ("crash_dir", _g("crash_dir")),
            ("work_dir", _g("work_dir")),
            ("owner", _g("owner")),
            ("created_at", _g("created_at")),
            ("started_at", _g("started_at")),
            ("finished_at", _g("finished_at")),
            ("notes", lambda i: truncate(i.get("notes") or "", 2000)),
        ],
    ),
    "targets": (
        "target_id",
        [
            ("target_id", _g("id")),
            ("name", _g("name")),
            ("binary_path", _g("binary_path")),
            ("source_root", _g("source_root")),
            ("kind", _g("kind")),
            ("language", _g("language")),
            ("architecture", _g("architecture")),
            ("operating_system", _g("operating_system")),
            ("upstream_project", _g("upstream_project")),
            ("version", _g("version")),
            ("instrumented", lambda i: _bool(i.get("instrumented"))),
            ("sanitizers_enabled", lambda i: ";".join(map(str, i.get("sanitizers_enabled") or []))),
            ("authorisation_id", _g("authorisation_id")),
            ("tags", lambda i: ";".join(map(str, i.get("tags") or []))),
            ("created_at", _g("created_at")),
            ("updated_at", _g("updated_at")),
        ],
    ),
    "reproductions": (
        "reproduction_id",
        [
            ("reproduction_id", _g("id")),
            ("crash_id", _g("crash_id")),
            ("campaign_id", _g("campaign_id")),
            ("outcome", _g("outcome")),
            ("attempts", _g("attempts")),
            ("successful_attempts", _g("successful_attempts")),
            ("reproducibility_rate", _g("reproducibility_rate")),
            ("duration_seconds", _g("duration_seconds")),
            ("performed_at", _g("performed_at")),
            ("performed_by", _g("performed_by")),
            ("notes", lambda i: truncate(i.get("notes") or "", 2000)),
        ],
    ),
    "minimizations": (
        "minimization_id",
        [
            ("minimization_id", _g("id")),
            ("crash_id", _g("crash_id")),
            ("original_path", _g("original_path")),
            ("original_size", _g("original_size")),
            ("minimized_path", _g("minimized_path")),
            ("minimized_size", _g("minimized_size")),
            ("reduction_ratio", _g("reduction_ratio")),
            ("iterations", _g("iterations")),
            ("strategy", _g("strategy")),
            ("still_crashes", lambda i: _bool(i.get("still_crashes"))),
            ("tool", _g("tool")),
            ("duration_seconds", _g("duration_seconds")),
            ("performed_at", _g("performed_at")),
        ],
    ),
    "corpora": (
        "corpus_id",
        [
            ("corpus_id", _g("id")),
            ("name", _g("name")),
            ("target_id", _g("target_id")),
            ("description", lambda i: truncate(i.get("description") or "", 2000)),
            ("format_hint", _g("format_hint")),
            ("entry_count", _g("entry_count")),
            ("total_bytes", _g("total_bytes")),
            ("tags", lambda i: ";".join(map(str, i.get("tags") or []))),
            ("created_at", _g("created_at")),
            ("updated_at", _g("updated_at")),
        ],
    ),
    "telemetry": (
        "telemetry_id",
        [
            ("telemetry_id", _g("id")),
            ("campaign_id", _g("campaign_id")),
            ("taken_at", _g("taken_at")),
            ("executions", lambda i: (i.get("sample") or {}).get("executions")
             or (i.get("sample") or {}).get("execs_done")
             or (i.get("sample") or {}).get("total_execs") or ""),
            ("execs_per_sec", lambda i: (i.get("sample") or {}).get("execs_per_sec") or ""),
            ("coverage", lambda i: (i.get("sample") or {}).get("coverage")
             or (i.get("sample") or {}).get("cov_edges") or ""),
            ("crashes", lambda i: (i.get("sample") or {}).get("crashes")
             or (i.get("sample") or {}).get("crashes_found") or ""),
            ("sample_json", lambda i: truncate(json.dumps(i.get("sample") or {}, sort_keys=True), 4000)),
        ],
    ),
    "regressions": (
        "regression_test_id",
        [
            ("regression_test_id", _g("id")),
            ("finding_id", _g("finding_id")),
            ("crash_id", _g("crash_id")),
            ("target_id", _g("target_id")),
            ("name", _g("name")),
            ("input_path", _g("input_path")),
            ("input_hash", _g("input_hash")),
            ("expected_signal", _g("expected_signal")),
            ("enabled", lambda i: _bool(i.get("enabled"))),
            ("last_run_at", _g("last_run_at")),
            ("last_outcome", _g("last_outcome")),
            ("pass_count", _g("pass_count")),
            ("fail_count", _g("fail_count")),
        ],
    ),
}


def evidence_rows(snap: ReportSnapshot) -> List[Dict[str, Any]]:
    """Flatten every artefact reference found across the snapshot."""

    index: Dict[str, Dict[str, Any]] = {}

    def add(path: Any, kind: str, owner_kind: str, owner_id: Any, digest: Any = "") -> None:
        if not path or str(path) == UNKNOWN:
            return
        entry = index.setdefault(
            str(path),
            {"path": str(path), "kinds": set(), "owners": set(), "digest": digest or ""},
        )
        entry["kinds"].add(kind)
        entry["owners"].add(f"{owner_kind}:{owner_id}")
        if digest and not entry["digest"]:
            entry["digest"] = digest

    for c in snap.crashes:
        add(c.get("input_path"), "crash-input", "crash", c.get("id"), c.get("input_hash"))
        add(c.get("reproducer_path"), "reproducer", "crash", c.get("id"))
        add(c.get("minimized_path"), "minimized-input", "crash", c.get("id"))
        add(c.get("raw_log_path"), "raw-log", "crash", c.get("id"))
    for m in snap.minimizations:
        add(m.get("original_path"), "original-input", "minimization", m.get("id"))
        add(m.get("minimized_path"), "minimized-input", "minimization", m.get("id"))
    for t in snap.targets:
        add(t.get("binary_path"), "target-binary", "target", t.get("id"))
    for f in snap.findings:
        ev = f.get("evidence")
        if isinstance(ev, list):
            for e in ev:
                if isinstance(e, dict):
                    add(e.get("path"), str(e.get("kind") or "evidence"), "finding",
                        f.get("id"), e.get("content_hash"))
    for g in snap.regressions:
        add(g.get("input_path"), "regression-input", "regression-test", g.get("id"), g.get("input_hash"))

    rows = []
    for entry in sorted(index.values(), key=lambda x: x["path"]):
        rows.append({
            "path": entry["path"],
            "kinds": ";".join(sorted(entry["kinds"])),
            "owners": ";".join(sorted(entry["owners"])),
            "content_hash": entry["digest"],
        })
    return rows


EVIDENCE_SCHEMA = (
    "evidence_path",
    [
        ("path", _g("path")),
        ("kinds", _g("kinds")),
        ("referenced_by", _g("owners")),
        ("content_hash", _g("content_hash")),
    ],
)


# ---------------------------------------------------------------------------
# Core rendering
# ---------------------------------------------------------------------------


def render_dataset(name: str, snap: ReportSnapshot) -> str:
    """Render one named dataset of *snap* as an RFC-4180 CSV string."""

    if name == "evidence":
        key_col, schema = EVIDENCE_SCHEMA
        rows = evidence_rows(snap)
    else:
        if name not in DATASETS:
            raise ReportError(
                f"unknown CSV dataset {name!r}; choose from: "
                + ", ".join(sorted(list(DATASETS) + ["evidence"]))
            )
        key_col, schema = DATASETS[name]
        attr = {
            "crashes": "crashes",
            "findings": "findings",
            "campaigns": "campaigns",
            "targets": "targets",
            "reproductions": "reproductions",
            "minimizations": "minimizations",
            "corpora": "corpora",
            "telemetry": "telemetry",
            "regressions": "regressions",
        }[name]
        rows = getattr(snap, attr)

    buf = io.StringIO(newline="")
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow([col for col, _ in schema])
    for item in rows:
        if not isinstance(item, Mapping):
            item = dict(item)
        writer.writerow([csv_cell(fn(item)) for _, fn in schema])
    return buf.getvalue()


def available_datasets() -> List[str]:
    return sorted(list(DATASETS) + ["evidence"])


def render_csv_report(
    snap: ReportSnapshot,
    *,
    dataset: str = "crashes",
    path: Optional[Any] = None,
    options: Optional[ReportOptions] = None,
) -> RenderResult:
    """Render *snap*'s chosen *dataset* as CSV; optionally save atomically."""

    options = options or ReportOptions()
    text = render_dataset(dataset, snap)
    out_path: Optional[str] = None
    size = len(text.encode("utf-8"))
    if path is not None:
        # keep caller's stem, force .csv
        p = Path(str(path))
        if p.suffix.lower() != ".csv":
            p = p.with_name(p.stem + f".{dataset}.csv")
        out_path = str(p)
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        tmp = out_path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        os.replace(tmp, out_path)
        size = len(text.encode("utf-8"))
    return RenderResult(
        fmt=f"csv:{dataset}",
        path=out_path,
        content_hash=content_hash(text),
        size_bytes=size,
        generated_at=snap.generated_at,
        snapshot_digest=snap.digest(),
        warnings=list(snap.warnings),
    )


def generate_csv_bundle(
    snap: ReportSnapshot,
    directory: Any,
    *,
    options: Optional[ReportOptions] = None,
    datasets: Optional[Sequence[str]] = None,
) -> Dict[str, RenderResult]:
    """Write every dataset to ``<directory>/<name>.csv`` plus manifest.json.

    Returns mapping dataset-name → :class:`RenderResult`.
    """

    options = options or ReportOptions()
    out_dir = Path(str(directory))
    out_dir.mkdir(parents=True, exist_ok=True)
    names = list(datasets) if datasets else available_datasets()
    results: Dict[str, RenderResult] = {}
    manifest: Dict[str, Any] = {
        "generated_at": snap.generated_at,
        "snapshot_digest": snap.digest(),
        "schema_version": snap.schema_version,
        "files": {},
    }
    for name in names:
        text = render_dataset(name, dataset_safe=name) if False else render_dataset(name, snap)
        fpath = out_dir / f"{name}.csv"
        tmp = str(fpath) + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        os.replace(tmp, fpath)
        line_count = max(0, text.count("\r\n") - 1)
        results[name] = RenderResult(
            fmt=f"csv:{name}",
            path=str(fpath),
            content_hash=content_hash(text),
            size_bytes=len(text.encode("utf-8")),
            generated_at=snap.generated_at,
            snapshot_digest=snap.digest(),
        )
        manifest["files"][f"{name}.csv"] = {
            "sha256": results[name].content_hash,
            "bytes": results[name].size_bytes,
            "data_rows": line_count,
        }
    summary = compute_summary(snap)
    manifest["summary"] = summary
    mtext = json.dumps(manifest, sort_keys=True, indent=2)
    (out_dir / "manifest.json").write_text(mtext, encoding="utf-8")
    results["_manifest"] = RenderResult(
        fmt="csv-manifest",
        path=str(out_dir / "manifest.json"),
        content_hash=content_hash(mtext),
        size_bytes=len(mtext.encode("utf-8")),
        generated_at=snap.generated_at,
        snapshot_digest=snap.digest(),
    )
    return results


def generate_csv_report(
    db: Any,
    *,
    path: Optional[Any] = None,
    dataset: str = "crashes",
    options: Optional[ReportOptions] = None,
) -> RenderResult:
    """One-shot convenience: snapshot → CSV → optional save."""

    options = options or ReportOptions()
    snap = load_snapshot(db, options)
    return render_csv_report(snap, dataset=dataset, path=path, options=options)


__all__ = [
    "DATASETS",
    "available_datasets",
    "evidence_rows",
    "render_dataset",
    "render_csv_report",
    "generate_csv_bundle",
    "generate_csv_report",
]
