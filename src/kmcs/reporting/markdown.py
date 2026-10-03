"""
kmcs.reporting.markdown
=======================

Markdown renderer for KMCS results — designed for GitHub/GitLab issues,
README-style security documentation, and diff-friendly storage in version
control.

Content rules (identical to the rest of ``kmcs.reporting``):

* Every number, path, hash, severity, and status is copied from the
  :class:`~kmcs.reporting.common.ReportSnapshot` built from real database
  rows.  Nothing is estimated or hard-coded.
* Unknown values render as ``_not recorded_`` rather than plausible fakes.
* Output is deterministic: same snapshot + options ⇒ identical bytes.
* Defensive framing only: crash inputs are referenced by path/hash/size;
  no payload bytes, no exploit material.

Sections (each toggleable via ``ReportOptions.include_sections``)::

    # Title
    ## Executive summary          - counts table + severity distribution
    ## Targets                    - one block per authorised target
    ## Campaigns                  - run metadata exactly as stored
    ## Findings                   - full finding write-ups w/ evidence links
    ## Crash index                - dedup-aware table of all crashes
    ## Reproduction               - reproducibility outcomes per crash
    ## Minimisation               - size reduction records
    ## Corpora                    - corpus inventory
    ## Telemetry                  - engine counters as recorded
    ## Regression tests           - guard-test inventory
    ## Appendix                   - warnings, integrity, provenance
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

from kmcs.reporting.common import (
    UNKNOWN,
    RenderResult,
    ReportOptions,
    ReportSnapshot,
    compute_summary,
    content_hash,
    load_snapshot,
    normalise_severity,
    resolve_out_path,
    truncate,
    write_report,
)

# ---------------------------------------------------------------------------
# Low-level markdown primitives
# ---------------------------------------------------------------------------

_WS_RE = re.compile(r"\s+")


def md_escape_cell(value: Any) -> str:
    """Make *value* safe inside a GFM table cell."""

    if value is None or value == "":
        return "—"
    s = str(value)
    s = s.replace("\\", "\\\\").replace("|", "\\|")
    s = _WS_RE.sub(" ", s)
    return truncate(s, 240)


def md_heading(text: str, level: int = 2) -> str:
    level = max(1, min(6, level))
    return f"{'#' * level} {text}"


def md_table(headers: Sequence[str], rows: Iterable[Sequence[Any]], *,
             aligns: Optional[Sequence[str]] = None) -> str:
    """Render a GitHub-flavoured markdown table."""

    headers = list(headers)
    if aligns is None:
        aligns = ["left"] * len(headers)
    lines: List[str] = []
    lines.append("| " + " | ".join(md_escape_cell(h) for h in headers) + " |")
    sep_map = {"left": ":---", "right": "---:", "center": ":---:"}
    lines.append("| " + " | ".join(sep_map.get(a, "---") for a in aligns) + " |")
    any_row = False
    for row in rows:
        any_row = True
        cells = [md_escape_cell(c) for c in row]
        # pad short rows so tables never break
        while len(cells) < len(headers):
            cells.append("—")
        lines.append("| " + " | ".join(cells) + " |")
    if not any_row:
        lines.append("| " + " | ".join("*no records*" for _ in headers) + " |")
    return "\n".join(lines)


def md_code_block(text: str, lang: str = "") -> str:
    """Fenced code block with safe fence selection (``` vs ~~~)."""

    text = "" if text is None else str(text)
    fence = "```"
    if "```" in text:
        fence = "~~~"
        if "~~~" in text:
            text = text.replace("~~~", "~~ ~")
    return f"{fence}{lang}\n{text.rstrip()}\n{fence}"


def md_badge(severity: Any) -> str:
    """Inline severity badge using unicode + bold (renders everywhere)."""

    token = normalise_severity(severity)
    icons = {
        "none": "⚪",
        "informational": "🔵",
        "low": "🟢",
        "moderate": "🟡",
        "medium": "🟠",
        "high": "🔴",
        "critical": "⛔",
    }
    return f"{icons.get(token, '⚪')} **{token.capitalize()}**"


def _fmt(value: Any, dash: str = "_not recorded_") -> str:
    if value is None or (isinstance(value, str) and (not value.strip() or value == UNKNOWN)):
        return dash
    return str(value)


def _short_id(ident: Any) -> str:
    s = str(ident or "")
    return s[:8] + "…" if len(s) > 9 else (s or "—")


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def section_summary(snap: ReportSnapshot, summary: Dict[str, Any]) -> str:
    counts = summary["counts"]
    parts: List[str] = [md_heading("Executive Summary"), ""]
    parts.append(
        "| Metric | Value |\n| :--- | ---: |\n"
        + "\n".join(
            f"| {k.replace('_', ' ').capitalize()} | {v} |"
            for k, v in sorted(counts.items())
        )
    )
    parts.append("")
    highest = summary.get("highest_observed_severity") or "none"
    parts.append(f"- Highest observed severity in scope: {md_badge(highest)}")
    execs = (summary.get("execution_totals") or {}).get("executions")
    prov = (summary.get("execution_totals") or {}).get("provenance")
    if execs is not None:
        parts.append(f"- Engine executions recorded: **{execs:,}** ({prov})")
    else:
        parts.append(f"- Engine executions: _not recorded_ ({prov})")
    repro = summary.get("reproduction") or {}
    if repro.get("attempts_total"):
        rate = repro.get("rate")
        rate_txt = f"{rate:.1%}" if isinstance(rate, float) else "n/a"
        parts.append(
            f"- Reproduction attempts: {repro['attempts_total']} "
            f"({repro['successes_total']} reproduced → {rate_txt})"
        )
    else:
        parts.append("- Reproduction attempts: _none recorded_")
    if summary.get("crash_class_breakdown"):
        parts += ["", "### Crash classes observed", "",
                  md_table(["Class", "Count"],
                           [(k, v) for k, v in sorted(summary["crash_class_breakdown"].items(),
                                                      key=lambda kv: (-kv[1], kv[0]))])]
    if summary.get("sanitizer_breakdown"):
        parts += ["", "### Sanitizer coverage of findings", "",
                  md_table(["Sanitizer", "Crashes"],
                           sorted(summary["sanitizer_breakdown"].items()))]
    return "\n".join(parts)


def section_targets(snap: ReportSnapshot) -> str:
    parts: List[str] = [md_heading("Targets"), ""]
    if not snap.targets:
        parts.append("_No targets registered._")
        return "\n".join(parts)
    for t in snap.targets:
        parts.append(f"### {_fmt(t.get('name'))}")
        parts.append("")
        rows = [
            ("Target ID", f"`{_short_id(t.get('id'))}`"),
            ("Binary", f"`{_fmt(t.get('binary_path'))}`"),
            ("Source root", f"`{_fmt(t.get('source_root'))}`"),
            ("Language / kind", f"{_fmt(t.get('language'))} / {_fmt(t.get('kind'))}"),
            ("Architecture", _fmt(t.get("architecture"))),
            ("Version", _fmt(t.get("version"))),
            ("Upstream", _fmt(t.get("upstream_project"))),
            ("Instrumented", "yes" if t.get("instrumented") else "no"),
            ("Sanitizers enabled", _fmt(", ".join(map(str, t.get("sanitizers_enabled") or [])) or None)),
            ("Authorisation", f"`{_short_id(t.get('authorisation_id'))}`"),
        ]
        parts.append(md_table(["Field", "Value"], rows))
        tags = t.get("tags")
        if tags:
            parts += ["", f"Tags: " + ", ".join(f"`{x}`" for x in tags)]
        parts.append("")
    return "\n".join(parts)


def section_campaigns(snap: ReportSnapshot) -> str:
    parts: List[str] = [md_heading("Campaigns"), ""]
    if not snap.campaigns:
        parts.append("_No campaigns recorded._")
        return "\n".join(parts)
    rows = []
    for c in snap.campaigns:
        dur = "—"
        if c.get("started_at") and c.get("finished_at"):
            dur = f"{c['started_at']} → {c['finished_at']}"
        rows.append((
            f"`{_short_id(c.get('id'))}`", c.get("name"), c.get("engine"),
            c.get("status"), c.get("worker_count"), dur,
        ))
    parts.append(md_table(
        ["ID", "Name", "Engine", "Status", "Workers", "Window"], rows,
        aligns=["left", "left", "left", "left", "right", "left"]))
    parts += ["", "> All campaign fields above are copied verbatim from stored "
              "campaign records; durations are timestamps, not estimates."]
    return "\n".join(parts)


def _stack_markdown(frames: Any, max_frames: int) -> str:
    if not isinstance(frames, list) or not frames:
        return "_stack trace not recorded_"
    lines: List[str] = []
    shown = frames[:max_frames]
    for fr in shown:
        if isinstance(fr, dict):
            idx = fr.get("index", fr.get("frame_index", "?"))
            fn = fr.get("function") or "?"
            loc = fr.get("file")
            line = fr.get("line")
            where = f" ({loc}:{line})" if loc and line else (f" ({loc})" if loc else "")
            addr = fr.get("address")
            addr_txt = f" [{addr}]" if addr else ""
            lines.append(f"#{idx} {fn}{where}{addr_txt}")
        else:
            lines.append(str(fr))
    if len(frames) > len(shown):
        lines.append(f"… {len(frames) - len(shown)} additional frame(s) omitted")
    return md_code_block("\n".join(lines), "text")


def section_findings(snap: ReportSnapshot, options: ReportOptions) -> str:
    parts: List[str] = [md_heading("Findings"), ""]
    if not snap.findings:
        parts.append("_No findings have been created yet._")
        return "\n".join(parts)
    crashes_by_id = snap.crash_by_id()
    repros_by_crash: Dict[str, List[Dict[str, Any]]] = {}
    for r in snap.reproductions:
        repros_by_crash.setdefault(str(r.get("crash_id")), []).append(r)
    mins_by_crash: Dict[str, List[Dict[str, Any]]] = {}
    for m in snap.minimizations:
        mins_by_crash.setdefault(str(m.get("crash_id")), []).append(m)

    ordered = sorted(snap.findings,
                     key=lambda f: (-_sev_rank(f.get("severity")), str(f.get("discovered_at") or "")))
    for n, f in enumerate(ordered, 1):
        sev = normalise_severity(f.get("severity"))
        title = _fmt(f.get("title"), dash="Untitled finding")
        parts.append(f"### {n}. {title}  {md_badge(sev)}")
        parts.append("")
        meta_rows = [
            ("Finding ID", f"`{_short_id(f.get('id'))}`"),
            ("State", f.get("state")),
            ("Crash class", f"`{_fmt(f.get('crash_class'))}`"),
            ("Confidence", f.get("confidence")),
            ("Target", _fmt(f.get("target_name"))),
            ("Discovered", _fmt(f.get("discovered_at"))),
            ("Confirmed", _fmt(f.get("confirmed_at"))),
            ("Analyst", _fmt(f.get("analyst") or f.get("assignee"))),
            ("Fixed in", _fmt(f.get("fixed_in"))),
        ]
        cvss_hint = f.get("cvss_vector_hint")
        if cvss_hint:
            meta_rows.append(("CVSS vector hint", f"`{cvss_hint}`"))
        parts.append(md_table(["Field", "Value"], meta_rows))
        if f.get("summary"):
            parts += ["", "**Summary.** " + str(f["summary"])]
        if f.get("description"):
            parts += ["", "**Details.**", "", str(f["description"])]
        hints = f.get("root_cause_hints")
        if isinstance(hints, list) and hints:
            parts += ["", "**Root-cause hints (analytic):**", ""]
            parts += [f"- {h}" for h in hints]
        refs = f.get("references")
        if isinstance(refs, list) and refs:
            parts += ["", "**References:**", ""]
            for ref in refs:
                parts.append(f"- {ref}")

        linked_ids: List[str] = []
        if f.get("canonical_crash_id"):
            linked_ids.append(str(f["canonical_crash_id"]))
        if isinstance(f.get("crash_ids"), list):
            linked_ids += [str(x) for x in f["crash_ids"]]
        seen: set = set()
        linked_ids = [i for i in linked_ids if not (i in seen or seen.add(i))]

        for cid in linked_ids:
            c = crashes_by_id.get(cid)
            if c is None:
                continue
            parts += ["", f"#### Crash evidence `{_short_id(cid)}`", ""]
            ev_rows = [
                ("Sanitizer", c.get("sanitizer")),
                ("Exit code", c.get("exit_code")),
                ("Signal", (c.get("signal") or {}).get("name") if isinstance(c.get("signal"), dict) else None),
                ("Input", f"`{_fmt(c.get('input_path'))}`"),
                ("Input SHA-256", f"`{_fmt(c.get('input_hash'))}`"),
                ("Input size", c.get("input_size")),
                ("Runtime (ms)", c.get("runtime_ms")),
                ("Occurrences", c.get("occurrence_count")),
                ("Fingerprint", f"`{_fmt(c.get('fingerprint_digest'))}`"),
            ]
            loc = c.get("location")
            if isinstance(loc, dict) and loc.get("file"):
                ev_rows.append(("Location", f"`{loc.get('file')}:{loc.get('line')}`"))
            mem = c.get("memory_access")
            if isinstance(mem, dict) and mem:
                ev_rows.append(("Faulting access",
                                f"{mem.get('access_type') or mem.get('type')} at `{mem.get('address')}`"))
            parts.append(md_table(["Evidence", "Value"], ev_rows))
            st = c.get("stack_trace")
            parts += ["", "**Stack trace (sanitizer evidence):**", "",
                      _stack_markdown(st, options.max_stack_frames)]
            rep = c.get("sanitizer_report")
            raw_txt = None
            if isinstance(rep, dict):
                raw_txt = rep.get("raw_text") or rep.get("text")
            elif isinstance(rep, str):
                raw_txt = rep
            if raw_txt and options.include_raw_sanitizer_output:
                parts += ["", "**Raw sanitizer output:**", "",
                          md_code_block(truncate(raw_txt, options.max_log_preview), "text")]
            for r in repros_by_crash.get(cid, []):
                parts += ["", f"**Reproduction:** outcome=`{_fmt(r.get('outcome'))}`, "
                        f"attempts={_fmt(r.get('attempts'))}, "
                        f"successes={_fmt(r.get('successful_attempts'))}, "
                        f"rate={_fmt(r.get('reproducibility_rate'))}"]
            for m in mins_by_crash.get(cid, []):
                orig, mini = m.get("original_size"), m.get("minimized_size")
                ratio = m.get("reduction_ratio")
                parts += ["", f"**Minimisation:** {orig} → {mini} bytes "
                        f"(ratio {_fmt(ratio)}), still-crashes={m.get('still_crashes')}, "
                        f"strategy=`{_fmt(m.get('strategy'))}`"]
        notes = f.get("disclosure_notes")
        if notes:
            parts += ["", f"> **Disclosure notes.** {notes}"]
        parts.append("")
    return "\n".join(parts)


def _sev_rank(value: Any) -> int:
    order = ["none", "informational", "low", "moderate", "medium", "high", "critical"]
    token = normalise_severity(value, default="none")
    return order.index(token)


def section_crash_index(snap: ReportSnapshot) -> str:
    parts: List[str] = [md_heading("Crash Index"), ""]
    if not snap.crashes:
        parts.append("_No crashes recorded in scope._")
        return "\n".join(parts)
    dupes = sum(1 for c in snap.crashes if c.get("duplicate_of"))
    parts.append(f"{len(snap.crashes)} crash record(s); {dupes} linked as duplicates.\n")
    rows = []
    for c in sorted(snap.crashes, key=lambda x: str(x.get("first_seen_at") or "")):
        rows.append((
            f"`{_short_id(c.get('id'))}`",
            md_badge(c.get("severity")),
            c.get("crash_class"),
            c.get("sanitizer"),
            c.get("engine"),
            c.get("target_name"),
            c.get("occurrence_count"),
            "dup→" + _short_id(c.get("duplicate_of")) if c.get("duplicate_of") else "unique",
            f"`{(c.get('fingerprint_digest') or '')[:12]}`",
        ))
    parts.append(md_table(
        ["ID", "Severity", "Class", "Sanitizer", "Engine", "Target", "#", "Dedup", "FP"],
        rows))
    return "\n".join(parts)


def section_reproduction(snap: ReportSnapshot) -> str:
    parts: List[str] = [md_heading("Reproduction"), ""]
    if not snap.reproductions:
        parts.append("_Reproduction has not been attempted for any crash in scope._")
        return "\n".join(parts)
    rows = []
    for r in snap.reproductions:
        rows.append((
            f"`{_short_id(r.get('crash_id'))}`",
            r.get("outcome"),
            r.get("attempts"),
            r.get("successful_attempts"),
            r.get("reproducibility_rate"),
            f"{r.get('duration_seconds')}s" if r.get("duration_seconds") is not None else "—",
        ))
    parts.append(md_table(
        ["Crash", "Outcome", "Attempts", "Successes", "Rate", "Duration"], rows,
        aligns=["left", "left", "right", "right", "right", "right"]))
    return "\n".join(parts)


def section_minimization(snap: ReportSnapshot) -> str:
    parts: List[str] = [md_heading("Minimisation"), ""]
    if not snap.minimizations:
        parts.append("_No minimisation runs recorded._")
        return "\n".join(parts)
    rows = []
    for m in snap.minimizations:
        rows.append((
            f"`{_short_id(m.get('crash_id'))}`",
            m.get("strategy"),
            m.get("original_size"),
            m.get("minimized_size"),
            m.get("reduction_ratio"),
            "yes" if m.get("still_crashes") else "no",
            m.get("tool"),
            m.get("iterations"),
        ))
    parts.append(md_table(
        ["Crash", "Strategy", "Original B", "Minimized B", "Ratio", "Still crashes", "Tool", "Iters"],
        rows))
    return "\n".join(parts)


def section_corpora(snap: ReportSnapshot) -> str:
    parts: List[str] = [md_heading("Corpora"), ""]
    if not snap.corpora:
        parts.append("_No corpora registered._")
        return "\n".join(parts)
    rows = []
    for c in snap.corpora:
        total = c.get("total_bytes")
        human = f"{total:,} B" if isinstance(total, int) else "—"
        rows.append((
            f"`{_short_id(c.get('id'))}`", c.get("name"), c.get("entry_count"),
            human, c.get("format_hint"),
        ))
    parts.append(md_table(["ID", "Name", "Entries", "Total size", "Format"], rows))
    return "\n".join(parts)


def section_telemetry(snap: ReportSnapshot) -> str:
    parts: List[str] = [md_heading("Telemetry"), ""]
    if not snap.telemetry:
        parts.append("_No telemetry samples stored._")
        return "\n".join(parts)
    rows = []
    for t in snap.telemetry[-50:]:  # most recent 50 samples
        sample = t.get("sample") or {}
        rows.append((
            _fmt(t.get("taken_at")),
            f"`{_short_id(t.get('campaign_id'))}`",
            sample.get("executions") or sample.get("execs_done") or sample.get("total_execs"),
            sample.get("execs_per_sec"),
            sample.get("crashes") if "crashes" in sample else sample.get("crashes_found"),
            sample.get("coverage") if "coverage" in sample else sample.get("cov_edges"),
        ))
    parts.append(md_table(["Taken at", "Campaign", "Executions", "Exec/s", "Crashes", "Coverage"], rows))
    parts += ["", "> Values are reported exactly as captured from the fuzzing engine's own output."]
    return "\n".join(parts)


def section_regressions(snap: ReportSnapshot) -> str:
    parts: List[str] = [md_heading("Regression Tests"), ""]
    if not snap.regressions:
        parts.append("_No regression guards defined yet._")
        return "\n".join(parts)
    rows = []
    for g in snap.regressions:
        rows.append((
            g.get("name"), f"`{_short_id(g.get('finding_id'))}`",
            "enabled" if g.get("enabled") else "disabled",
            g.get("last_outcome"), g.get("pass_count"), g.get("fail_count"),
        ))
    parts.append(md_table(["Test", "Finding", "State", "Last outcome", "Pass", "Fail"], rows))
    return "\n".join(parts)


def section_appendix(snap: ReportSnapshot, summary: Dict[str, Any], options: ReportOptions) -> str:
    parts: List[str] = [md_heading("Appendix"), ""]
    parts.append(f"- Generated at: `{snap.generated_at}`")
    parts.append(f"- Tool: `{snap.tool.get('name','KMCS')}` v`{snap.tool.get('version','?')}` "
                 f"(schema `{snap.schema_version}`)")
    parts.append(f"- Snapshot digest (SHA-256): `{snap.digest()}`")
    parts.append(f"- Scope filters: severities ≥ `{options.severity_min or 'any'}`, "
                 f"states `{options.states or 'any'}`, "
                 f"targets `{options.target_ids or 'all'}`, "
                 f"campaigns `{options.campaign_ids or 'all'}`")
    if snap.warnings:
        parts += ["", "### Data warnings", ""]
        parts += [f"- ⚠️ {w}" for w in snap.warnings]
    parts += ["", "### Integrity statement", "",
              "This document was generated by KMCS strictly from stored campaign data. "
              "Counts, severities, fingerprints, reproduction outcomes and timings are copied "
              "from recorded evidence; nothing was estimated or synthesised. Fields without "
              "recorded data are marked _not recorded_.",
              "",
              "### Scope of this tool", "",
              "KMCS is a defensive fuzzing and memory-safety research platform operating only on "
              "authorised targets. This report documents defects for triage and remediation; it "
              "contains no exploit material and must be handled according to your disclosure policy."]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_markdown_report(
    snap: ReportSnapshot,
    *,
    path: Optional[Any] = None,
    options: Optional[ReportOptions] = None,
) -> RenderResult:
    """Render *snap* as Markdown; optionally write atomically to *path*."""

    options = options or ReportOptions()
    summary = compute_summary(snap)
    title = options.title or "KMCS Fuzzing & Memory-Safety Report"

    chunks: List[str] = [
        f"# {title}",
        "",
        f"_Generated {snap.generated_at} · schema {snap.schema_version} · "
        f"snapshot `{snap.digest()[:16]}…`_",
        "",
        "---",
        "",
    ]
    builders = {
        "summary": lambda: section_summary(snap, summary),
        "targets": lambda: section_targets(snap),
        "campaigns": lambda: section_campaigns(snap),
        "findings": lambda: section_findings(snap, options),
        "crashes": lambda: section_crash_index(snap),
        "reproduction": lambda: section_reproduction(snap),
        "minimization": lambda: section_minimization(snap),
        "corpora": lambda: section_corpora(snap),
        "telemetry": lambda: section_telemetry(snap),
        "regression_tests": lambda: section_regressions(snap),
        "appendix": lambda: section_appendix(snap, summary, options),
    }
    # alias so both "regressions" and "regression_tests" work
    builders["regressions"] = builders["regression_tests"]
    rendered_any = False
    for name in options.include_sections:
        if not options.should_render(name):
            continue
        builder = builders.get(name)
        if builder is None:
            continue
        if rendered_any:
            chunks += ["", "---", ""]
        chunks += [builder(), ""]
        rendered_any = True
    if not rendered_any:
        chunks.append("_All sections disabled by report options._")
    text = "\n".join(chunks).rstrip() + "\n"

    out_path: Optional[str] = None
    size = len(text.encode("utf-8"))
    if path is not None:
        out_path = resolve_out_path(path, "markdown")
        size = write_report(out_path, text)
    return RenderResult(
        fmt="markdown",
        path=out_path,
        content_hash=content_hash(text),
        size_bytes=size,
        generated_at=snap.generated_at,
        snapshot_digest=snap.digest(),
        warnings=list(snap.warnings),
    )


def generate_markdown_report(
    db: Any,
    *,
    path: Optional[Any] = None,
    options: Optional[ReportOptions] = None,
) -> RenderResult:
    """One-shot convenience: snapshot → markdown → optional save."""

    options = options or ReportOptions()
    snap = load_snapshot(db, options)
    return render_markdown_report(snap, path=path, options=options)


__all__ = [
    "md_escape_cell",
    "md_heading",
    "md_table",
    "md_code_block",
    "md_badge",
    "render_markdown_report",
    "generate_markdown_report",
]
