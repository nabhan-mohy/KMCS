"""
kmcs.reporting.html
===================

Browser-friendly HTML report renderer for KMCS results.

This is the flagship human-readable format: a single self-contained page
(inline CSS + vanilla JS, zero external assets — safe for air-gapped review
and offline sharing) that presents everything KMCS recorded about a campaign:

* header with provenance (tool version, schema, snapshot digest);
* campaign summary cards computed **only** from stored rows;
* severity distribution bar rendered from real counts;
* target inventory (authorised binaries, instrumentation, sanitizers);
* campaign table exactly as persisted;
* findings — expandable cards with classification, confidence, CVSS hint,
  root-cause hints, reproduction & minimisation outcomes;
* crash evidence — sanitizer reports, stack traces, faulting source
  locations, memory-access details, fingerprints, dedup links;
* reproduction matrix and input-artefact listing (path/hash/size only —
  never payload bytes);
* corpora / telemetry / regression-test inventories;
* appendix: data warnings, scope filters, integrity statement.

Faithfulness rules (identical contract to the rest of ``kmcs.reporting``):

1. No invented values. Absent fields render as ``not recorded``.
2. Deterministic output for a given snapshot + options.
3. All dynamic content HTML-escaped at the point of interpolation.
4. Defensive framing: the report documents defects for triage/remediation.

Public API
----------
``render_html_report(snap, path=..., options=...) -> RenderResult``
``generate_html_report(db, path=..., options=...) -> RenderResult``
plus lower-level helpers (``html_table``, ``severity_badge`` …) reused by
tests and other modules.
"""

from __future__ import annotations

import html as _html
import json
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from kmcs.reporting.common import (
    SEVERITY_COLORS,
    UNKNOWN,
    RenderResult,
    ReportOptions,
    ReportSnapshot,
    compute_summary,
    content_hash,
    cvss_score_from_vector,
    html_escape,
    load_snapshot,
    normalise_severity,
    resolve_out_path,
    severity_rank,
    truncate,
    write_report,
)

# ---------------------------------------------------------------------------
# Micro templating helpers
# ---------------------------------------------------------------------------


def e(value: Any) -> str:
    """HTML-escape *value*; None renders empty."""

    return html_escape("" if value is None else value)


def or_dash(value: Any) -> str:
    """Escape for display, substituting an italic 'not recorded' marker."""

    if value is None or (isinstance(value, str) and (not value.strip() or value == UNKNOWN)):
        return '<span class="nr">not recorded</span>'
    return e(value)


def _raw_cell(markup: str) -> "html_table.RawCell":
    """Wrap pre-built, trusted markup so :func:`html_table` skips escaping.

    Only pass strings composed by this module itself (with ``e()``/``or_dash``
    applied to any dynamic parts) — never raw user data.
    """

    return html_table.RawCell(markup)


def html_table(headers: Sequence[str], rows: Iterable[Sequence[Any]], *,
               classes: str = "data", row_classes: Optional[Sequence[str]] = None) -> str:
    """Render an accessible <table> from already-safe-or-raw cells.

    Cells are escaped here unless they are :class:`RawCell` instances
    (produced by :func:`_raw_cell`), which carry pre-built markup.
    """

    out: List[str] = [f'<table class="{classes}"><thead><tr>']
    out += [f"<th>{e(h)}</th>" for h in headers]
    out.append("</tr></thead><tbody>")
    nrows = 0
    for i, row in enumerate(rows):
        rc = f' class="{row_classes[i]}"' if row_classes and i < len(row_classes) and row_classes[i] else ""
        cells = []
        for cell in row:
            if isinstance(cell, html_table.RawCell):
                cells.append(str(cell))
            else:
                cells.append(f"<td>{or_dash(cell)}</td>")
        while len(cells) < len(headers):
            cells.append("<td>—</td>")
        out.append(f"<tr{rc}>" + "".join(cells) + "</tr>")
        nrows += 1
    if nrows == 0:
        out.append(f'<tr><td colspan="{max(1, len(headers))}" class="empty">No records in scope.</td></tr>')
    out.append("</tbody></table>")
    return "".join(out)


# Attach the RawCell marker type to the function namespace (defined after so
# both helpers can reference it regardless of definition order).
class _RawCell(str):
    """A string of trusted, pre-escaped markup for table interpolation."""

    __slots__ = ()


html_table.RawCell = _RawCell  # type: ignore[attr-defined]
_raw = _raw_cell


def severity_badge(severity: Any) -> str:
    token = normalise_severity(severity)
    color = SEVERITY_COLORS.get(token, SEVERITY_COLORS["none"])
    return (
        f'<span class="badge" style="--bg:{color}" role="img" '
        f'aria-label="severity {e(token)}">{e(token)}</span>'
    )


def anchor_id(prefix: str, ident: Any) -> str:
    s = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in str(ident or ""))
    return f"{prefix}-{s[:48]}"


# ---------------------------------------------------------------------------
# CSS / JS (self-contained)
# ---------------------------------------------------------------------------

_CSS = """\
:root{
  --bg:#0f1420; --panel:#171e2e; --panel2:#1d2639; --ink:#e7ecf5; --muted:#93a0b8;
  --line:#2a3550; --accent:#5aa2ff; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
@media (prefers-color-scheme: light){
  :root{--bg:#f5f7fb; --panel:#ffffff; --panel2:#eef2f9; --ink:#17202f; --muted:#5b6b85; --line:#d7dfec;}
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
 font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header.doc{padding:28px 32px 18px;border-bottom:1px solid var(--line);background:var(--panel)}
header.doc h1{margin:0 0 6px;font-size:26px;letter-spacing:.2px}
header.doc .meta{color:var(--muted);font-size:13px;display:flex;flex-wrap:wrap;gap:14px}
header.doc .meta code{font-family:var(--mono);font-size:12px}
main{max-width:1180px;margin:0 auto;padding:24px 32px 64px}
nav.toc{position:sticky;top:0;z-index:5;background:var(--panel);border:1px solid var(--line);
 border-radius:10px;padding:10px 14px;margin-bottom:22px;display:flex;flex-wrap:wrap;gap:8px}
nav.toc a{color:var(--ink);text-decoration:none;font-size:13px;padding:4px 10px;border-radius:999px;
 background:var(--panel2);border:1px solid var(--line)}
nav.toc a:hover{border-color:var(--accent)}
section{margin:0 0 30px}
h2{font-size:20px;margin:26px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:18px 0 8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .num{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums}
.card .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.6px}
table.data{border-collapse:collapse;width:100%;font-size:13.5px;margin:8px 0}
table.data th,table.data td{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}
table.data th{background:var(--panel2);position:sticky;top:56px}
table.data tr:nth-child(even) td{background:color-mix(in srgb,var(--panel) 92%,var(--ink))}
table.data td.empty{color:var(--muted);font-style:italic;text-align:center}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;
 color:#fff;background:var(--bg-fallback,#6b7280);background:var(--bg);text-transform:capitalize}
.nr{color:var(--muted);font-style:italic}
code,.mono{font-family:var(--mono);font-size:12.5px}
pre.stack{background:var(--panel2);border:1px solid var(--line);border-left:3px solid var(--accent);
 border-radius:8px;padding:12px 14px;overflow:auto;font-family:var(--mono);font-size:12.5px;line-height:1.5}
details.finding,details.crash{background:var(--panel);border:1px solid var(--line);border-radius:10px;
 margin:10px 0;overflow:hidden}
details.finding>summary,details.crash>summary{cursor:pointer;padding:12px 16px;display:flex;gap:10px;
 align-items:center;flex-wrap:wrap;list-style:none}
details.finding>summary::-webkit-details-marker,details.crash>summary::-webkit-details-marker{display:none}
details.finding>summary::before{content:"▸";color:var(--muted);transition:transform .15s}
details[open]>summary::before{transform:rotate(90deg)}
details .body{padding:4px 18px 16px;border-top:1px solid var(--line)}
.kv{display:grid;grid-template-columns:190px 1fr;gap:4px 14px;font-size:13.5px;margin:10px 0}
.kv dt{color:var(--muted)}
.kv dd{margin:0;word-break:break-word}
.sevbar{display:flex;height:26px;border-radius:8px;overflow:hidden;border:1px solid var(--line);margin:10px 0}
.sevbar div{min-width:2px;display:flex;align-items:center;justify-content:center;color:#fff;
 font-size:11px;font-weight:700}
.warn{background:color-mix(in srgb,#eab308 18%,var(--panel));border:1px solid #eab30866;
 border-radius:8px;padding:10px 14px;margin:10px 0;font-size:13.5px}
.note{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:10px 14px;
 margin:10px 0;font-size:13px;color:var(--muted)}
.pill{display:inline-block;background:var(--panel2);border:1px solid var(--line);border-radius:999px;
 padding:1px 9px;font-size:12px;margin:1px 3px 1px 0}
input.filter{width:100%;max-width:420px;padding:8px 12px;border-radius:8px;border:1px solid var(--line);
 background:var(--panel2);color:var(--ink);font-size:13.5px;margin:6px 0 10px}
footer{border-top:1px solid var(--line);padding:18px 32px;color:var(--muted);font-size:12.5px}
a{color:var(--accent)}
@media print{nav.toc,.toolbar{display:none}body{background:#fff;color:#000}}
"""

_JS = """\
document.addEventListener('DOMContentLoaded', function () {
  // finding/crash live filter boxes
  document.querySelectorAll('input.filter[data-target]').forEach(function (inp) {
    inp.addEventListener('input', function () {
      var q = inp.value.trim().toLowerCase();
      document.querySelectorAll(inp.dataset.target + ' > details').forEach(function (el) {
        var hay = (el.textContent || '').toLowerCase();
        el.style.display = (!q || hay.indexOf(q) !== -1) ? '' : 'none';
      });
    });
  });
  // deep-link expansion (#finding-... / #crash-...)
  if (location.hash) {
    var t = document.getElementById(location.hash.slice(1));
    if (t && t.tagName === 'DETAILS') t.open = true;
    else if (t) { var d = t.closest('details'); if (d) d.open = true; }
  }
  // expand / collapse all buttons
  document.querySelectorAll('[data-expand]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var sel = btn.dataset.expand;
      document.querySelectorAll(sel + ' > details').forEach(function (el) {
        el.open = btn.dataset.mode === 'open';
      });
    });
  });
});
"""


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


def _sev_bar(breakdown: Mapping[str, int]) -> str:
    total = sum(breakdown.values()) or 0
    if not total:
        return '<div class="note">No crashes with recorded severity in scope.</div>'
    segs: List[str] = []
    order = ["critical", "high", "medium", "moderate", "low", "informational", "none"]
    for token in order:
        n = breakdown.get(token, 0)
        if not n:
            continue
        pct = 100.0 * n / total
        color = SEVERITY_COLORS[token]
        label = f"{n}" if pct > 4 else ""
        segs.append(
            f'<div style="flex:{pct:.3f};background:{color}" title="{e(token)}: {n}">'
            f"{label}</div>"
        )
    legend = " ".join(
        f'<span class="pill"><span class="badge" style="--bg:{SEVERITY_COLORS[t]}">{t}</span> {breakdown[t]}</span>'
        for t in order if breakdown.get(t)
    )
    return f'<div class="sevbar" role="img" aria-label="severity distribution">{"".join(segs)}</div><div>{legend}</div>'


def _sec_summary(snap: ReportSnapshot, summary: Dict[str, Any]) -> str:
    counts = summary["counts"]
    cards = [
        ("Targets", counts["targets"]),
        ("Campaigns", counts["campaigns"]),
        ("Crashes", counts["crashes"]),
        ("Findings", counts["findings"]),
        ("Duplicate links", counts["duplicates_linked"]),
        ("Reproductions", counts["reproductions"]),
        ("Minimizations", counts["minimizations"]),
        ("Corpora entries", counts["corpora"]),
    ]
    html = ["<section id='summary'><h2>Campaign Summary</h2>"]
    html.append('<div class="cards">' + "".join(
        f'<div class="card"><div class="num">{int(v)}</div><div class="lbl">{e(k)}</div></div>'
        for k, v in cards) + "</div>")
    html.append("<h3>Severity distribution (crash records)</h3>")
    html.append(_sev_bar(summary.get("crash_severity_breakdown") or {}))
    highest = summary.get("highest_observed_severity") or "none"
    html.append(
        f"<p>Highest observed severity in scope: {severity_badge(highest)} "
        "<span class='nr'>(as recorded by KMCS analysis — not inferred by this report)</span></p>"
    )
    ex = (summary.get("execution_totals") or {})
    if ex.get("executions") is not None:
        exec_txt = f"<strong>{ex['executions']:,}</strong> ({e(ex.get('provenance'))})"
    else:
        exec_txt = "<span class='nr'>not recorded</span>"
    repro = summary.get("reproduction") or {}
    if repro.get("attempts_total"):
        rate = repro.get("rate")
        rate_txt = f"{rate:.1%}" if isinstance(rate, float) else "—"
        repro_txt = (f"{repro['attempts_total']} attempts, {repro['successes_total']} reproduced "
                     f"(rate {rate_txt})")
    else:
        repro_txt = "<span class='nr'>no reproduction attempts recorded</span>"
    html.append(
        '<dl class="kv">'
        f"<dt>Engine executions</dt><dd>{exec_txt}</dd>"
        f"<dt>Reproduction activity</dt><dd>{repro_txt}</dd>"
        f"<dt>Total crash occurrences</dt><dd>{counts['crash_occurrences_total']}</dd>"
        f"<dt>Unique input hashes</dt><dd>{counts['unique_input_hashes']}</dd>"
        "</dl>"
    )
    cls_rows = sorted((summary.get("crash_class_breakdown") or {}).items(), key=lambda kv: (-kv[1], kv[0]))
    san_rows = sorted((summary.get("sanitizer_breakdown") or {}).items())
    eng_rows = sorted((summary.get("engine_breakdown") or {}).items())
    st_rows = sorted((summary.get("finding_state_breakdown") or {}).items())
    html.append("<div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px'>")
    html.append("<div><h3>Crash classes</h3>" + html_table(
        ["Class", "Count"], cls_rows, classes="data") + "</div>")
    html.append("<div><h3>Sanitizers</h3>" + html_table(
        ["Sanitizer", "Crashes"], san_rows, classes="data") + "</div>")
    html.append("<div><h3>Engines</h3>" + html_table(
        ["Engine", "Crashes"], eng_rows, classes="data") + "</div>")
    html.append("<div><h3>Finding states</h3>" + html_table(
        ["State", "Findings"], st_rows, classes="data") + "</div>")
    html.append("</div>")
    if snap.stats:
        stat_rows = sorted((k, v) for k, v in snap.stats.items() if isinstance(v, int))
        html.append("<h3>Database counters (verbatim from <code>db.stats()</code>)</h3>")
        html.append(html_table(["Counter", "Value"], stat_rows, classes="data"))
    html.append("</section>")
    return "".join(html)


def _sec_targets(snap: ReportSnapshot) -> str:
    html = ["<section id='targets'><h2>Targets</h2>"]
    if not snap.targets:
        html.append("<p class='nr'>No targets registered.</p></section>")
        return "".join(html)
    rows = []
    for t in snap.targets:
        rows.append((
            _raw(f"<code>{e(t.get('id'))}</code>"),
            t.get("name"),
            _raw(f"<code>{or_dash(t.get('binary_path'))}</code>"),
            t.get("language"),
            t.get("architecture"),
            t.get("version"),
            _raw("<span class='pill'>" + e(", ".join(map(str, t.get("sanitizers_enabled") or [])) or "none recorded") + "</span>"),
            _raw("yes" if t.get("instrumented") else "<span class='nr'>no</span>"),
        ))
    html.append(html_table(
        ["ID", "Name", "Binary (redacted)", "Language", "Arch", "Version", "Sanitizers", "Instrumented"],
        rows))
    html.append("<p class='note'>Paths shown are tail-shortened to avoid leaking build-machine layouts.</p>")
    html.append("</section>")
    return "".join(html)


def _sec_campaigns(snap: ReportSnapshot) -> str:
    html = ["<section id='campaigns'><h2>Campaigns</h2>"]
    if not snap.campaigns:
        html.append("<p class='nr'>No campaigns recorded.</p></section>")
        return "".join(html)
    rows = []
    for c in snap.campaigns:
        window = "—"
        if c.get("started_at") or c.get("finished_at"):
            window = f"{or_dash(c.get('started_at'))} → {or_dash(c.get('finished_at'))}"
        rows.append((
            _raw(f"<code>{e(c.get('id'))}</code>"),
            c.get("name"), c.get("engine"), c.get("status"),
            c.get("worker_count"), _raw(window),
            _raw(e("; ".join(map(str, c.get("sanitizers") or []))) or "—"),
        ))
    html.append(html_table(
        ["ID", "Name", "Engine", "Status", "Workers", "Window (recorded timestamps)", "Sanitizers"], rows))
    html.append("</section>")
    return "".join(html)


def _stack_pre(frames: Any, max_frames: int) -> str:
    if not isinstance(frames, list) or not frames:
        return "<p class='nr'>Stack trace not recorded for this crash.</p>"
    lines: List[str] = []
    for position, fr in enumerate(frames[:max_frames]):
        if isinstance(fr, dict):
            idx = fr.get("index", fr.get("frame_index", position))
            fn = fr.get("function") or "?"
            file_ = fr.get("file")
            line = fr.get("line")
            addr = fr.get("address")
            loc = f" {file_}:{line}" if file_ and line else (f" {file_}" if file_ else "")
            extra = f" [{addr}]" if addr else ""
            syslib = " (system library)" if fr.get("is_system_library") else ""
            lines.append(f"#{idx} {fn}{loc}{extra}{syslib}")
        else:
            lines.append(str(fr))
    if len(frames) > max_frames:
        lines.append(f"… {len(frames) - max_frames} additional frame(s) omitted by report options")
    return f"<pre class='stack'>{e(chr(10).join(lines))}</pre>"


def _crash_evidence_block(c: Mapping[str, Any], options: ReportOptions,
                          repros: Sequence[Mapping[str, Any]],
                          mins: Sequence[Mapping[str, Any]]) -> str:
    parts: List[str] = []
    sig = c.get("signal") if isinstance(c.get("signal"), Mapping) else {}
    mem = c.get("memory_access") if isinstance(c.get("memory_access"), Mapping) else {}
    loc = c.get("location") if isinstance(c.get("location"), Mapping) else {}
    parts.append("<dl class='kv'>")

    def kv(k: str, v: Any) -> None:
        """Emit one dt/dd pair; strings containing markup are trusted (built here)."""

        if isinstance(v, str) and "<" in v:
            rendered = v
        else:
            rendered = or_dash(v)
        parts.append(f"<dt>{e(k)}</dt><dd>{rendered}</dd>")

    kv("Crash ID", f"<code>{e(c.get('id'))}</code>")
    kv("Sanitizer / engine", f"{e(c.get('sanitizer') or '—')} / {e(c.get('engine') or '—')}")
    kv("Exit code / signal", f"{e(c.get('exit_code') if c.get('exit_code') is not None else '—')} / "
       f"{e((sig or {}).get('name') or '—')}")
    kv("Runtime", f"{e(c.get('runtime_ms'))} ms" if c.get("runtime_ms") is not None else None)
    kv("Occurrences", c.get("occurrence_count"))
    kv("Input file", f"<code>{or_dash(c.get('input_path'))}</code>")
    kv("Input SHA-256", f"<code>{or_dash(c.get('input_hash'))}</code>")
    kv("Input size", f"{e(c.get('input_size'))} bytes" if c.get("input_size") is not None else None)
    if loc:
        kv("Fault location", f"<code>{e(loc.get('file'))}:{e(loc.get('line'))}</code> "
           f"in <code>{e(loc.get('function'))}</code>" if loc.get("file") else None)
    if mem and (mem.get("address") or mem.get("access_type")):
        kv("Faulting access", f"{e(mem.get('access_type') or mem.get('type') or '')} at "
           f"<code>{e(mem.get('address'))}</code>".replace("<code>None</code>", "<span class='nr'>address not recorded</span>"))
    fp = c.get("fingerprint")
    fp_digest = c.get("fingerprint_digest")
    if fp_digest:
        strat = fp.get("strategy") if isinstance(fp, Mapping) else None
        kv("Fingerprint", f"<code>{e(fp_digest)}</code>"
           + (f" <span class='pill'>{e(strat)}</span>" if strat else ""))
    if c.get("duplicate_of"):
        kv("Duplicate of", f"<a href='#crash-{e(c['duplicate_of'])}'><code>{e(c['duplicate_of'])}</code></a>")
    parts.append("</dl>")
    parts.append("<h4>Stack trace (sanitizer evidence)</h4>")
    parts.append(_stack_pre(c.get("stack_trace"), options.max_stack_frames))
    rep = c.get("sanitizer_report")
    raw_txt = None
    if isinstance(rep, Mapping):
        raw_txt = rep.get("raw_text") or rep.get("text")
    elif isinstance(rep, str):
        raw_txt = rep
    if raw_txt and options.include_raw_sanitizer_output:
        parts.append("<h4>Raw sanitizer output</h4>")
        parts.append(f"<pre class='stack'>{e(truncate(raw_txt, options.max_log_preview))}</pre>")
    elif raw_txt:
        parts.append("<p class='nr'>Raw sanitizer output omitted by report options.</p>")
    for r in repros:
        outcome = str(r.get("outcome") or "")
        cls = "warn" if outcome.startswith("failed") else "note"
        parts.append(
            f"<div class='{cls}'><strong>Reproduction:</strong> outcome={or_dash(r.get('outcome'))}, "
            f"attempts={or_dash(r.get('attempts'))}, successes={or_dash(r.get('successful_attempts'))}, "
            f"rate={or_dash(r.get('reproducibility_rate'))}, "
            f"performed {or_dash(r.get('performed_at'))} by {or_dash(r.get('performed_by'))}</div>")
    for m in mins:
        parts.append(
            "<div class='note'><strong>Minimisation:</strong> "
            f"{or_dash(m.get('original_size'))} → {or_dash(m.get('minimized_size'))} bytes "
            f"(ratio {or_dash(m.get('reduction_ratio'))}), strategy {or_dash(m.get('strategy'))}, "
            f"still reproduces: {or_dash('yes' if m.get('still_crashes') else ('no' if m.get('still_crashes') is False else None))}</div>")
    return "".join(parts)


def _sec_findings(snap: ReportSnapshot, options: ReportOptions) -> str:
    parts: List[str] = ["<section id='findings'><h2>Findings</h2>"]
    if not snap.findings:
        parts.append("<p class='nr'>No findings created yet — crash records are listed in the Crash Evidence section.</p>")
        parts.append("</section>")
        return "".join(parts)
    crashes_by_id = snap.crash_by_id()
    repros_by_crash: Dict[str, List[Mapping[str, Any]]] = {}
    for r in snap.reproductions:
        repros_by_crash.setdefault(str(r.get("crash_id")), []).append(r)
    mins_by_crash: Dict[str, List[Mapping[str, Any]]] = {}
    for m in snap.minimizations:
        mins_by_crash.setdefault(str(m.get("crash_id")), []).append(m)

    ordered = sorted(snap.findings, key=lambda f: (-severity_rank(f.get("severity")),
                                                   str(f.get("discovered_at") or "")))
    parts.append(
        "<div class='toolbar'><input class='filter' data-target='#finding-list' "
        "placeholder='Filter findings by text…' aria-label='Filter findings'>"
        "<button data-expand='#finding-list' data-mode='open'>Expand all</button> "
        "<button data-expand='#finding-list' data-mode='close'>Collapse all</button></div>")
    parts.append("<div id='finding-list'>")
    for f in ordered:
        fid = str(f.get("id"))
        aid = anchor_id("finding", fid)
        sev = normalise_severity(f.get("severity"))
        title = f.get("title") or "Untitled finding"
        cvss = None
        if f.get("cvss_vector_hint"):
            cvss = cvss_score_from_vector(str(f["cvss_vector_hint"]))
        head = (f"{severity_badge(sev)} <strong>{e(title)}</strong> "
                f"<span class='pill'>{e(f.get('state') or 'unknown state')}</span> "
                f"<span class='pill mono'>{e(fid[:8])}…</span>")
        if cvss is not None:
            head += f" <span class='pill'>CVSS {e(cvss)}</span>"
        parts.append(f"<details class='finding' id='{aid}'><summary>{head}</summary><div class='body'>")
        parts.append("<dl class='kv'>")
        parts.append(f"<dt>Target</dt><dd>{or_dash(f.get('target_name'))}</dd>")
        parts.append(f"<dt>Crash class</dt><dd><code>{or_dash(f.get('crash_class'))}</code></dd>")
        parts.append(f"<dt>Confidence</dt><dd>{or_dash(f.get('confidence'))}</dd>")
        parts.append(f"<dt>Discovered / confirmed</dt><dd>{or_dash(f.get('discovered_at'))} / {or_dash(f.get('confirmed_at'))}</dd>")
        parts.append(f"<dt>Analyst</dt><dd>{or_dash(f.get('analyst') or f.get('assignee'))}</dd>")
        parts.append(f"<dt>Fixed in</dt><dd>{or_dash(f.get('fixed_in'))}</dd>")
        if f.get("cvss_vector_hint"):
            parts.append(f"<dt>CVSS vector (analysis hint)</dt><dd><code>{e(f['cvss_vector_hint'])}</code></dd>")
        if f.get("summary"):
            parts.append(f"<dt>Summary</dt><dd>{e(f['summary'])}</dd>")
        if f.get("description"):
            parts.append(f"<dt>Details</dt><dd>{e(f['description'])}</dd>")
        hints = f.get("root_cause_hints")
        if isinstance(hints, list) and hints:
            parts.append("<dt>Root-cause hints</dt><dd>" + "".join(
                f"<div>• {e(h)}</div>" for h in hints) + "</dd>")
        refs = f.get("references")
        if isinstance(refs, list) and refs:
            parts.append("<dt>References</dt><dd>" + "".join(
                f"<div>{e(r)}</div>" for r in refs) + "</dd>")
        labels = f.get("labels")
        if isinstance(labels, list) and labels:
            parts.append("<dt>Labels</dt><dd>" + "".join(
                f"<span class='pill'>{e(l)}</span>" for l in labels) + "</dd>")
        parts.append("</dl>")
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
                parts.append(f"<div class='warn'>Linked crash <code>{e(cid)}</code> is outside the current report scope.</div>")
                continue
            parts.append(f"<h4>Crash evidence <a href='#crash-{e(cid)}'><code>{e(cid[:8])}…</code></a></h4>")
            parts.append(_crash_evidence_block(c, options,
                                               repros_by_crash.get(cid, []),
                                               mins_by_crash.get(cid, [])))
        if f.get("disclosure_notes"):
            parts.append(f"<div class='note'><strong>Disclosure notes.</strong> {e(f['disclosure_notes'])}</div>")
        parts.append("</div></details>")
    parts.append("</div></section>")
    return "".join(parts)


def _sec_crashes(snap: ReportSnapshot, options: ReportOptions) -> str:
    parts: List[str] = ["<section id='crashes'><h2>Crash Evidence</h2>"]
    if not snap.crashes:
        parts.append("<p class='nr'>No crash records in scope.</p></section>")
        return "".join(parts)
    dupes = sum(1 for c in snap.crashes if c.get("duplicate_of"))
    parts.append(f"<p>{len(snap.crashes)} crash record(s); {dupes} marked as duplicates of another record.</p>")
    parts.append(
        "<div class='toolbar'><input class='filter' data-target='#crash-list' "
        "placeholder='Filter crashes…' aria-label='Filter crashes'></div>")
    repros_by_crash: Dict[str, List[Mapping[str, Any]]] = {}
    for r in snap.reproductions:
        repros_by_crash.setdefault(str(r.get("crash_id")), []).append(r)
    mins_by_crash: Dict[str, List[Mapping[str, Any]]] = {}
    for m in snap.minimizations:
        mins_by_crash.setdefault(str(m.get("crash_id")), []).append(m)
    parts.append("<div id='crash-list'>")
    for c in sorted(snap.crashes, key=lambda x: (-severity_rank(x.get("severity")),
                                                 str(x.get("first_seen_at") or ""))):
        cid = str(c.get("id"))
        sev = normalise_severity(c.get("severity"))
        head = (f"{severity_badge(sev)} <strong>{e(c.get('crash_class') or 'uncategorised crash')}</strong> "
                f"<span class='pill'>{e(c.get('sanitizer') or 'sanitizer?')}</span>"
                f"<span class='pill mono'>{e(cid[:8])}…</span>"
                + ("<span class='pill'>duplicate</span>" if c.get("duplicate_of") else ""))
        parts.append(f"<details class='crash' id='{anchor_id('crash', cid)}'><summary>{head}</summary>"
                     f"<div class='body'>{_crash_evidence_block(c, options, repros_by_crash.get(cid, []), mins_by_crash.get(cid, []))}</div></details>")
    parts.append("</div></section>")
    return "".join(parts)


def _sec_reproduction(snap: ReportSnapshot) -> str:
    parts: List[str] = ["<section id='reproduction'><h2>Reproduction Results</h2>"]
    if not snap.reproductions:
        parts.append("<p class='nr'>Reproduction has not been attempted for any crash in scope.</p></section>")
        return "".join(parts)
    rows = []
    for r in snap.reproductions:
        rows.append((
            _raw(f"<a href='#crash-{e(r.get('crash_id'))}'><code>{e(r.get('crash_id'))}</code></a>"),
            r.get("outcome"), r.get("attempts"), r.get("successful_attempts"),
            r.get("reproducibility_rate"), r.get("duration_seconds"),
            r.get("performed_at"), r.get("performed_by"),
        ))
    parts.append(html_table(
        ["Crash", "Outcome", "Attempts", "Successes", "Rate", "Seconds", "When", "By"], rows))
    parts.append("</section>")
    return "".join(parts)


def _sec_inputs(snap: ReportSnapshot) -> str:
    """Input artefact inventory — references only, never contents."""

    parts: List[str] = ["<section id='inputs'><h2>Input Files</h2>"]
    rows = []
    for c in snap.crashes:
        if c.get("input_path") or c.get("input_hash"):
            rows.append((
                _raw(f"<code>{e(c.get('id'))}</code>"),
                "crash-input",
                _raw(f"<code>{or_dash(c.get('input_path'))}</code>"),
                _raw(f"<code>{or_dash(c.get('input_hash'))}</code>"),
                c.get("input_size"),
            ))
        if c.get("minimized_path"):
            rows.append((
                _raw(f"<code>{e(c.get('id'))}</code>"),
                "minimized-input",
                _raw(f"<code>{e(c['minimized_path'])}</code>"),
                "", "",
            ))
    for g in snap.regressions:
        rows.append((
            _raw(f"<code>{e(g.get('id'))}</code>"),
            "regression-input",
            _raw(f"<code>{or_dash(g.get('input_path'))}</code>"),
            _raw(f"<code>{or_dash(g.get('input_hash'))}</code>"),
            g.get("input_size"),
        ))
    if not rows:
        parts.append("<p class='nr'>No input artefacts referenced in scope.</p>")
    else:
        parts.append(html_table(["Record", "Role", "Path (redacted)", "SHA-256", "Size (bytes)"], rows))
    parts.append("<p class='note'>KMCS reports reference stored artefacts by path and hash only; "
                 "file contents are intentionally not embedded in reports.</p>")
    parts.append("</section>")
    return "".join(parts)


def _sec_corpora(snap: ReportSnapshot) -> str:
    parts: List[str] = ["<section id='corpora'><h2>Corpora</h2>"]
    if not snap.corpora:
        parts.append("<p class='nr'>No corpora registered.</p></section>")
        return "".join(parts)
    rows = [(
        _raw(f"<code>{e(c.get('id'))}</code>"), c.get("name"), c.get("entry_count"),
        c.get("total_bytes"), c.get("format_hint"),
    ) for c in snap.corpora]
    parts.append(html_table(["ID", "Name", "Entries", "Total bytes", "Format"], rows))
    parts.append("</section>")
    return "".join(parts)


def _sec_telemetry(snap: ReportSnapshot) -> str:
    parts: List[str] = ["<section id='telemetry'><h2>Telemetry</h2>"]
    if not snap.telemetry:
        parts.append("<p class='nr'>No telemetry samples stored.</p></section>")
        return "".join(parts)
    rows = []
    for t in snap.telemetry[-100:]:
        s = t.get("sample") or {}
        rows.append((
            t.get("taken_at"),
            _raw(f"<code>{e(str(t.get('campaign_id'))[:8])}…</code>"),
            s.get("executions") or s.get("execs_done") or s.get("total_execs"),
            s.get("execs_per_sec"),
            s.get("crashes") if "crashes" in s else s.get("crashes_found"),
            s.get("coverage") if "coverage" in s else s.get("cov_edges"),
        ))
    parts.append(html_table(["Taken at", "Campaign", "Executions", "Exec/s", "Crashes", "Coverage"], rows))
    parts.append("<p class='note'>Values are copied verbatim from engine output captured by the KMCS monitor.</p>")
    parts.append("</section>")
    return "".join(parts)


def _sec_appendix(snap: ReportSnapshot, summary: Dict[str, Any], options: ReportOptions) -> str:
    parts: List[str] = ["<section id='appendix'><h2>Appendix — Provenance &amp; Integrity</h2>"]
    if snap.warnings:
        for w in snap.warnings:
            parts.append(f"<div class='warn'>⚠ {e(w)}</div>")
    parts.append("<dl class='kv'>")
    parts.append(f"<dt>Generated at</dt><dd><code>{e(snap.generated_at)}</code></dd>")
    parts.append(f"<dt>Tool</dt><dd>{e(snap.tool.get('name'))} v{e(snap.tool.get('version'))} "
                 f"(report schema {e(snap.schema_version)})</dd>")
    parts.append(f"<dt>Snapshot digest (SHA-256)</dt><dd><code>{e(snap.digest())}</code></dd>")
    parts.append(f"<dt>Scope filters</dt><dd>severity ≥ {or_dash(options.severity_min)} · "
                 f"states {e(', '.join(options.states) or 'any')} · "
                 f"targets {e(', '.join(options.target_ids) or 'all')} · "
                 f"campaigns {e(', '.join(options.campaign_ids) or 'all')}</dd>")
    parts.append("</dl>")
    parts.append(
        "<div class='note'><strong>Integrity statement.</strong> This document was produced by KMCS "
        "strictly from stored campaign data. Counts, severities, classifications, fingerprints, "
        "reproduction outcomes and timings are copied from recorded evidence; nothing was estimated "
        "or synthesised. Fields without recorded data are marked “not recorded”.</div>")
    parts.append(
        "<div class='note'><strong>Scope.</strong> KMCS is a defensive fuzzing and memory-safety "
        "research platform operating only on authorised targets. This report supports triage and "
        "remediation; it contains no exploit material and must be handled per your disclosure policy.</div>")
    parts.append("</section>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_html_report(
    snap: ReportSnapshot,
    *,
    path: Optional[Any] = None,
    options: Optional[ReportOptions] = None,
) -> RenderResult:
    """Render *snap* as a self-contained HTML page; optionally save atomically."""

    options = options or ReportOptions()
    summary = compute_summary(snap)
    title = options.title or "KMCS Fuzzing & Memory-Safety Report"

    builders = {
        "summary": lambda: _sec_summary(snap, summary),
        "targets": lambda: _sec_targets(snap),
        "campaigns": lambda: _sec_campaigns(snap),
        "findings": lambda: _sec_findings(snap, options),
        "crashes": lambda: _sec_crashes(snap, options),
        "reproduction": lambda: _sec_reproduction(snap),
        "minimization": lambda: _sec_inputs(snap),  # inputs+minimization artefacts
        "corpora": lambda: _sec_corpora(snap),
        "telemetry": lambda: _sec_telemetry(snap),
        "appendix": lambda: _sec_appendix(snap, summary, options),
    }
    nav_order = [
        ("summary", "Summary"), ("targets", "Targets"), ("campaigns", "Campaigns"),
        ("findings", "Findings"), ("crashes", "Crashes"), ("reproduction", "Reproduction"),
        ("minimization", "Inputs"), ("corpora", "Corpora"), ("telemetry", "Telemetry"),
        ("appendix", "Appendix"),
    ]
    body: List[str] = []
    nav_items = [f'<a href="#{sid}">{e(lbl)}</a>' for sid, lbl in nav_order if options.should_render(sid)]
    if nav_items:
        body.append("<nav class='toc' aria-label='Report sections'>" + "".join(nav_items) + "</nav>")
    rendered_any = False
    for name in options.include_sections:
        if not options.should_render(name):
            continue
        builder = builders.get(name)
        if builder is None:
            continue
        body.append(builder())
        rendered_any = True
    if not rendered_any:
        body.append("<section><p class='nr'>All report sections disabled by options.</p></section>")

    doc = f"""<!DOCTYPE html>
<html lang="{e(options.locale_note)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="KMCS reporting/html.py schema {e(snap.schema_version)}">
<meta name="kmcs:snapshot-digest" content="{e(snap.digest())}">
<meta name="kmcs:generated-at" content="{e(snap.generated_at)}">
<title>{e(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<header class="doc">
<h1>{e(title)}</h1>
<div class="meta">
<span>Generated <code>{e(snap.generated_at)}</code></span>
<span>KMCS v<code>{e(snap.tool.get('version'))}</code></span>
<span>Schema <code>{e(snap.schema_version)}</code></span>
<span>Snapshot <code>{e(snap.digest()[:16])}…</code></span>
<span>{e(summary['counts']['crashes'])} crashes · {e(summary['counts']['findings'])} findings · {e(summary['counts']['campaigns'])} campaigns</span>
</div>
</header>
<main>
{''.join(body)}
</main>
<footer>KMCS defensive fuzzing report — data reflects recorded evidence only. Handle per your organisation's disclosure policy.</footer>
<script>{_JS}</script>
</body>
</html>
"""
    out_path: Optional[str] = None
    size = len(doc.encode("utf-8"))
    if path is not None:
        out_path = resolve_out_path(path, "html")
        size = write_report(out_path, doc)
    return RenderResult(
        fmt="html",
        path=out_path,
        content_hash=content_hash(doc),
        size_bytes=size,
        generated_at=snap.generated_at,
        snapshot_digest=snap.digest(),
        warnings=list(snap.warnings),
    )


def generate_html_report(
    db: Any,
    *,
    path: Optional[Any] = None,
    options: Optional[ReportOptions] = None,
) -> RenderResult:
    """One-shot convenience: snapshot → HTML → optional save."""

    options = options or ReportOptions()
    snap = load_snapshot(db, options)
    return render_html_report(snap, path=path, options=options)


__all__ = [
    "e",
    "or_dash",
    "html_table",
    "severity_badge",
    "render_html_report",
    "generate_html_report",
]
