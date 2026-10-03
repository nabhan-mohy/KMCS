"""
kmcs.reporting.common
=====================

Shared, format-agnostic foundation for the KMCS reporting layer.

Design principles (enforced throughout the whole ``kmcs.reporting`` package):

1.  **Real data only.**  Every value that appears in a report is read from a
    KMCS database row or a core model produced by a real campaign.  The
    reporting layer never synthesises severities, crash counts, coverage
    numbers, timings, or reproduction outcomes.  Where a field is absent the
    renderers emit an explicit *unknown / not recorded* marker instead of a
    plausible-looking placeholder.

2.  **Determinism.**  Given the same snapshot and options, every renderer
    produces byte-identical output (timestamps embedded in documents are
    taken from the data itself; the single generation timestamp can be pinned
    via ``ReportOptions.generated_at``).  This makes reports diffable and
    suitable for regression baselines.

3.  **Defensive framing.**  Reports document memory-safety defects for
    triage and remediation.  They contain no exploit material: input files
    are referenced by path/hash/size, never inlined as "payloads"; stack
    traces are sanitizer evidence; severity is analytic triage guidance.

This module provides:

* :class:`Severity` ladder helpers shared by all formats (CVSS score →
  textual rating mapping, ordering, colour tokens).
* :func:`load_snapshot` — builds a :class:`ReportSnapshot` from a
  :class:`~kmcs.database.database.DatabaseManager` (findings, crashes,
  campaigns, targets, reproductions, minimizations, corpora, telemetry,
  stats) into plain JSON-safe dictionaries.
* :class:`ReportOptions` — pydantic validation of user-supplied report
  options (scope filters, redaction, section toggles, max sizes).
* Redaction helpers (absolute-path tail shortening, secret-ish token
  scrubbing) applied uniformly across formats.
* Small text/HTML-safe utilities used by several renderers.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# KMCS imports (tolerant of partial environments so the pure helpers here stay
# unit-testable even without SQLAlchemy installed)
# ---------------------------------------------------------------------------

try:  # pragma: no cover - exercised implicitly
    from kmcs.core.models import Severity as _CoreSeverity

    _CORE_SEVERITY_VALUES = [e.value for e in _CoreSeverity.__members__.values()]
except Exception:  # pragma: no cover
    _CoreSeverity = None
    _CORE_SEVERITY_VALUES = [
        "none",
        "informational",
        "low",
        "moderate",
        "medium",
        "high",
        "critical",
    ]

try:  # pragma: no cover
    from kmcs.core.exceptions import KMCSBaseError
except Exception:  # pragma: no cover

    class KMCSBaseError(Exception):  # type: ignore[no-redef]
        pass


# ---------------------------------------------------------------------------
# Constants & sentinels
# ---------------------------------------------------------------------------

#: Canonical "we do not know" marker.  Renderers must use this instead of
#: inventing values.  Formats translate it to their own idiom.
UNKNOWN = "<unknown>"

#: Marker used when a section was explicitly disabled via options.
SKIPPED = "<skipped>"

REPORT_SCHEMA_VERSION = "1.0"

#: Ordering of severity tokens (lowest first).  Includes aliases that appear
#: in historical rows.
SEVERITY_ORDER: Tuple[str, ...] = tuple(_CORE_SEVERITY_VALUES)

_SEVERITY_ALIASES: Dict[str, str] = {
    "info": "informational",
    "information": "informational",
    "note": "informational",
    "med": "medium",
    "mod": "moderate",
    "severe": "high",
    "fatal": "critical",
    "crit": "critical",
    "none": "none",
    "": "none",
}

#: Colour tokens per severity (used by HTML/SARIF/CSV styling hints).
SEVERITY_COLORS: Dict[str, str] = {
    "none": "#6b7280",
    "informational": "#3b82f6",
    "low": "#22c55e",
    "moderate": "#eab308",
    "medium": "#f97316",
    "high": "#ef4444",
    "critical": "#7f1d1d",
}

#: CVSS base-score band boundaries → canonical severity token.
_CVSS_BANDS: Sequence[Tuple[float, str]] = (
    (0.1, "none"),
    (4.0, "low"),
    (7.0, "moderate"),
    (9.0, "medium"),
    (10.1, "high"),
)
# NOTE: bands above map *conservatively*: we keep both 'moderate' and
# 'medium' because KMCS's ladder has them; CVSS 4.0-6.9 -> moderate,
# 7.0-8.9 -> medium, 9.0-10.0 -> high... but many tools treat >=9 as critical.
# We follow the KMCS core convention: >=9.0 -> high, and reserve 'critical'
# for explicit analyst/CVSS-critical assignments made upstream (analysis
# severity module), never inferred here.

_SECRET_PATTERNS: Sequence[Tuple[re.Pattern[str], str]] = (
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S+"), r"\1=<redacted>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<redacted-aws-key>"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "<redacted-github-token>"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "<redacted-slack-token>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "<redacted-private-key>"),
)


class ReportError(KMCSBaseError):
    """Raised for invalid reporting operations (bad scope, unwritable path...)."""


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------


def normalise_severity(value: Any, default: str = "none") -> str:
    """Coerce *value* to a canonical severity token.

    Accepts enum members, strings (case-insensitive, alias-tolerant), CVSS
    numeric scores (mapped through conservative bands), and ``None``.
    Never raises — falls back to *default*.
    """

    if value is None:
        return default
    if hasattr(value, "value") and not isinstance(value, (str, int, float)):
        value = value.value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            score = float(value)
        except (TypeError, ValueError):
            return default
        if math.isnan(score):
            return default
        score = max(0.0, min(10.0, score))
        for bound, token in _CVSS_BANDS:
            if score < bound:
                return token
        return "high"
    text = str(value).strip().lower().replace("_", "-")
    if text in SEVERITY_ORDER:
        return text
    aliased = _SEVERITY_ALIASES.get(text)
    if aliased:
        return aliased
    # tolerate suffixed forms like "high-severity"
    for token in SEVERITY_ORDER:
        if text.startswith(token):
            return token
    return default


def severity_rank(value: Any) -> int:
    """Integer rank of a severity token (higher == worse). Unknown -> -1."""

    token = normalise_severity(value, default="")
    if token == "":
        return -1
    return SEVERITY_ORDER.index(token)


def severity_worse(a: Any, b: Any) -> str:
    """Return whichever of *a*/*b* has the higher rank (ties -> a)."""

    return a if severity_rank(a) >= severity_rank(b) else b


def severity_color(value: Any) -> str:
    """Hex colour token for styling (HTML badge, CSV hint)."""

    return SEVERITY_COLORS.get(normalise_severity(value), SEVERITY_COLORS["none"])


def cvss_score_from_vector(vector: Optional[str]) -> Optional[float]:
    """Parse a CVSS 3.1 vector string and compute the base score honestly.

    Returns ``None`` when the vector is missing or malformed — the caller
    must then mark the score unknown rather than guess.  Implemented from
    the FIRST.org CVSS v3.1 specification equations.
    """

    if not vector:
        return None
    m = re.match(r"^\s*CVSS:3\.[01]/(.+)$", vector.strip())
    if not m:
        return None
    weights_exploitability = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "UI": {"N": 0.85, "R": 0.62},
        "PR": {
            "N": 0.85,
            "L": 0.62,
            "H": 0.27,
        },
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    }
    metrics: Dict[str, str] = {}
    for part in m.group(1).split("/"):
        if ":" not in part:
            return None
        key, _, val = part.partition(":")
        metrics[key.upper()] = val.upper()
    required = ("AV", "AC", "UI", "PR", "C", "I", "A")
    for key in required:
        if key not in metrics:
            return None
    scope_changed = metrics.get("S", "U") == "C"
    pr_key = dict(metrics)
    # PR weight depends on Scope per spec
    if scope_changed:
        pr_table = {"N": 0.85, "L": 0.68, "H": 0.23}
    else:
        pr_table = {"N": 0.85, "L": 0.62, "H": 0.27}
    for table_key in ("PR",):
        if metrics[table_key] not in pr_table:
            return None
    for key in ("AV", "AC", "UI", "C", "I", "A"):
        if metrics[key] not in weights_exploitability[key]:
            return None
    try:
        av = weights_exploitability["AV"][metrics["AV"]]
        ac = weights_exploitability["AC"][metrics["AC"]]
        ui = weights_exploitability["UI"][metrics["UI"]]
        pr = pr_table[metrics["PR"]]
        conf = weights_exploitability["C"][metrics["C"]]
        integ = weights_exploitability["I"][metrics["I"]]
        avail = weights_exploitability["A"][metrics["A"]]
    except KeyError:
        return None
    iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    # roundup to 1 decimal per CVSS spec
    return math.ceil(base * 10) / 10.0


# ---------------------------------------------------------------------------
# Text utilities
# ---------------------------------------------------------------------------


def short_path(path: Any, keep: int = 3) -> str:
    """Render a filesystem path safely: only the trailing *keep* components.

    Absolute prefixes are stripped so reports do not leak usernames or build
    layouts.  ``None``/empty renders as :data:`UNKNOWN`.
    """

    if path is None or str(path).strip() == "":
        return UNKNOWN
    raw = str(path)
    parts = [p for p in re.split(r"[\\/]+", raw) if p not in ("", ".")]
    if not parts:
        return UNKNOWN
    if len(parts) <= keep:
        joined = "/".join(parts)
        return joined if not raw.startswith("/") else "./" + joined
    return ".../" + "/".join(parts[-keep:])


def truncate(text: Any, limit: int = 4000, marker: str = "…[truncated]") -> str:
    """Truncate long strings (stack dumps, logs) to *limit* characters."""

    if text is None:
        return ""
    s = str(text)
    if limit < 0:
        return s
    if len(s) <= limit:
        return s
    head = s[: max(0, limit - len(marker))]
    return head + marker


def redact(text: Any) -> str:
    """Scrub obvious credential material from free-form text fields."""

    if text is None:
        return ""
    s = str(text)
    for pattern, repl in _SECRET_PATTERNS:
        s = pattern.sub(repl, s)
    return s


def html_escape(value: Any) -> str:
    """Minimal HTML escaping (kept dependency-free)."""

    if value is None:
        return ""
    s = str(value)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def csv_cell(value: Any) -> str:
    """Convert arbitrary value to a CSV-safe string (RFC 4180 quoting done
    later by the :mod:`csv` writer; here we only stringify + redact)."""

    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value) if isinstance(value, float) else str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, tuple, set)):
        return "; ".join(csv_cell(v) for v in sorted(map(str, value)))
    if isinstance(value, Mapping):
        return "; ".join(f"{k}={csv_cell(v)}" for k, v in sorted(value.items()))
    return redact(str(value))


def json_default(obj: Any) -> Any:
    """Fallback encoder for :func:`json.dumps` covering KMCS types."""

    if obj is None:
        return None
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return obj.hex()
    if hasattr(obj, "value") and hasattr(obj, "name"):  # Enum-like
        return obj.value
    if hasattr(obj, "model_dump"):  # pydantic v2
        return obj.model_dump(mode="json")
    if hasattr(obj, "dict") and callable(getattr(obj, "dict")):  # pydantic v1
        try:
            return obj.dict()
        except Exception:
            pass
    if hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
        try:
            return obj.to_dict()
        except Exception:
            pass
    if isinstance(obj, (set, frozenset)):
        return sorted(map(str, obj))
    return str(obj)


def stable_json(data: Any, *, indent: Optional[int] = None) -> str:
    """Deterministic JSON serialisation (sorted keys, KMCS fallbacks)."""

    return json.dumps(
        data,
        sort_keys=True,
        indent=indent,
        ensure_ascii=False,
        default=json_default,
        separators=(",", ": ") if indent is not None else (",", ":"),
    )


def content_hash(data: bytes | str) -> str:
    """SHA-256 hex digest used to stamp generated reports."""

    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Report options
# ---------------------------------------------------------------------------

try:  # pragma: no cover
    from pydantic import BaseModel, ConfigDict, Field, field_validator

    _HAVE_PYDANTIC = True
except Exception:  # pragma: no cover
    _HAVE_PYDANTIC = False


if _HAVE_PYDANTIC:

    class ReportOptions(BaseModel):
        """Validated options accepted by every renderer.

        All scoping is *filtering*, never fabrication: options can only
        narrow what gets rendered, never add content.
        """

        model_config = ConfigDict(extra="forbid", validate_assignment=True)

        title: Optional[str] = Field(default=None, description="Report title override.")
        include_sections: List[str] = Field(
            default_factory=lambda: [
                "summary",
                "campaigns",
                "targets",
                "findings",
                "crashes",
                "reproduction",
                "minimization",
                "corpora",
                "telemetry",
                "appendix",
            ],
            description="Ordered list of sections to render.",
        )
        exclude_sections: List[str] = Field(default_factory=list)
        max_findings: int = Field(default=500, ge=1, le=100_000)
        max_crashes: int = Field(default=2_000, ge=1, le=1_000_000)
        max_stack_frames: int = Field(default=32, ge=1, le=512)
        max_log_preview: int = Field(default=6_000, ge=0, le=1_000_000)
        severity_min: Optional[str] = Field(
            default=None, description="Only include items at/above this severity."
        )
        target_ids: List[str] = Field(default_factory=list)
        campaign_ids: List[str] = Field(default_factory=list)
        finding_ids: List[str] = Field(default_factory=list)
        states: List[str] = Field(default_factory=list, description="Finding/crash state filter.")
        redact_paths: bool = Field(default=True)
        include_raw_sanitizer_output: bool = Field(default=True)
        generated_at: Optional[str] = Field(
            default=None, description="Pin the generation timestamp for reproducibility."
        )
        locale_note: str = Field(default="en")

        @field_validator("severity_min")
        @classmethod
        def _check_sev(cls, v: Optional[str]) -> Optional[str]:
            if v is None:
                return None
            norm = normalise_severity(v, default="")
            if norm == "":
                raise ValueError(f"unknown severity filter: {v!r}")
            return norm

        def should_render(self, section: str) -> bool:
            if section in self.exclude_sections:
                return False
            return section in self.include_sections

        def ts(self) -> str:
            return self.generated_at or utcnow_iso()

else:  # pragma: no cover - minimal stand-in when pydantic missing

    @dataclass
    class ReportOptions:  # type: ignore[no-redef]
        title: Optional[str] = None
        include_sections: List[str] = field(default_factory=lambda: ["summary", "campaigns", "targets", "findings", "crashes", "reproduction", "minimization", "corpora", "telemetry", "appendix"])
        exclude_sections: List[str] = field(default_factory=list)
        max_findings: int = 500
        max_crashes: int = 2000
        max_stack_frames: int = 32
        max_log_preview: int = 6000
        severity_min: Optional[str] = None
        target_ids: List[str] = field(default_factory=list)
        campaign_ids: List[str] = field(default_factory=list)
        finding_ids: List[str] = field(default_factory=list)
        states: List[str] = field(default_factory=list)
        redact_paths: bool = True
        include_raw_sanitizer_output: bool = True
        generated_at: Optional[str] = None
        locale_note: str = "en"

        def should_render(self, section: str) -> bool:
            return section not in self.exclude_sections and section in self.include_sections

        def ts(self) -> str:
            return self.generated_at or utcnow_iso()


# ---------------------------------------------------------------------------
# Snapshot construction
# ---------------------------------------------------------------------------


def _row_to_dict(row: Any) -> Dict[str, Any]:
    """JSON-safe dict of a SQLAlchemy row or dataclass-like object."""

    if row is None:
        return {}
    if isinstance(row, Mapping):
        source: Iterable[Tuple[str, Any]] = row.items()
    elif hasattr(row, "_mapping"):  # SQLAlchemy Row / ORM instance
        source = row._mapping.items()
    elif hasattr(row, "__dict__"):
        source = [(k, v) for k, v in vars(row).items() if not k.startswith("_")]
    else:
        return json.loads(stable_json(row))
    out: Dict[str, Any] = {}
    for key, value in source:
        if isinstance(value, (datetime,)):
            out[key] = value.isoformat()
        elif isinstance(value, Path):
            out[key] = str(value)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            out[key] = value
        elif isinstance(value, (list, tuple)):
            out[key] = [_scalar_or_str(v) for v in value]
        elif isinstance(value, Mapping):
            out[key] = {str(k): _scalar_or_str(v) for k, v in value.items()}
        else:
            out[key] = json_default(value)
    return out


def _scalar_or_str(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    return json_default(value)


def _parse_json_field(raw: Any) -> Any:
    """Sanitizer/stack/fingerprint columns are stored as JSON text.

    Handles double-encoded values (a JSON string whose payload is itself
    JSON, produced by some storage paths / repr'd containers).
    """

    if raw is None or raw == "":
        return None
    value = raw
    for _ in range(3):  # bounded unwrap loop — never unbounded recursion
        if isinstance(value, (dict, list)):
            return value
        if not isinstance(value, str):
            break
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            # tolerate python-repr style lists/dicts written by legacy code
            import ast

            stripped = value.strip()
            if stripped[:1] in ("[", "{"):
                try:
                    value = ast.literal_eval(stripped)
                    continue
                except (ValueError, SyntaxError):
                    pass
            return {"unparsed": str(raw)[:2000]}
    if isinstance(value, str):
        return {"unparsed": value[:2000]} if value else None
    return value


def _normalise_stack_trace(parsed: Any) -> List[Any]:
    """Coerce stored stack-trace shapes into a flat list of frame dicts.

    KMCS persists :class:`~kmcs.core.models.StackTrace` objects, which land
    here as ``{"frames": [...], "signature": ...}`` (and occasionally as a
    repr-string inside that field).  Renderers always receive ``list[frame]``.
    """

    if parsed is None:
        return []
    if isinstance(parsed, list):
        frames = parsed
    elif isinstance(parsed, dict):
        inner = parsed.get("frames")
        if isinstance(inner, str):
            inner = _parse_json_field(inner)
        frames = inner if isinstance(inner, list) else ([parsed] if parsed else [])
    elif isinstance(parsed, str):
        again = _parse_json_field(parsed)
        return _normalise_stack_trace(again) if not isinstance(again, dict) or "unparsed" not in again else [parsed]
    else:
        return []
    out: List[Any] = []
    for fr in frames:
        if isinstance(fr, str):
            again = _parse_json_field(fr)
            fr = again if isinstance(again, dict) else {"function": fr}
        if isinstance(fr, dict):
            # StackFrame fields may arrive under either naming convention
            if "index" not in fr and "frame_index" in fr:
                fr = {**fr, "index": fr["frame_index"]}
            out.append(fr)
    return out


@dataclass
class ReportSnapshot:
    """Immutable, JSON-safe view of everything a report may show.

    Construction happens once (:func:`load_snapshot`) and every renderer
    reads from this structure, guaranteeing identical content across formats.
    """

    generated_at: str
    schema_version: str = REPORT_SCHEMA_VERSION
    tool: Dict[str, Any] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)
    targets: List[Dict[str, Any]] = field(default_factory=list)
    campaigns: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    crashes: List[Dict[str, Any]] = field(default_factory=list)
    reproductions: List[Dict[str, Any]] = field(default_factory=list)
    minimizations: List[Dict[str, Any]] = field(default_factory=list)
    corpora: List[Dict[str, Any]] = field(default_factory=list)
    telemetry: List[Dict[str, Any]] = field(default_factory=list)
    regressions: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # ---- derived indexes -------------------------------------------------
    def crash_by_id(self) -> Dict[str, Dict[str, Any]]:
        return {str(c.get("id")): c for c in self.crashes}

    def finding_by_id(self) -> Dict[str, Dict[str, Any]]:
        return {str(f.get("id")): f for f in self.findings}

    def target_by_id(self) -> Dict[str, Dict[str, Any]]:
        return {str(t.get("id")): t for t in self.targets}

    def campaign_by_id(self) -> Dict[str, Dict[str, Any]]:
        return {str(c.get("id")): c for c in self.campaigns}

    def to_dict(self) -> Dict[str, Any]:
        return _row_to_dict(self)

    def digest(self) -> str:
        return content_hash(stable_json(self.to_dict()))


def _apply_options_filter(snapshot: ReportSnapshot, options: ReportOptions) -> ReportSnapshot:
    """Narrow snapshot collections according to *options* (never widens)."""

    sev_floor = options.severity_min
    sev_floor_rank = severity_rank(sev_floor) if sev_floor else None

    def pass_sev(item: Mapping[str, Any]) -> bool:
        if sev_floor_rank is None:
            return True
        return severity_rank(item.get("severity")) >= sev_floor_rank

    def pass_states(item: Mapping[str, Any]) -> bool:
        if not options.states:
            return True
        return str(item.get("state", "")).lower() in {s.lower() for s in options.states}

    if options.target_ids:
        wanted_t = set(options.target_ids)
        snapshot.targets = [t for t in snapshot.targets if str(t.get("id")) in wanted_t]
    if options.campaign_ids:
        wanted_c = set(options.campaign_ids)
        snapshot.campaigns = [c for c in snapshot.campaigns if str(c.get("id")) in wanted_c]
    if options.finding_ids:
        wanted_f = set(options.finding_ids)
        snapshot.findings = [f for f in snapshot.findings if str(f.get("id")) in wanted_f]

    allowed_campaign_ids = {str(c.get("id")) for c in snapshot.campaigns} if options.campaign_ids else None
    allowed_target_ids = {str(t.get("id")) for t in snapshot.targets} if options.target_ids else None

    def scoped(item: Mapping[str, Any]) -> bool:
        if allowed_campaign_ids is not None and str(item.get("campaign_id", "")) not in allowed_campaign_ids:
            if "campaign_ids" in item:  # findings carry a list
                ids = item.get("campaign_ids") or []
                if not any(str(i) in allowed_campaign_ids for i in ids):
                    return False
            else:
                return False
        if allowed_target_ids is not None and str(item.get("target_id", "")) not in allowed_target_ids:
            return False
        return True

    snapshot.crashes = [c for c in snapshot.crashes if scoped(c) and pass_sev(c) and pass_states(c)]
    snapshot.findings = [f for f in snapshot.findings if pass_sev(f) and pass_states(f)]
    snapshot.crashes = snapshot.crashes[: options.max_crashes]
    snapshot.findings = snapshot.findings[: options.max_findings]

    kept_crash_ids = {str(c.get("id")) for c in snapshot.crashes}
    snapshot.reproductions = [r for r in snapshot.reproductions if str(r.get("crash_id")) in kept_crash_ids]
    snapshot.minimizations = [m for m in snapshot.minimizations if str(m.get("crash_id")) in kept_crash_ids]
    return snapshot


def load_snapshot(
    db: Any,
    options: Optional[ReportOptions] = None,
    *,
    tool_name: str = "KMCS",
    tool_version: str = "0.1.0",
) -> ReportSnapshot:
    """Read a complete, filtered, JSON-safe snapshot from *db*.

    *db* must expose the :class:`~kmcs.database.database.DatabaseManager`
    query surface (``find``, ``stats``).  Missing tables degrade to empty
    collections with a warning entry — they are never fabricated.
    """

    options = options or ReportOptions()
    snap = ReportSnapshot(generated_at=options.ts())
    snap.tool = {
        "name": tool_name,
        "version": tool_version,
        "purpose": "defensive fuzzing / memory-safety research reporting",
        "schema_version": REPORT_SCHEMA_VERSION,
    }

    try:
        snap.stats = dict(db.stats() or {})
    except Exception as exc:  # pragma: no cover
        snap.warnings.append(f"database stats unavailable: {exc}")

    from kmcs.database import models as dbm  # local import: keeps module light

    def _collect(model: Any, label: str) -> List[Dict[str, Any]]:
        try:
            rows = db.find(model)
            return [_row_to_dict(r) for r in rows]
        except Exception as exc:
            snap.warnings.append(f"could not read {label}: {exc}")
            return []

    snap.targets = _collect(dbm.TargetRow, "targets")
    snap.campaigns = _collect(dbm.CampaignRow, "campaigns")
    snap.findings = _collect(dbm.FindingRow, "findings")
    snap.corpora = _collect(dbm.CorpusRow, "corpora")
    snap.regressions = _collect(dbm.RegressionTestRow, "regression tests")

    # crashes: hydrate JSON columns into structured data
    crash_rows = _collect(dbm.CrashRow, "crashes")
    for c in crash_rows:
        c["signal"] = _parse_json_field(c.pop("signal_json", None))
        c["memory_access"] = _parse_json_field(c.pop("memory_access_json", None))
        c["location"] = _parse_json_field(c.pop("location_json", None))
        c["stack_trace"] = _normalise_stack_trace(_parse_json_field(c.pop("stack_trace_json", None)))
        c["sanitizer_report"] = _parse_json_field(c.pop("sanitizer_report_json", None))
        c["fingerprint"] = _parse_json_field(c.pop("fingerprint_json", None))
    snap.crashes = crash_rows

    snap.reproductions = _collect(dbm.ReproductionRow, "reproductions")
    for r in snap.reproductions:
        r["exit_codes"] = _parse_json_field(r.pop("exit_codes_json", None))
        r["signals"] = _parse_json_field(r.pop("signals_json", None))
        r["environment"] = _parse_json_field(r.pop("environment_json", None))
    snap.minimizations = _collect(dbm.MinimizationRow, "minimizations")

    finding_rows_extra = _collect(dbm.EvidenceRow, "evidence")
    ev_by_finding: Dict[str, List[Dict[str, Any]]] = {}
    for e in finding_rows_extra:
        ev_by_finding.setdefault(str(e.get("finding_id")), []).append(e)
    for f in snap.findings:
        f["location"] = _parse_json_field(f.pop("location_json", None))
        f["root_cause_hints"] = _parse_json_field(f.pop("root_cause_hints_json", None))
        f["evidence"] = _parse_json_field(f.pop("evidence_json", None)) or ev_by_finding.get(str(f.get("id")), [])
        f["references"] = _parse_json_field(f.pop("references_json", None)) or []

    telem = _collect(dbm.TelemetryRow, "telemetry")
    for t in telem:
        t["sample"] = _parse_json_field(t.pop("sample_json", None))
    snap.telemetry = telem

    snap = _apply_options_filter(snap, options)

    if options.redact_paths:
        _redact_snapshot(snap)
    return snap


def _redact_snapshot(snap: ReportSnapshot) -> None:
    """Apply path shortening + secret scrubbing in place."""

    path_fields = (
        "input_path", "binary_path", "source_root", "crash_dir", "work_dir",
        "log_path", "raw_log_path", "reproducer_path", "minimized_path",
        "original_path", "path",
    )
    text_fields = ("notes", "description", "summary", "disclosure_notes", "error")
    collections = (snap.targets, snap.campaigns, snap.crashes, snap.findings,
                   snap.reproductions, snap.minimizations, snap.corpora, snap.regressions)
    for coll in collections:
        for item in coll:
            for fld in path_fields:
                if fld in item and item[fld]:
                    item[fld] = short_path(item[fld])
            for fld in text_fields:
                if fld in item and isinstance(item[fld], str):
                    item[fld] = redact(truncate(item[fld], 20_000))
    for c in snap.crashes:
        st = c.get("stack_trace")
        if isinstance(st, list):
            for frame in st:
                if isinstance(frame, dict):
                    for key in ("file", "module", "path"):
                        if frame.get(key):
                            frame[key] = short_path(frame[key])
        loc = c.get("location")
        if isinstance(loc, dict) and loc.get("file"):
            loc["file"] = short_path(loc["file"])


# ---------------------------------------------------------------------------
# Shared summary computation (derived ONLY from snapshot contents)
# ---------------------------------------------------------------------------


def compute_summary(snap: ReportSnapshot) -> Dict[str, Any]:
    """Aggregate counters/breakdowns computed from actual rows.

    Everything here is arithmetic over the snapshot — no external knowledge,
    no invented estimates.
    """

    sev_counts: Dict[str, int] = {}
    class_counts: Dict[str, int] = {}
    san_counts: Dict[str, int] = {}
    engine_counts: Dict[str, int] = {}
    unique_fps = 0
    dup_count = 0
    repro_attempts = 0
    repro_successes = 0
    total_execs = 0
    execs_provenance = False
    total_runtime_ms = 0
    inputs_seen = set()

    for c in snap.crashes:
        sev = normalise_severity(c.get("severity"))
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        cls = str(c.get("crash_class") or UNKNOWN)
        class_counts[cls] = class_counts.get(cls, 0) + 1
        san = str(c.get("sanitizer") or UNKNOWN)
        san_counts[san] = san_counts.get(san, 0) + 1
        eng = str(c.get("engine") or UNKNOWN)
        engine_counts[eng] = engine_counts.get(eng, 0) + 1
        if c.get("fingerprint_digest"):
            unique_fps += 1
        if c.get("duplicate_of"):
            dup_count += 1
        occ = c.get("occurrence_count")
        if isinstance(occ, int) and occ > 0:
            pass  # occurrences tracked below via sum
        if c.get("input_hash"):
            inputs_seen.add(str(c["input_hash"]))
        if isinstance(c.get("runtime_ms"), (int, float)):
            total_runtime_ms += int(c["runtime_ms"])

    for f in snap.findings:
        sev = normalise_severity(f.get("severity"))
        # findings severities counted separately in findings block below

    for r in snap.reproductions:
        attempts = r.get("attempts")
        succ = r.get("successful_attempts")
        if isinstance(attempts, int):
            repro_attempts += attempts
        if isinstance(succ, int):
            repro_successes += succ

    for t in snap.telemetry:
        sample = t.get("sample") or {}
        if isinstance(sample, dict):
            ex = sample.get("executions") or sample.get("total_execs") or sample.get("execs_done")
            if isinstance(ex, (int, float)):
                total_execs += int(ex)
                execs_provenance = True

    finding_sev: Dict[str, int] = {}
    state_counts: Dict[str, int] = {}
    for f in snap.findings:
        sev = normalise_severity(f.get("severity"))
        finding_sev[sev] = finding_sev.get(sev, 0) + 1
        st = str(f.get("state") or UNKNOWN)
        state_counts[st] = state_counts.get(st, 0) + 1

    campaign_status: Dict[str, int] = {}
    for c in snap.campaigns:
        st = str(c.get("status") or UNKNOWN)
        campaign_status[st] = campaign_status.get(st, 0) + 1

    occurrences = sum(
        int(c["occurrence_count"]) for c in snap.crashes
        if isinstance(c.get("occurrence_count"), int)
    )

    worst = "none"
    for c in list(snap.crashes) + list(snap.findings):
        worst = severity_worse(worst, c.get("severity"))

    return {
        "counts": {
            "targets": len(snap.targets),
            "campaigns": len(snap.campaigns),
            "findings": len(snap.findings),
            "crashes": len(snap.crashes),
            "unique_input_hashes": len(inputs_seen),
            "crash_occurrences_total": occurrences,
            "duplicates_linked": dup_count,
            "fingerprints_recorded": unique_fps,
            "reproductions": len(snap.reproductions),
            "minimizations": len(snap.minimizations),
            "corpora": len(snap.corpora),
            "telemetry_samples": len(snap.telemetry),
            "regression_tests": len(snap.regressions),
        },
        "highest_observed_severity": worst,
        "crash_severity_breakdown": sev_counts,
        "finding_severity_breakdown": finding_sev,
        "crash_class_breakdown": class_counts,
        "sanitizer_breakdown": san_counts,
        "engine_breakdown": engine_counts,
        "finding_state_breakdown": state_counts,
        "campaign_status_breakdown": campaign_status,
        "reproduction": {
            "attempts_total": repro_attempts,
            "successes_total": repro_successes,
            "rate": (round(repro_successes / repro_attempts, 4) if repro_attempts else None),
        },
        "execution_totals": {
            "executions": total_execs if execs_provenance else None,
            "provenance": "summed from stored telemetry samples" if execs_provenance else "no telemetry recorded",
        },
        "crash_runtime_ms_total": total_runtime_ms,
        "warnings": list(snap.warnings),
    }


# ---------------------------------------------------------------------------
# Renderer base
# ---------------------------------------------------------------------------


@dataclass
class RenderResult:
    """Outcome of a render operation — written file plus integrity metadata."""

    fmt: str
    path: Optional[str]
    content_hash: str
    size_bytes: int
    generated_at: str
    snapshot_digest: str
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.fmt,
            "path": self.path,
            "content_hash": self.content_hash,
            "size_bytes": self.size_bytes,
            "generated_at": self.generated_at,
            "snapshot_digest": self.snapshot_digest,
            "warnings": self.warnings,
        }


def write_report(path: str | os.PathLike[str], text: str) -> int:
    """Atomically write *text* to *path*; returns bytes written."""

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    data = text.encode("utf-8")
    tmp.write_bytes(data)
    os.replace(tmp, p)
    return len(data)


def resolve_out_path(path: Any, fmt: str) -> str:
    """Normalise an output path, appending the format extension if needed."""

    if path is None:
        raise ReportError("output path is required")
    p = Path(str(path))
    suffixes = {
        "html": {".html", ".htm"},
        "json": {".json"},
        "markdown": {".md", ".markdown"},
        "csv": {".csv", ".zip"},
        "sarif": {".sarif", ".json"},
    }.get(fmt, set())
    if p.suffix.lower() not in suffixes:
        ext = {"markdown": ".md", "sarif": ".sarif"}.get(fmt, "." + fmt)
        p = p.with_name(p.name + ext)
    return str(p)


__all__ = [
    "UNKNOWN",
    "SKIPPED",
    "REPORT_SCHEMA_VERSION",
    "SEVERITY_ORDER",
    "SEVERITY_COLORS",
    "ReportError",
    "ReportOptions",
    "ReportSnapshot",
    "RenderResult",
    "normalise_severity",
    "severity_rank",
    "severity_worse",
    "severity_color",
    "cvss_score_from_vector",
    "short_path",
    "truncate",
    "redact",
    "html_escape",
    "csv_cell",
    "json_default",
    "stable_json",
    "content_hash",
    "utcnow_iso",
    "load_snapshot",
    "compute_summary",
    "write_report",
    "resolve_out_path",
]
