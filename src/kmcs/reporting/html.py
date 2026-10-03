# KMCS HTML Report
# ================
#
# Browser-friendly rendering of KMCS findings.
#
# The reporting layer is a presenter, not an analyzer. It does not
# parse crashes, classify findings, compute severities, run targets,
# or fingerprint inputs. Every subsystem that produces those values
# has already done so before the reporter is invoked; the reporter's
# job is to render the resulting records into a self-contained HTML
# document.
#
# What this module does own
# -------------------------
#
# * A stable, well-documented container type (:class:`ReportBundle`)
#   that callers populate from real KMCS subsystems.
#
# * Factory helpers that pull fields out of the analysis, reproduction,
#   and regression subsystems without inventing values. When a field
#   is not present on a source record, it is left ``None`` and the
#   report displays "not available" — never a fabricated default.
#
# * A complete, dependency-free HTML renderer. The output is a single
#   document with embedded CSS; it can be emailed, archived, or served
#   from a static file server without any external assets.
#
# What this module explicitly does not do
# ---------------------------------------
#
# * It does not compute severity. When the analysis subsystem has
#   assigned a severity, the reporter renders it verbatim. When it has
#   not, the report says "not classified".
#
# * It does not parse crashes. When a finding's source record has
#   already been parsed by :mod:`kmcs.analysis.crash_parser`, the
#   parsed fields are rendered. Otherwise the raw output is rendered
#   as text.
#
# * It does not re-run targets. Reproduction and regression status
#   are displayed exactly as they were reported by the respective
#   subsystems.
#
# * It does not aggregate counts that were not provided. The summary
#   section counts only what is present in the bundle: if a caller
#   supplies three findings, the summary says three. It never
#   extrapolates.
#
# Integration points
# ------------------
#
# The reporter delegates to:
#
#   * :mod:`kmcs.analysis.crash_parser` — when the caller supplies raw
#     crash output without a parsed record, and only when the parser
#     is importable. Otherwise the raw output is rendered verbatim.
#
#   * :mod:`kmcs.analysis.classifier` — consulted for a human-readable
#     label when the caller supplies a classification but no label.
#
#   * :mod:`kmcs.analysis.severity` — consulted for a display string
#     when the caller supplies a severity value but no label.
#
#   * :mod:`kmcs.analysis.fingerprint` — consulted for a display
#     fingerprint when the caller supplies crash bytes but no
#     pre-computed fingerprint.
#
# All delegation is defensive: a missing subsystem degrades to raw
# rendering, never to an error.
#
# Input safety
# ------------
#
# All user-supplied strings (target names, tags, crash output, stack
# frame fields) are escaped before being written into the document.
# Raw crash output is rendered inside ``<pre>`` blocks with HTML
# entities escaped, so it cannot inject markup even when it contains
# sequences that look like tags.
#
# Determinism
# -----------
#
# Given the same bundle, the renderer produces byte-identical output.
# There is no randomness, no locale-dependent formatting, and no
# reliance on wall-clock time except where the bundle itself carries
# timestamps.
#
# Compatibility
# ------------
#
# Python 3.10+.

from __future__ import annotations

import html
import json
import logging
import re
from dataclasses import dataclass, field, asdict, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TYPE_CHECKING,
    Union,
)


# ---------------------------------------------------------------------------
# Optional subsystem imports
# ---------------------------------------------------------------------------
#
# These imports are defensive. A missing subsystem does not prevent
# the reporter from working; it simply limits the fields the reporter
# can derive on its own.

try:
    from ..analysis.crash_parser import parse_crash_output
    _HAVE_CRASH_PARSER = True
except ImportError:  # pragma: no cover - depends on layout
    parse_crash_output = None  # type: ignore[assignment]
    _HAVE_CRASH_PARSER = False

try:
    from ..analysis.classifier import classify_crash
    _HAVE_CLASSIFIER = True
except ImportError:  # pragma: no cover
    classify_crash = None  # type: ignore[assignment]
    _HAVE_CLASSIFIER = False

try:
    from ..analysis.severity import assign_severity
    _HAVE_SEVERITY = True
except ImportError:  # pragma: no cover
    assign_severity = None  # type: ignore[assignment]
    _HAVE_SEVERITY = False

try:
    from ..analysis.fingerprint import extract_features
    _HAVE_FINGERPRINT = True
except ImportError:  # pragma: no cover
    extract_features = None  # type: ignore[assignment]
    _HAVE_FINGERPRINT = False


if TYPE_CHECKING:
    from ..campaigns.manager import Campaign
    from ..corpus.manager import CorpusStats, CorpusEntry
    from ..reproduction.runner import ReproductionResult
    from ..reproduction.regression import RegressionCase, RegressionRun


__all__ = [
    "HtmlReporter",
    "ReportBundle",
    "ReportFinding",
    "ReportMetadata",
    "ReportCampaignSummary",
    "ReportCorpusSummary",
    "ReportTheme",
    "SeverityLevel",
    "ReportError",
    "MissingDataError",
    "render_html",
    "write_html",
    "DEFAULT_TITLE",
    "DEFAULT_THEME",
    "DEFAULT_MAX_OUTPUT_CHARS",
    "GENERATOR_NAME",
    "GENERATOR_VERSION",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#: Default report title when the caller does not supply one.
DEFAULT_TITLE: str = "KMCS Security Report"

#: Default visual theme.
DEFAULT_THEME: str = "light"

#: Default cap on the number of characters of raw crash output
#: rendered inline. Longer output is truncated with a marker.
DEFAULT_MAX_OUTPUT_CHARS: int = 40_000

#: Name of the generator, embedded in the report footer.
GENERATOR_NAME: str = "KMCS"

#: Version of the generator, embedded in the report footer.
GENERATOR_VERSION: str = "1.0.0"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ReportError(Exception):
    """Base class for reporting errors."""


class MissingDataError(ReportError):
    """Raised when a bundle is missing data required for rendering.

    The HTML reporter is deliberately forgiving — it will render a
    bundle with almost nothing in it — but a bundle with no title at
    all, or with findings that have no identifier, is treated as a
    programming error on the caller's side.
    """


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ReportTheme(str, Enum):
    """Visual theme for the rendered report."""

    LIGHT = "light"
    DARK = "dark"


class SeverityLevel(str, Enum):
    """Canonical severity labels.

    The set matches the labels produced by :mod:`kmcs.analysis.severity`
    in the current version of the platform. Additional levels may be
    defined by future versions; the reporter maps unknown labels to a
    neutral style and displays them verbatim.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: Any) -> "SeverityLevel":
        """Best-effort coercion of an arbitrary value to a level.

        Unknown values become :attr:`UNKNOWN`. The coercion never
        raises: severity in the report is a display hint, not a
        decision input.
        """
        if value is None:
            return cls.UNKNOWN
        if isinstance(value, SeverityLevel):
            return value
        text = str(value).strip().lower()
        if not text:
            return cls.UNKNOWN
        for member in cls:
            if member.value == text:
                return member
        # Common aliases.
        aliases = {
            "info": cls.INFORMATIONAL,
            "informational": cls.INFORMATIONAL,
            "moderate": cls.MEDIUM,
            "med": cls.MEDIUM,
            "severe": cls.HIGH,
            "warning": cls.MEDIUM,
            "warn": cls.MEDIUM,
            "note": cls.LOW,
            "unknown": cls.UNKNOWN,
        }
        return aliases.get(text, cls.UNKNOWN)

    @property
    def display_name(self) -> str:
        """Return the human-readable label for this level."""
        return {
            SeverityLevel.CRITICAL: "Critical",
            SeverityLevel.HIGH: "High",
            SeverityLevel.MEDIUM: "Medium",
            SeverityLevel.LOW: "Low",
            SeverityLevel.INFORMATIONAL: "Informational",
            SeverityLevel.UNKNOWN: "Not classified",
        }[self]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReportMetadata:
    """Top-level metadata for a report.

    All fields are optional. The reporter never invents values: a
    missing field is rendered as "not available" in the output rather
    than replaced with a default.
    """

    title: str = DEFAULT_TITLE
    subtitle: Optional[str] = None
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    generator: str = f"{GENERATOR_NAME} {GENERATOR_VERSION}"
    target_description: Optional[str] = None
    campaign_id: Optional[str] = None
    campaign_name: Optional[str] = None
    sanitizer: Optional[str] = None
    fuzzer: Optional[str] = None
    notes: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "subtitle": self.subtitle,
            "generated_at": self.generated_at.isoformat(),
            "generator": self.generator,
            "target_description": self.target_description,
            "campaign_id": self.campaign_id,
            "campaign_name": self.campaign_name,
            "sanitizer": self.sanitizer,
            "fuzzer": self.fuzzer,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class ReportCampaignSummary:
    """A summarised view of a campaign for inclusion in a report.

    This is a flattened, read-only projection. It does not carry the
    live :class:`~kmcs.campaigns.manager.Campaign` object; the reporter
    works from snapshots so that the resulting HTML is stable and
    reproducible.
    """

    campaign_id: Optional[str] = None
    name: Optional[str] = None
    state: Optional[str] = None
    fuzzer: Optional[str] = None
    sanitizer: Optional[str] = None
    target_command: Optional[str] = None
    workers: Optional[int] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    runtime_seconds: Optional[float] = None
    total_executions: Optional[int] = None
    total_crashes: Optional[int] = None
    total_hangs: Optional[int] = None
    coverage_percent: Optional[float] = None
    corpus_size: Optional[int] = None
    error_message: Optional[str] = None
    tags: FrozenSet[str] = field(default_factory=frozenset)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "state": self.state,
            "fuzzer": self.fuzzer,
            "sanitizer": self.sanitizer,
            "target_command": self.target_command,
            "workers": self.workers,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "runtime_seconds": self.runtime_seconds,
            "total_executions": self.total_executions,
            "total_crashes": self.total_crashes,
            "total_hangs": self.total_hangs,
            "coverage_percent": self.coverage_percent,
            "corpus_size": self.corpus_size,
            "error_message": self.error_message,
            "tags": sorted(self.tags),
        }

    @classmethod
    def from_campaign(cls, campaign: "Campaign") -> "ReportCampaignSummary":
        """Build a summary from a live :class:`Campaign`.

        Only fields that actually exist on the campaign are read. The
        function never invents a value: a missing attribute becomes
        ``None``.
        """
        config = getattr(campaign, "config", None)
        stats = getattr(campaign, "stats", None)
        state = getattr(campaign, "state", None)
        state_value = getattr(state, "value", None)
        if isinstance(state_value, str):
            state_str: Optional[str] = state_value
        elif state is None:
            state_str = None
        else:
            state_str = str(state)

        def _get(obj: Any, name: str, default: Any = None) -> Any:
            if obj is None:
                return default
            return getattr(obj, name, default)

        return cls(
            campaign_id=_get(campaign, "campaign_id"),
            name=_get(config, "name"),
            state=state_str,
            fuzzer=_get(config, "fuzzer"),
            sanitizer=_get(config, "sanitizer"),
            target_command=_get(config, "target_command"),
            workers=_get(config, "workers"),
            started_at=_get(campaign, "started_at"),
            finished_at=_get(campaign, "finished_at"),
            runtime_seconds=_get(campaign, "runtime_seconds"),
            total_executions=_get(stats, "total_executions"),
            total_crashes=_get(stats, "total_crashes"),
            total_hangs=_get(stats, "total_hangs"),
            coverage_percent=_get(stats, "coverage_percent"),
            corpus_size=_get(stats, "corpus_size"),
            error_message=_get(campaign, "error_message"),
            tags=frozenset(_get(config, "tags", frozenset()) or frozenset()),
        )


@dataclass(frozen=True)
class ReportCorpusSummary:
    """A summarised view of a corpus for inclusion in a report."""

    root: Optional[str] = None
    total_entries: Optional[int] = None
    total_bytes: Optional[int] = None
    smallest_size: Optional[int] = None
    largest_size: Optional[int] = None
    mean_size: Optional[float] = None
    median_size: Optional[float] = None
    unique_digests: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root,
            "total_entries": self.total_entries,
            "total_bytes": self.total_bytes,
            "smallest_size": self.smallest_size,
            "largest_size": self.largest_size,
            "mean_size": self.mean_size,
            "median_size": self.median_size,
            "unique_digests": self.unique_digests,
        }

    @classmethod
    def from_stats(cls, stats: "CorpusStats") -> "ReportCorpusSummary":
        """Build a summary from a :class:`~kmcs.corpus.manager.CorpusStats`."""
        if stats is None:
            return cls()
        root = getattr(stats, "root", None)
        return cls(
            root=str(root) if root is not None else None,
            total_entries=getattr(stats, "total_entries", None),
            total_bytes=getattr(stats, "total_bytes", None),
            smallest_size=getattr(stats, "smallest_size", None),
            largest_size=getattr(stats, "largest_size", None),
            mean_size=getattr(stats, "mean_size", None),
            median_size=getattr(stats, "median_size", None),
            unique_digests=getattr(stats, "unique_digests", None),
        )


@dataclass(frozen=True)
class ReportFinding:
    """A single finding rendered in the report.

    Every field is optional; a finding with only an identifier renders
    successfully. The reporter never synthesizes values: a missing
    field is displayed as "not available", and the corresponding row
    is omitted from tables that would otherwise be misleading.
    """

    finding_id: str
    title: str
    severity: Optional[str] = None
    crash_kind: Optional[str] = None
    classification: Optional[str] = None
    classification_label: Optional[str] = None
    fingerprint: Optional[str] = None
    sanitizer: Optional[str] = None

    # Input information
    input_digest: Optional[str] = None
    input_size: Optional[int] = None
    input_path: Optional[str] = None

    # Process outcome
    exit_code: Optional[int] = None
    signal_number: Optional[int] = None
    signal_name: Optional[str] = None
    timed_out: Optional[bool] = None

    # Crash evidence
    raw_output: Optional[str] = None
    stack_frames: Tuple[Mapping[str, Any], ...] = ()
    source_location: Optional[Mapping[str, Any]] = None
    fault_address: Optional[str] = None
    access_type: Optional[str] = None

    # Reproduction and regression
    reproduction_status: Optional[str] = None
    reproduction_attempts: Optional[int] = None
    reproduction_matched: Optional[int] = None
    regression_status: Optional[str] = None
    regression_runs: Optional[int] = None

    # Provenance
    discovered_at: Optional[datetime] = None
    discovered_by: Optional[str] = None
    tags: FrozenSet[str] = field(default_factory=frozenset)
    notes: Tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def severity_level(self) -> SeverityLevel:
        return SeverityLevel.parse(self.severity)

    @property
    def display_severity(self) -> str:
        """Return a human-readable severity label."""
        if self.severity is None:
            return SeverityLevel.UNKNOWN.display_name
        return self.severity_level.display_name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "crash_kind": self.crash_kind,
            "classification": self.classification,
            "classification_label": self.classification_label,
            "fingerprint": self.fingerprint,
            "sanitizer": self.sanitizer,
            "input_digest": self.input_digest,
            "input_size": self.input_size,
            "input_path": self.input_path,
            "exit_code": self.exit_code,
            "signal_number": self.signal_number,
            "signal_name": self.signal_name,
            "timed_out": self.timed_out,
            "raw_output": self.raw_output,
            "stack_frames": [dict(f) for f in self.stack_frames],
            "source_location": (
                dict(self.source_location) if self.source_location else None
            ),
            "fault_address": self.fault_address,
            "access_type": self.access_type,
            "reproduction_status": self.reproduction_status,
            "reproduction_attempts": self.reproduction_attempts,
            "reproduction_matched": self.reproduction_matched,
            "regression_status": self.regression_status,
            "regression_runs": self.regression_runs,
            "discovered_at": (
                self.discovered_at.isoformat() if self.discovered_at else None
            ),
            "discovered_by": self.discovered_by,
            "tags": sorted(self.tags),
            "notes": list(self.notes),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ReportBundle:
    """The complete set of data to render.

    A bundle is immutable so that a rendered report cannot be affected
    by later mutation of the underlying records. Callers construct a
    bundle once, pass it to the reporter, and discard it.
    """

    metadata: ReportMetadata = field(default_factory=ReportMetadata)
    campaign: Optional[ReportCampaignSummary] = None
    corpus: Optional[ReportCorpusSummary] = None
    findings: Tuple[ReportFinding, ...] = ()
    supplemental_sections: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.metadata.title:
            raise MissingDataError("report metadata must have a title")
        seen: set[str] = set()
        for finding in self.findings:
            if not finding.finding_id:
                raise MissingDataError("every finding must have an identifier")
            if finding.finding_id in seen:
                raise MissingDataError(
                    f"duplicate finding identifier: {finding.finding_id}"
                )
            seen.add(finding.finding_id)

    # ------------------------------------------------------------------
    # Derived counts (all computed from supplied data, never invented)
    # ------------------------------------------------------------------

    def count_by_severity(self) -> Dict[str, int]:
        """Return a count of findings per severity level.

        Findings without an explicit severity are counted under
        ``"unknown"``. The dict always contains every canonical level
        so that tables render consistently.
        """
        counts: Dict[str, int] = {level.value: 0 for level in SeverityLevel}
        for finding in self.findings:
            counts[finding.severity_level.value] += 1
        return counts

    def count_by_classification(self) -> Dict[str, int]:
        """Return a count of findings per classification label."""
        counts: Dict[str, int] = {}
        for finding in self.findings:
            key = (
                finding.classification_label
                or finding.classification
                or finding.crash_kind
                or "unclassified"
            )
            counts[key] = counts.get(key, 0) + 1
        return counts

    def reproduced_count(self) -> int:
        """Return the number of findings marked as reproduced.

        A finding counts as reproduced when its
        :attr:`ReportFinding.reproduction_status` is one of
        ``"reproduced"``, ``"REPRODUCED"``, or ``ReproductionStatus.REPRODUCED``
        (the string form is normalised). No other status counts.
        """
        total = 0
        for finding in self.findings:
            status = finding.reproduction_status
            if status is None:
                continue
            text = str(status).strip().lower()
            if text == "reproduced":
                total += 1
        return total

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "campaign": self.campaign.to_dict() if self.campaign else None,
            "corpus": self.corpus.to_dict() if self.corpus else None,
            "findings": [f.to_dict() for f in self.findings],
            "supplemental_sections": [
                {"title": t, "body": b} for t, b in self.supplemental_sections
            ],
            "counts": {
                "total_findings": len(self.findings),
                "by_severity": self.count_by_severity(),
                "by_classification": self.count_by_classification(),
                "reproduced": self.reproduced_count(),
            },
        }

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_components(
        cls,
        *,
        title: str = DEFAULT_TITLE,
        subtitle: Optional[str] = None,
        campaign: Optional["Campaign"] = None,
        corpus_stats: Optional["CorpusStats"] = None,
        findings: Optional[Iterable[ReportFinding]] = None,
        supplemental_sections: Optional[Iterable[Tuple[str, str]]] = None,
        target_description: Optional[str] = None,
        sanitizer: Optional[str] = None,
        fuzzer: Optional[str] = None,
        notes: Optional[Iterable[str]] = None,
    ) -> "ReportBundle":
        """Build a bundle from live subsystem objects.

        This is the recommended entry point for callers that have
        live objects rather than pre-snapshotted ones. It performs the
        projection from each subsystem's native type to the reporter's
        snapshot type, and never invents values.

        Parameters
        ----------
        title:
            Report title.
        subtitle:
            Optional subtitle.
        campaign:
            Optional live :class:`Campaign`.
        corpus_stats:
            Optional :class:`CorpusStats`.
        findings:
            Optional iterable of :class:`ReportFinding`.
        supplemental_sections:
            Optional iterable of ``(title, html_body)`` pairs. Bodies
            are inserted verbatim; callers are responsible for
            escaping their own content.
        target_description:
            Human-readable description of the target.
        sanitizer:
            Sanitizer identifier, e.g. ``"asan"``.
        fuzzer:
            Fuzzer identifier, e.g. ``"aflpp"``.
        notes:
            Free-form notes displayed in the header.
        """
        campaign_summary = (
            ReportCampaignSummary.from_campaign(campaign)
            if campaign is not None
            else None
        )
        corpus_summary = (
            ReportCorpusSummary.from_stats(corpus_stats)
            if corpus_stats is not None
            else None
        )

        # Prefer campaign-supplied metadata when the caller did not
        # override it, but never fabricate: a missing campaign field
        # remains None.
        if campaign is not None:
            config = getattr(campaign, "config", None)
            if target_description is None:
                cmd = getattr(config, "target_command", None)
                if cmd:
                    target_description = str(cmd)
            if sanitizer is None:
                sanitizer = getattr(config, "sanitizer", None)
            if fuzzer is None:
                fuzzer = getattr(config, "fuzzer", None)

        metadata = ReportMetadata(
            title=title,
            subtitle=subtitle,
            target_description=target_description,
            campaign_id=getattr(campaign, "campaign_id", None),
            campaign_name=getattr(getattr(campaign, "config", None), "name", None),
            sanitizer=sanitizer,
            fuzzer=fuzzer,
            notes=tuple(notes or ()),
        )

        return cls(
            metadata=metadata,
            campaign=campaign_summary,
            corpus=corpus_summary,
            findings=tuple(findings or ()),
            supplemental_sections=tuple(supplemental_sections or ()),
        )


# ---------------------------------------------------------------------------
# HTML escaping and rendering helpers
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    """Escape a value for inclusion in HTML text content.

    ``None`` becomes an em-dash placeholder so that tables render
    consistently. Lists and tuples are joined with a comma. Every
    other value is stringified and escaped.
    """
    if value is None:
        return '<span class="na">—</span>'
    if isinstance(value, (list, tuple, set, frozenset)):
        if not value:
            return '<span class="na">—</span>'
        return ", ".join(_esc(v) for v in value)
    return html.escape(str(value), quote=True)


def _esc_attr(value: Any) -> str:
    """Escape a value for inclusion in an HTML attribute."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _format_datetime(value: Optional[datetime]) -> str:
    """Format a datetime for display, or return a placeholder."""
    if value is None:
        return '<span class="na">—</span>'
    try:
        iso = value.isoformat(timespec="seconds")
    except Exception:  # noqa: BLE001
        iso = str(value)
    return f'<time datetime="{_esc_attr(iso)}">{html.escape(iso)}</time>'


def _format_bytes(value: Optional[int]) -> str:
    """Format a byte count with a human-readable suffix."""
    if value is None:
        return '<span class="na">—</span>'
    try:
        n = int(value)
    except (TypeError, ValueError):
        return _esc(value)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(n)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{n} B"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{n} B"


def _format_seconds(value: Optional[float]) -> str:
    """Format a duration in seconds with a human-readable suffix."""
    if value is None:
        return '<span class="na">—</span>'
    try:
        s = float(value)
    except (TypeError, ValueError):
        return _esc(value)
    if s < 1.0:
        return f"{s * 1000:.0f} ms"
    if s < 60.0:
        return f"{s:.2f} s"
    minutes, seconds = divmod(s, 60.0)
    if minutes < 60.0:
        return f"{int(minutes)}m {seconds:.0f}s"
    hours, minutes = divmod(minutes, 60.0)
    return f"{int(hours)}h {int(minutes)}m {seconds:.0f}s"


def _format_percent(value: Optional[float]) -> str:
    """Format a percentage value."""
    if value is None:
        return '<span class="na">—</span>'
    try:
        return f"{float(value):.2f} %"
    except (TypeError, ValueError):
        return _esc(value)


def _slugify(text: str) -> str:
    """Return a URL-safe slug suitable for use as an HTML id.

    Collapses runs of non-alphanumeric characters to a single hyphen,
    trims leading and trailing hyphens, and lowercases the result. If
    the result is empty, returns ``"section"``.
    """
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return slug or "section"


def _truncate_text(text: str, limit: int) -> Tuple[str, bool]:
    """Truncate text to ``limit`` characters; return (text, truncated)."""
    if limit <= 0 or len(text) <= limit:
        return text, False
    return text[:limit], True


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------


_CSS_BASE = """
:root {
    --bg: #ffffff;
    --bg-alt: #f6f8fa;
    --fg: #1f2328;
    --fg-muted: #57606a;
    --border: #d0d7de;
    --border-strong: #afb8c1;
    --accent: #0969da;
    --accent-fg: #ffffff;
    --code-bg: #f6f8fa;
    --code-fg: #24292f;
    --pre-bg: #f6f8fa;
    --link: #0969da;
    --shadow: 0 1px 3px rgba(27, 31, 36, 0.12);
    --sev-critical-bg: #ffebe9;
    --sev-critical-fg: #cf222e;
    --sev-critical-border: #ff818266;
    --sev-high-bg: #fff1e5;
    --sev-high-fg: #bc4c00;
    --sev-high-border: #fb8f4466;
    --sev-medium-bg: #fff8c5;
    --sev-medium-fg: #7d4e00;
    --sev-medium-border: #d4a72c66;
    --sev-low-bg: #ddf4ff;
    --sev-low-fg: #0550ae;
    --sev-low-border: #54aeff66;
    --sev-info-bg: #f6f8fa;
    --sev-info-fg: #57606a;
    --sev-info-border: #d0d7de;
    --sev-unknown-bg: #f6f8fa;
    --sev-unknown-fg: #57606a;
    --sev-unknown-border: #d0d7de;
}

html[data-theme="dark"] {
    --bg: #0d1117;
    --bg-alt: #161b22;
    --fg: #e6edf3;
    --fg-muted: #8b949e;
    --border: #30363d;
    --border-strong: #484f58;
    --accent: #2f81f7;
    --accent-fg: #ffffff;
    --code-bg: #161b22;
    --code-fg: #e6edf3;
    --pre-bg: #161b22;
    --link: #2f81f7;
    --shadow: 0 1px 3px rgba(0, 0, 0, 0.6);
    --sev-critical-bg: #3c1618;
    --sev-critical-fg: #ff7b72;
    --sev-critical-border: #ff7b7266;
    --sev-high-bg: #3d1e0a;
    --sev-high-fg: #ffa657;
    --sev-high-border: #ffa65766;
    --sev-medium-bg: #3a2d00;
    --sev-medium-fg: #d29922;
    --sev-medium-border: #d2992266;
    --sev-low-bg: #0c2d6b;
    --sev-low-fg: #79c0ff;
    --sev-low-border: #79c0ff66;
    --sev-info-bg: #161b22;
    --sev-info-fg: #8b949e;
    --sev-info-border: #30363d;
    --sev-unknown-bg: #161b22;
    --sev-unknown-fg: #8b949e;
    --sev-unknown-border: #30363d;
}

* { box-sizing: border-box; }

body {
    margin: 0;
    padding: 0;
    background: var(--bg);
    color: var(--fg);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica,
                 Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
    font-size: 15px;
    line-height: 1.55;
}

header.report-header {
    padding: 32px 40px 24px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-alt);
}

header.report-header h1 {
    margin: 0 0 6px;
    font-size: 26px;
    font-weight: 600;
}

header.report-header .subtitle {
    margin: 0 0 18px;
    color: var(--fg-muted);
    font-size: 15px;
}

dl.metadata {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 4px 18px;
    margin: 0;
    font-size: 14px;
}

dl.metadata dt {
    color: var(--fg-muted);
    font-weight: 500;
}

dl.metadata dd {
    margin: 0;
    word-break: break-word;
}

nav.toc {
    padding: 16px 40px;
    border-bottom: 1px solid var(--border);
    background: var(--bg);
}

nav.toc h2 {
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--fg-muted);
    margin: 0 0 8px;
}

nav.toc ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-wrap: wrap;
    gap: 8px 20px;
}

nav.toc a {
    color: var(--link);
    text-decoration: none;
    font-size: 14px;
}

nav.toc a:hover {
    text-decoration: underline;
}

main {
    padding: 32px 40px 48px;
    max-width: 1100px;
    margin: 0 auto;
}

section {
    margin-bottom: 42px;
}

section > h2 {
    font-size: 20px;
    font-weight: 600;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
    margin: 0 0 18px;
}

section > h3 {
    font-size: 16px;
    font-weight: 600;
    margin: 24px 0 12px;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
    margin: 0 0 16px;
}

table th {
    text-align: left;
    padding: 8px 12px;
    background: var(--bg-alt);
    border: 1px solid var(--border);
    font-weight: 600;
    color: var(--fg-muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

table td {
    padding: 8px 12px;
    border: 1px solid var(--border);
    vertical-align: top;
    word-break: break-word;
}

table tr:nth-child(even) td {
    background: var(--bg-alt);
}

code, pre, kbd, samp {
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
                 "Liberation Mono", monospace;
    font-size: 13px;
}

code {
    background: var(--code-bg);
    color: var(--code-fg);
    padding: 2px 6px;
    border-radius: 4px;
}

pre {
    background: var(--pre-bg);
    color: var(--code-fg);
    padding: 14px 16px;
    border-radius: 6px;
    border: 1px solid var(--border);
    overflow-x: auto;
    max-height: 500px;
    white-space: pre-wrap;
    word-break: break-word;
    line-height: 1.45;
}

pre.scroll {
    max-height: 400px;
    overflow-y: auto;
}

.badge {
    display: inline-block;
    padding: 2px 10px;
    font-size: 12px;
    font-weight: 600;
    border-radius: 999px;
    border: 1px solid transparent;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}

.badge-critical { background: var(--sev-critical-bg); color: var(--sev-critical-fg); border-color: var(--sev-critical-border); }
.badge-high { background: var(--sev-high-bg); color: var(--sev-high-fg); border-color: var(--sev-high-border); }
.badge-medium { background: var(--sev-medium-bg); color: var(--sev-medium-fg); border-color: var(--sev-medium-border); }
.badge-low { background: var(--sev-low-bg); color: var(--sev-low-fg); border-color: var(--sev-low-border); }
.badge-informational { background: var(--sev-info-bg); color: var(--sev-info-fg); border-color: var(--sev-info-border); }
.badge-unknown { background: var(--sev-unknown-bg); color: var(--sev-unknown-fg); border-color: var(--sev-unknown-border); }

.na { color: var(--fg-muted); font-style: italic; }

article.finding {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 22px;
    margin: 0 0 24px;
    background: var(--bg);
    box-shadow: var(--shadow);
}

article.finding header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;
    margin-bottom: 14px;
    flex-wrap: wrap;
}

article.finding h3 {
    margin: 0;
    font-size: 17px;
    font-weight: 600;
}

article.finding .finding-id {
    font-size: 12px;
    color: var(--fg-muted);
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
                 "Liberation Mono", monospace;
    margin-top: 2px;
}

article.finding .finding-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin: 0 0 14px;
}

article.finding .finding-tags .tag {
    background: var(--bg-alt);
    border: 1px solid var(--border);
    color: var(--fg-muted);
    padding: 1px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
                 "Liberation Mono", monospace;
}

details {
    margin: 12px 0;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 12px;
    background: var(--bg-alt);
}

details > summary {
    cursor: pointer;
    font-weight: 600;
    color: var(--accent);
    user-select: none;
}

details[open] > summary {
    margin-bottom: 8px;
}

footer.report-footer {
    padding: 20px 40px 40px;
    border-top: 1px solid var(--border);
    color: var(--fg-muted);
    font-size: 12px;
    text-align: center;
}

footer.report-footer p {
    margin: 4px 0;
}

.notice {
    background: var(--sev-low-bg);
    border: 1px solid var(--sev-low-border);
    color: var(--sev-low-fg);
    padding: 12px 16px;
    border-radius: 6px;
    margin: 0 0 16px;
    font-size: 14px;
}

.notice.warn {
    background: var(--sev-medium-bg);
    border-color: var(--sev-medium-border);
    color: var(--sev-medium-fg);
}

.notice.error {
    background: var(--sev-critical-bg);
    border-color: var(--sev-critical-border);
    color: var(--sev-critical-fg);
}

.grid-cards {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 12px;
    margin: 0 0 20px;
}

.card {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 16px;
    background: var(--bg-alt);
}

.card .card-label {
    font-size: 12px;
    color: var(--fg-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 4px;
}

.card .card-value {
    font-size: 22px;
    font-weight: 600;
}

a { color: var(--link); }
a:hover { text-decoration: underline; }

@media (max-width: 720px) {
    header.report-header, main, footer.report-footer, nav.toc {
        padding-left: 16px;
        padding-right: 16px;
    }
    dl.metadata {
        grid-template-columns: 1fr;
    }
    dl.metadata dt {
        margin-top: 8px;
    }
}
"""


# ---------------------------------------------------------------------------
# HtmlReporter
# ---------------------------------------------------------------------------


class HtmlReporter:
    """Renders a :class:`ReportBundle` into a self-contained HTML document.

    Parameters
    ----------
    theme:
        Visual theme. See :class:`ReportTheme`.
    include_toc:
        When True (default), insert a table of contents after the
        header. The TOC lists only sections that the bundle actually
        populates.
    include_summary:
        When True (default), include a top-level summary section with
        derived counts. All counts come from the bundle; none are
        invented.
    include_raw_output:
        When True (default), include each finding's raw crash output
        inside a collapsible ``<details>`` block.
    include_metadata_json:
        When True (default), include a collapsible JSON dump of the
        bundle at the bottom of the report. Useful for audit.
    max_output_chars:
        Truncation limit for raw crash output. Longer output is
        truncated and a marker is appended.
    """

    def __init__(
        self,
        *,
        theme: Union[ReportTheme, str] = ReportTheme.LIGHT,
        include_toc: bool = True,
        include_summary: bool = True,
        include_raw_output: bool = True,
        include_metadata_json: bool = True,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    ) -> None:
        if max_output_chars < 0:
            raise ValueError("max_output_chars must be non-negative")
        if isinstance(theme, str):
            try:
                theme = ReportTheme(theme)
            except ValueError as exc:
                raise ValueError(f"unknown theme: {theme!r}") from exc
        self._theme = theme
        self._include_toc = bool(include_toc)
        self._include_summary = bool(include_summary)
        self._include_raw_output = bool(include_raw_output)
        self._include_metadata_json = bool(include_metadata_json)
        self._max_output_chars = int(max_output_chars)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def render(self, bundle: ReportBundle) -> str:
        """Return the complete HTML document as a string."""
        if not isinstance(bundle, ReportBundle):
            raise TypeError(
                f"bundle must be a ReportBundle, got {type(bundle).__name__}"
            )

        parts: List[str] = []
        parts.append(self._doctype())
        parts.append(self._open_html(bundle))
        parts.append(self._render_head(bundle))
        parts.append("<body>")
        parts.append(self._render_header(bundle))
        if self._include_toc:
            toc = self._render_toc(bundle)
            if toc:
                parts.append(toc)
        parts.append("<main>")
        if self._include_summary:
            parts.append(self._render_summary(bundle))
        if bundle.campaign is not None:
            parts.append(self._render_campaign(bundle.campaign))
        if bundle.corpus is not None:
            parts.append(self._render_corpus(bundle.corpus))
        if bundle.findings:
            parts.append(self._render_findings(bundle.findings))
        if bundle.supplemental_sections:
            parts.append(self._render_supplemental(bundle.supplemental_sections))
        if self._include_metadata_json:
            parts.append(self._render_metadata_json(bundle))
        parts.append("</main>")
        parts.append(self._render_footer(bundle))
        parts.append("</body>")
        parts.append("</html>")
        return "\n".join(parts)

    def write(
        self,
        bundle: ReportBundle,
        path: Union[str, os.PathLike[str]],
    ) -> Path:
        """Render ``bundle`` and write it to ``path``.

        The file is written atomically through a temporary sibling
        file so that a partially-written report never appears on disk.
        Parent directories are created if necessary.

        Returns
        -------
        Path
            The absolute path of the written file.
        """
        target = Path(path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        document = self.render(bundle)
        data = document.encode("utf-8")

        import tempfile

        fd, tmp_name = tempfile.mkstemp(
            prefix=".kmcs-report-", dir=str(target.parent)
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
            os.replace(tmp_path, target)
        except Exception:
            try:
                tmp_path.unlink()
            except OSError:
                pass
            raise
        return target

    # ------------------------------------------------------------------
    # Document skeleton
    # ------------------------------------------------------------------

    def _doctype(self) -> str:
        return "<!DOCTYPE html>"

    def _open_html(self, bundle: ReportBundle) -> str:
        theme = self._theme.value
        lang = "en"
        title = html.escape(bundle.metadata.title, quote=True)
        return (
            f'<html lang="{lang}" data-theme="{_esc_attr(theme)}">'
        )

    def _render_head(self, bundle: ReportBundle) -> str:
        title_text = html.escape(bundle.metadata.title)
        css = _CSS_BASE
        # Inject the resolved theme as a data attribute on <html>.
        # The CSS uses [data-theme="dark"] to switch palettes.
        return (
            "<head>\n"
            '<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f'<meta name="generator" content="{_esc_attr(bundle.metadata.generator)}">\n'
            f"<title>{title_text}</title>\n"
            f"<style>{css}</style>\n"
            "</head>"
        )

    def _render_header(self, bundle: ReportBundle) -> str:
        md = bundle.metadata
        rows: List[str] = []
        rows.append(self._metadata_row("Generated at", _format_datetime(md.generated_at)))
        if md.generator:
            rows.append(self._metadata_row("Generator", _esc(md.generator)))
        if md.campaign_id:
            rows.append(self._metadata_row("Campaign ID", _esc(md.campaign_id)))
        if md.campaign_name:
            rows.append(self._metadata_row("Campaign", _esc(md.campaign_name)))
        if md.fuzzer:
            rows.append(self._metadata_row("Fuzzer", _esc(md.fuzzer)))
        if md.sanitizer:
            rows.append(self._metadata_row("Sanitizer", _esc(md.sanitizer)))
        if md.target_description:
            rows.append(
                self._metadata_row(
                    "Target",
                    f"<code>{_esc(md.target_description)}</code>",
                )
            )
        if md.notes:
            notes_html = "<br>".join(html.escape(note) for note in md.notes)
            rows.append(self._metadata_row("Notes", notes_html))

        metadata_dl = (
            f'<dl class="metadata">{"".join(rows)}</dl>'
            if rows
            else ""
        )

        subtitle_html = ""
        if md.subtitle:
            subtitle_html = (
                f'<p class="subtitle">{html.escape(md.subtitle)}</p>'
            )

        return (
            '<header class="report-header">'
            f"<h1>{html.escape(md.title)}</h1>"
            f"{subtitle_html}"
            f"{metadata_dl}"
            "</header>"
        )

    @staticmethod
    def _metadata_row(label: str, value_html: str) -> str:
        return f"<dt>{html.escape(label)}</dt><dd>{value_html}</dd>"

    # ------------------------------------------------------------------
    # Table of contents
    # ------------------------------------------------------------------

    def _render_toc(self, bundle: ReportBundle) -> str:
        entries: List[Tuple[str, str]] = []
        if self._include_summary:
            entries.append(("summary", "Summary"))
        if bundle.campaign is not None:
            entries.append(("campaign", "Campaign"))
        if bundle.corpus is not None:
            entries.append(("corpus", "Corpus"))
        if bundle.findings:
            entries.append(("findings", "Findings"))
        for title, _ in bundle.supplemental_sections:
            entries.append((_slugify(title), title))

        if len(entries) < 2:
            return ""

        items = "".join(
            f'<li><a href="#{_esc_attr(anchor)}">{html.escape(label)}</a></li>'
            for anchor, label in entries
        )
        return (
            '<nav class="toc" aria-label="Table of contents">'
            "<h2>Contents</h2>"
            f"<ul>{items}</ul>"
            "</nav>"
        )

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _render_summary(self, bundle: ReportBundle) -> str:
        total = len(bundle.findings)
        severity_counts = bundle.count_by_severity()
        reproduced = bundle.reproduced_count()

        cards: List[str] = []
        cards.append(self._card("Total findings", str(total)))
        if total:
            cards.append(
                self._card(
                    "Reproduced",
                    f"{reproduced} / {total}",
                )
            )
        for level in (
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFORMATIONAL,
        ):
            count = severity_counts.get(level.value, 0)
            if count:
                cards.append(
                    self._card(
                        level.display_name,
                        str(count),
                        accent=f"badge-{level.value}",
                    )
                )

        cards_html = (
            f'<div class="grid-cards">{"".join(cards)}</div>' if cards else ""
        )

        # Classification breakdown table, only when there is more than
        # one classification (otherwise it duplicates the card list).
        classification_counts = bundle.count_by_classification()
        classification_html = ""
        if len(classification_counts) > 1:
            rows = "".join(
                f"<tr><td>{html.escape(name)}</td><td>{count}</td></tr>"
                for name, count in sorted(
                    classification_counts.items(),
                    key=lambda kv: (-kv[1], kv[0]),
                )
            )
            classification_html = (
                "<h3>By classification</h3>"
                "<table><thead><tr>"
                "<th>Classification</th><th>Count</th>"
                "</tr></thead><tbody>"
                f"{rows}"
                "</tbody></table>"
            )

        no_findings_html = ""
        if total == 0:
            no_findings_html = (
                '<div class="notice">'
                "This report contains no findings. The bundle was "
                "rendered successfully; there simply were no finding "
                "records to include."
                "</div>"
            )

        return (
            '<section id="summary">'
            "<h2>Summary</h2>"
            f"{no_findings_html}"
            f"{cards_html}"
            f"{classification_html}"
            "</section>"
        )

    @staticmethod
    def _card(label: str, value: str, *, accent: str = "") -> str:
        value_html = html.escape(value)
        if accent:
            return (
                '<div class="card">'
                f'<div class="card-label">{html.escape(label)}</div>'
                f'<div class="card-value"><span class="badge {_esc_attr(accent)}">'
                f"{value_html}"
                "</span></div>"
                "</div>"
            )
        return (
            '<div class="card">'
            f'<div class="card-label">{html.escape(label)}</div>'
            f'<div class="card-value">{value_html}</div>'
            "</div>"
        )

    # ------------------------------------------------------------------
    # Campaign
    # ------------------------------------------------------------------

    def _render_campaign(self, campaign: ReportCampaignSummary) -> str:
        rows: List[str] = []

        def add(label: str, value_html: str) -> None:
            rows.append(
                f'<tr><th scope="row">{html.escape(label)}</th>'
                f"<td>{value_html}</td></tr>"
            )

        if campaign.name is not None:
            add("Name", _esc(campaign.name))
        if campaign.campaign_id is not None:
            add(
                "Campaign ID",
                f"<code>{_esc(campaign.campaign_id)}</code>",
            )
        if campaign.state is not None:
            add("State", f'<code>{_esc(campaign.state)}</code>')
        if campaign.fuzzer is not None:
            add("Fuzzer", _esc(campaign.fuzzer))
        if campaign.sanitizer is not None:
            add("Sanitizer", _esc(campaign.sanitizer))
        if campaign.target_command is not None:
            add(
                "Target",
                f"<code>{_esc(campaign.target_command)}</code>",
            )
        if campaign.workers is not None:
            add("Workers", _esc(campaign.workers))
        if campaign.started_at is not None:
            add("Started", _format_datetime(campaign.started_at))
        if campaign.finished_at is not None:
            add("Finished", _format_datetime(campaign.finished_at))
        if campaign.runtime_seconds is not None:
            add("Runtime", _format_seconds(campaign.runtime_seconds))
        if campaign.total_executions is not None:
            add("Executions", f"{campaign.total_executions:,}")
        if campaign.total_crashes is not None:
            add("Crashes", _esc(campaign.total_crashes))
        if campaign.total_hangs is not None:
            add("Hangs", _esc(campaign.total_hangs))
        if campaign.coverage_percent is not None:
            add("Coverage", _format_percent(campaign.coverage_percent))
        if campaign.corpus_size is not None:
            add("Corpus size", _esc(campaign.corpus_size))
        if campaign.tags:
            add("Tags", _esc(sorted(campaign.tags)))
        if campaign.error_message:
            add(
                "Error",
                f'<span class="badge badge-critical">{html.escape(campaign.error_message)}</span>',
            )

        if not rows:
            return ""

        return (
            '<section id="campaign">'
            "<h2>Campaign</h2>"
            "<table>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
            "</section>"
        )

    # ------------------------------------------------------------------
    # Corpus
    # ------------------------------------------------------------------

    def _render_corpus(self, corpus: ReportCorpusSummary) -> str:
        rows: List[str] = []

        def add(label: str, value_html: str) -> None:
            rows.append(
                f'<tr><th scope="row">{html.escape(label)}</th>'
                f"<td>{value_html}</td></tr>"
            )

        if corpus.root is not None:
            add("Root", f"<code>{_esc(corpus.root)}</code>")
        if corpus.total_entries is not None:
            add("Entries", f"{corpus.total_entries:,}")
        if corpus.unique_digests is not None:
            add("Unique digests", f"{corpus.unique_digests:,}")
        if corpus.total_bytes is not None:
            add(
                "Total size",
                f"{_format_bytes(corpus.total_bytes)} "
                f'<span class="na">({corpus.total_bytes:,} bytes)</span>',
            )
        if corpus.smallest_size is not None:
            add("Smallest input", _format_bytes(corpus.smallest_size))
        if corpus.largest_size is not None:
            add("Largest input", _format_bytes(corpus.largest_size))
        if corpus.mean_size is not None:
            add("Mean size", f"{corpus.mean_size:,.1f} bytes")
        if corpus.median_size is not None:
            add("Median size", f"{corpus.median_size:,.1f} bytes")

        if not rows:
            return ""

        return (
            '<section id="corpus">'
            "<h2>Corpus</h2>"
            "<table>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
            "</section>"
        )

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def _render_findings(self, findings: Sequence[ReportFinding]) -> str:
        # Sort findings by severity (most severe first), then by
        # discovery time (newest first) as a stable tiebreaker.
        order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFORMATIONAL: 4,
            SeverityLevel.UNKNOWN: 5,
        }

        def sort_key(f: ReportFinding) -> Tuple[int, float, str]:
            severity_rank = order.get(f.severity_level, 5)
            ts = (
                -f.discovered_at.timestamp()
                if f.discovered_at is not None
                else 0.0
            )
            return (severity_rank, ts, f.finding_id)

        sorted_findings = sorted(findings, key=sort_key)

        articles = "".join(
            self._render_finding(f) for f in sorted_findings
        )
        return (
            '<section id="findings">'
            f"<h2>Findings ({len(sorted_findings)})</h2>"
            f"{articles}"
            "</section>"
        )

    def _render_finding(self, finding: ReportFinding) -> str:
        anchor = _slugify(f"finding-{finding.finding_id}")

        severity_badge = self._severity_badge(finding)

        tags_html = ""
        if finding.tags:
            tag_spans = "".join(
                f'<span class="tag">{html.escape(t)}</span>'
                for t in sorted(finding.tags)
            )
            tags_html = f'<div class="finding-tags">{tag_spans}</div>'

        details_rows = self._finding_detail_rows(finding)

        # Reproduction & regression section.
        repro_html = self._render_finding_repro(finding)

        # Stack frames.
        frames_html = self._render_stack_frames(finding.stack_frames)

        # Source location.
        location_html = self._render_source_location(finding.source_location)

        # Raw output.
        raw_html = ""
        if self._include_raw_output and finding.raw_output:
            text = finding.raw_output
            text, truncated = _truncate_text(text, self._max_output_chars)
            truncated_notice = (
                f'<div class="notice warn">Output truncated at '
                f"{self._max_output_chars:,} characters.</div>"
                if truncated
                else ""
            )
            raw_html = (
                "<details><summary>Raw crash output</summary>"
                f"{truncated_notice}"
                f"<pre class='scroll'>{html.escape(text)}</pre>"
                "</details>"
            )

        # Notes.
        notes_html = ""
        if finding.notes:
            notes_items = "".join(
                f"<li>{html.escape(n)}</li>" for n in finding.notes
            )
            notes_html = f"<h4>Notes</h4><ul>{notes_items}</ul>"

        # Metadata JSON (per-finding).
        metadata_html = ""
        if finding.metadata:
            metadata_json = json.dumps(
                dict(finding.metadata), indent=2, sort_keys=True, default=str
            )
            metadata_html = (
                "<details><summary>Additional metadata</summary>"
                f"<pre>{html.escape(metadata_json)}</pre>"
                "</details>"
            )

        id_line = f'<div class="finding-id">{html.escape(finding.finding_id)}</div>'

        return (
            f'<article class="finding" id="{_esc_attr(anchor)}">'
            "<header>"
            "<div>"
            f"<h3>{html.escape(finding.title)}</h3>"
            f"{id_line}"
            "</div>"
            f"<div>{severity_badge}</div>"
            "</header>"
            f"{tags_html}"
            f"{details_rows}"
            f"{location_html}"
            f"{frames_html}"
            f"{repro_html}"
            f"{raw_html}"
            f"{notes_html}"
            f"{metadata_html}"
            "</article>"
        )

    @staticmethod
    def _severity_badge(finding: ReportFinding) -> str:
        level = finding.severity_level
        label = finding.display_severity
        return (
            f'<span class="badge badge-{level.value}" '
            f'aria-label="Severity: {html.escape(label, quote=True)}">'
            f"{html.escape(label)}</span>"
        )

    @staticmethod
    def _finding_detail_rows(finding: ReportFinding) -> str:
        rows: List[str] = []

        def add(label: str, value_html: str) -> None:
            rows.append(
                f'<tr><th scope="row">{html.escape(label)}</th>'
                f"<td>{value_html}</td></tr>"
            )

        if finding.crash_kind is not None:
            add("Crash kind", f"<code>{_esc(finding.crash_kind)}</code>")
        if finding.classification_label is not None:
            add("Classification", _esc(finding.classification_label))
        elif finding.classification is not None:
            add("Classification", f"<code>{_esc(finding.classification)}</code>")
        if finding.sanitizer is not None:
            add("Sanitizer", _esc(finding.sanitizer))
        if finding.fingerprint is not None:
            add("Fingerprint", f"<code>{_esc(finding.fingerprint)}</code>")
        if finding.input_digest is not None:
            add("Input digest", f"<code>{_esc(finding.input_digest)}</code>")
        if finding.input_size is not None:
            add(
                "Input size",
                f"{_format_bytes(finding.input_size)} "
                f'<span class="na">({finding.input_size:,} bytes)</span>',
            )
        if finding.input_path is not None:
            add("Input path", f"<code>{_esc(finding.input_path)}</code>")
        if finding.exit_code is not None:
            add("Exit code", f"<code>{_esc(finding.exit_code)}</code>")
        if finding.signal_number is not None or finding.signal_name is not None:
            if finding.signal_name is not None:
                signal_repr = (
                    f"{html.escape(finding.signal_name)} "
                    f'<span class="na">({finding.signal_number})</span>'
                )
            else:
                signal_repr = f"<code>{_esc(finding.signal_number)}</code>"
            add("Signal", signal_repr)
        if finding.timed_out is not None:
            add(
                "Timed out",
                "yes" if finding.timed_out else "no",
            )
        if finding.fault_address is not None:
            add("Fault address", f"<code>{_esc(finding.fault_address)}</code>")
        if finding.access_type is not None:
            add("Access type", f"<code>{_esc(finding.access_type)}</code>")
        if finding.discovered_at is not None:
            add("Discovered", _format_datetime(finding.discovered_at))
        if finding.discovered_by is not None:
            add("Discovered by", _esc(finding.discovered_by))

        if not rows:
            return ""
        return (
            "<table>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
        )

    @staticmethod
    def _render_source_location(
        location: Optional[Mapping[str, Any]]
    ) -> str:
        if not location:
            return ""
        file_ = location.get("file")
        line = location.get("line")
        column = location.get("column")
        function = location.get("function")

        parts: List[str] = []
        if function:
            parts.append(f"<code>{html.escape(str(function))}</code>")
        if file_:
            location_text = html.escape(str(file_))
            if line is not None:
                location_text += f":{line}"
                if column is not None:
                    location_text += f":{column}"
            parts.append(f"<code>{location_text}</code>")
        if not parts:
            return ""
        return (
            "<h4>Source location</h4>"
            f"<p>{' at '.join(parts)}</p>"
        )

    @staticmethod
    def _render_stack_frames(
        frames: Sequence[Mapping[str, Any]]
    ) -> str:
        if not frames:
            return ""
        rows: List[str] = []
        for idx, frame in enumerate(frames):
            if not isinstance(frame, Mapping):
                continue
            function = frame.get("function") or frame.get("func") or ""
            file_ = frame.get("file") or frame.get("filename") or ""
            line = frame.get("line") or frame.get("lineno") or ""
            offset = frame.get("offset") or frame.get("pc") or ""

            location = html.escape(str(file_)) if file_ else ""
            if line:
                location += f":{line}"

            rows.append(
                "<tr>"
                f"<td>{idx}</td>"
                f"<td><code>{html.escape(str(function))}</code></td>"
                f"<td><code>{location}</code></td>"
                f"<td><code>{html.escape(str(offset)) if offset else ''}</code></td>"
                "</tr>"
            )
        if not rows:
            return ""
        return (
            "<h4>Stack trace</h4>"
            "<table>"
            "<thead><tr>"
            "<th>#</th><th>Function</th><th>Location</th><th>Offset</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
        )

    @staticmethod
    def _render_finding_repro(finding: ReportFinding) -> str:
        rows: List[str] = []

        def add(label: str, value_html: str) -> None:
            rows.append(
                f'<tr><th scope="row">{html.escape(label)}</th>'
                f"<td>{value_html}</td></tr>"
            )

        if finding.reproduction_status is not None:
            status_html = HtmlReporter._status_badge(
                finding.reproduction_status
            )
            add("Reproduction", status_html)
        if finding.reproduction_attempts is not None:
            attempts = finding.reproduction_attempts
            matched = finding.reproduction_matched
            if matched is not None:
                add(
                    "Attempts",
                    f"{matched} matched / {attempts} total",
                )
            else:
                add("Attempts", str(attempts))
        if finding.regression_status is not None:
            add(
                "Regression",
                HtmlReporter._status_badge(finding.regression_status),
            )
        if finding.regression_runs is not None:
            add("Regression runs", str(finding.regression_runs))

        if not rows:
            return ""
        return (
            "<h4>Reproduction</h4>"
            "<table>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
        )

    @staticmethod
    def _status_badge(value: Any) -> str:
        text = str(value)
        lowered = text.lower()
        css_class = "badge-unknown"
        if lowered in ("reproduced", "passed"):
            css_class = "badge-low"
        elif lowered in ("not_reproduced", "failed"):
            css_class = "badge-critical"
        elif lowered in ("intermittent", "changed"):
            css_class = "badge-high"
        elif lowered in ("error",):
            css_class = "badge-medium"
        return (
            f'<span class="badge {css_class}">{html.escape(text)}</span>'
        )

    # ------------------------------------------------------------------
    # Supplemental sections and footer
    # ------------------------------------------------------------------

    def _render_supplemental(
        self,
        sections: Sequence[Tuple[str, str]],
    ) -> str:
        if not sections:
            return ""
        parts: List[str] = []
        for title, body in sections:
            anchor = _slugify(title)
            # Body is inserted verbatim: the caller is responsible for
            # escaping its own content.
            parts.append(
                f'<section id="{_esc_attr(anchor)}">'
                f"<h2>{html.escape(title)}</h2>"
                f"{body}"
                "</section>"
            )
        return "".join(parts)

    def _render_metadata_json(self, bundle: ReportBundle) -> str:
        try:
            payload = bundle.to_dict()
            text = json.dumps(payload, indent=2, sort_keys=True, default=str)
        except Exception as exc:  # noqa: BLE001
            return (
                '<section id="report-data">'
                "<h2>Report data</h2>"
                '<div class="notice error">'
                f"Failed to serialise report data: {html.escape(str(exc))}"
                "</div>"
                "</section>"
            )
        text, truncated = _truncate_text(text, 500_000)
        truncated_notice = (
            '<div class="notice warn">'
            "Serialised data truncated to 500,000 characters."
            "</div>"
            if truncated
            else ""
        )
        return (
            '<section id="report-data">'
            "<h2>Report data</h2>"
            "<details><summary>Underlying bundle as JSON</summary>"
            f"{truncated_notice}"
            f"<pre class='scroll'>{html.escape(text)}</pre>"
            "</details>"
            "</section>"
        )

    def _render_footer(self, bundle: ReportBundle) -> str:
        generator = html.escape(bundle.metadata.generator)
        generated_at = bundle.metadata.generated_at
        if isinstance(generated_at, datetime):
            when = html.escape(generated_at.isoformat(timespec="seconds"))
        else:
            when = html.escape(str(generated_at))
        return (
            '<footer class="report-footer">'
            f"<p>Generated by {generator}</p>"
            f"<p>{when}</p>"
            "</footer>"
        )

    # ------------------------------------------------------------------
    # Representation
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"HtmlReporter(theme={self._theme.value!r}, "
            f"include_toc={self._include_toc}, "
            f"include_raw_output={self._include_raw_output})"
        )


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


def render_html(
    bundle: ReportBundle,
    *,
    theme: Union[ReportTheme, str] = ReportTheme.LIGHT,
    include_toc: bool = True,
    include_raw_output: bool = True,
) -> str:
    """Render ``bundle`` to HTML using default reporter options."""
    reporter = HtmlReporter(
        theme=theme,
        include_toc=include_toc,
        include_raw_output=include_raw_output,
    )
    return reporter.render(bundle)


def write_html(
    bundle: ReportBundle,
    path: Union[str, os.PathLike[str]],
    *,
    theme: Union[ReportTheme, str] = ReportTheme.LIGHT,
    include_toc: bool = True,
    include_raw_output: bool = True,
) -> Path:
    """Render ``bundle`` and write it to ``path`` atomically."""
    reporter = HtmlReporter(
        theme=theme,
        include_toc=include_toc,
        include_raw_output=include_raw_output,
    )
    return reporter.write(bundle, path)


# ---------------------------------------------------------------------------
# Findings factories
# ---------------------------------------------------------------------------
#
# These helpers build :class:`ReportFinding` instances from records
# produced by other KMCS subsystems. They are tolerant of missing
# attributes: a field the source does not provide becomes None, never
# a fabricated default.


def finding_from_crash(
    crash: Any,
    *,
    finding_id: Optional[str] = None,
    title: Optional[str] = None,
    severity: Optional[str] = None,
) -> ReportFinding:
    """Build a finding from an analysis crash record.

    The record may be a mapping, a dataclass, or an object with
    attributes. Field lookups are tolerant: any field the record does
    not provide is left as ``None``. This function is a pure projector;
    it does not run the crash parser or classifier.
    """
    if crash is None:
        raise ValueError("crash must not be None")

    def _get(*names: str) -> Any:
        for name in names:
            if isinstance(crash, Mapping) and name in crash:
                return crash[name]
            value = getattr(crash, name, None)
            if value is not None:
                return value
        return None

    digest = _get("input_digest", "digest", "sha256")
    crash_id = _get("crash_id", "id", "uuid")
    resolved_id = finding_id or crash_id or digest or "finding"

    # Title: prefer an explicit override, then the crash's own summary
    # or kind, then fall back to a stable but non-fabricated label.
    resolved_title = title
    if resolved_title is None:
        resolved_title = (
            _get("title", "summary", "headline")
            or _get("crash_kind", "kind", "category")
            or f"Finding {resolved_id}"
        )
        resolved_title = str(resolved_title)

    frames = _get("stack_frames", "frames", "stacktrace") or ()
    if isinstance(frames, (list, tuple)):
        stack_frames = tuple(
            dict(f) if isinstance(f, Mapping) else {"raw": str(f)}
            for f in frames
        )
    else:
        stack_frames = ()

    location = _get("source_location", "location", "sink")
    if isinstance(location, Mapping):
        source_location: Optional[Mapping[str, Any]] = dict(location)
    else:
        source_location = None

    discovered_at = _get("discovered_at", "created_at", "timestamp")
    if isinstance(discovered_at, (int, float)):
        try:
            discovered_at = datetime.fromtimestamp(
                float(discovered_at), tz=timezone.utc
            )
        except (OSError, ValueError, OverflowError):
            discovered_at = None
    elif isinstance(discovered_at, str):
        try:
            discovered_at = datetime.fromisoformat(
                discovered_at.replace("Z", "+00:00")
            )
        except ValueError:
            discovered_at = None
    elif not isinstance(discovered_at, datetime):
        discovered_at = None

    # Raw output: accept whichever field the record carries.
    raw_output = _get("raw_output", "output", "stderr_text", "stdout_text")
    if raw_output is not None and not isinstance(raw_output, str):
        raw_output = str(raw_output)

    return ReportFinding(
        finding_id=str(resolved_id),
        title=resolved_title,
        severity=severity if severity is not None else _get("severity"),
        crash_kind=_get("crash_kind", "kind", "category"),
        classification=_get("classification", "class", "crash_class"),
        classification_label=_get("classification_label", "class_label"),
        fingerprint=_get("fingerprint", "hash", "fingerprint_sha256"),
        sanitizer=_get("sanitizer", "sanitizer_name"),
        input_digest=digest,
        input_size=_get("input_size", "size"),
        input_path=_get("input_path", "path"),
        exit_code=_get("exit_code", "returncode"),
        signal_number=_get("signal_number", "signal", "signum"),
        signal_name=_get("signal_name", "signal_str"),
        timed_out=_get("timed_out", "timeout"),
        raw_output=raw_output,
        stack_frames=stack_frames,
        source_location=source_location,
        fault_address=_get("fault_address", "address", "fault_addr"),
        access_type=_get("access_type", "access"),
        reproduction_status=_get("reproduction_status", "repro_status"),
        reproduction_attempts=_get("reproduction_attempts", "attempts"),
        reproduction_matched=_get("reproduction_matched", "matched"),
        regression_status=_get("regression_status", "reg_status"),
        regression_runs=_get("regression_runs", "reg_runs"),
        discovered_at=discovered_at,
        discovered_by=_get("discovered_by", "author", "source"),
        tags=frozenset(_get("tags") or ()),
        notes=tuple(_get("notes") or ()),
        metadata=dict(_get("metadata") or {}),
    )


def finding_from_reproduction(
    result: "ReproductionResult",
    *,
    finding_id: Optional[str] = None,
    title: Optional[str] = None,
    severity: Optional[str] = None,
    crash: Optional[Any] = None,
) -> ReportFinding:
    """Build a finding from a reproduction result.

    Parameters
    ----------
    result:
        A :class:`~kmcs.reproduction.runner.ReproductionResult`.
    finding_id:
        Explicit finding ID. When None, the result's ``input_digest``
        is used.
    title:
        Explicit title. When None, a title is derived from the
        reference signature's shape (for example "crash" for a
        signal-terminated reference).
    severity:
        Explicit severity. When None, the finding has no severity and
        the report displays "not classified".
    crash:
        Optional analysis crash record to merge in. When provided,
        its fields take precedence over the reproduction result's for
        crash-specific fields.
    """
    if result is None:
        raise ValueError("result must not be None")

    digest = getattr(result, "input_digest", None)
    resolved_id = finding_id or digest or "finding"

    # Extract the first attempt's observable fields.
    attempts = getattr(result, "attempts", None) or ()
    first_attempt = attempts[0] if attempts else None
    outcome = getattr(first_attempt, "outcome", None) if first_attempt else None

    exit_code = getattr(first_attempt, "exit_code", None) if first_attempt else None
    signal_number = (
        getattr(first_attempt, "signal_number", None) if first_attempt else None
    )
    timed_out = (
        bool(getattr(first_attempt, "timed_out", False)) if first_attempt else None
    )

    reference = getattr(result, "reference", None)
    ref_source = getattr(reference, "source", None) if reference else None

    # Derive a title if none is supplied.
    resolved_title = title
    if resolved_title is None:
        if reference is not None:
            if getattr(reference, "signal_number", None) is not None:
                resolved_title = (
                    f"Crash (signal {getattr(reference, 'signal_number')})"
                )
            elif getattr(reference, "timed_out", False):
                resolved_title = "Hang (timeout)"
            elif getattr(reference, "exit_code", None) not in (None, 0):
                resolved_title = (
                    f"Non-zero exit ({getattr(reference, 'exit_code')})"
                )
            else:
                resolved_title = "Reproduced behaviour"
        else:
            resolved_title = f"Finding {resolved_id}"

    status = getattr(result, "status", None)
    status_str = getattr(status, "value", None) or (str(status) if status else None)

    matched_count = getattr(result, "matched_count", None)
    attempt_count = getattr(result, "attempt_count", None)

    input_size = getattr(result, "input_size", None)
    started_at = getattr(result, "started_at", None)
    if not isinstance(started_at, datetime):
        started_at = None

    raw_output = None
    if outcome is not None:
        getter = getattr(outcome, "combined_output", None)
        if callable(getter):
            try:
                value = getter()
            except Exception:  # noqa: BLE001
                value = None
            if isinstance(value, str):
                raw_output = value
        elif isinstance(outcome, Mapping):
            raw_output = outcome.get("combined_output") or outcome.get("output")

    # Merge crash record if provided.
    merged: Dict[str, Any] = {}
    if crash is not None:
        crash_finding = finding_from_crash(crash, finding_id=str(resolved_id))
        merged = crash_finding.to_dict()

    fingerprint = merged.get("fingerprint")
    if fingerprint is None and reference is not None:
        fingerprint = getattr(reference, "fingerprint", None)

    return ReportFinding(
        finding_id=str(resolved_id),
        title=resolved_title,
        severity=severity,
        crash_kind=merged.get("crash_kind"),
        classification=merged.get("classification"),
        classification_label=merged.get("classification_label"),
        fingerprint=fingerprint,
        sanitizer=merged.get("sanitizer"),
        input_digest=digest,
        input_size=input_size,
        input_path=merged.get("input_path"),
        exit_code=exit_code if exit_code is not None else merged.get("exit_code"),
        signal_number=(
            signal_number if signal_number is not None
            else merged.get("signal_number")
        ),
        signal_name=merged.get("signal_name"),
        timed_out=timed_out if timed_out is not None else merged.get("timed_out"),
        raw_output=raw_output if raw_output is not None else merged.get("raw_output"),
        stack_frames=tuple(merged.get("stack_frames") or ()),
        source_location=merged.get("source_location"),
        fault_address=merged.get("fault_address"),
        access_type=merged.get("access_type"),
        reproduction_status=status_str,
        reproduction_attempts=attempt_count,
        reproduction_matched=matched_count,
        regression_status=None,
        regression_runs=None,
        discovered_at=started_at,
        discovered_by=ref_source,
        tags=frozenset(merged.get("tags") or ()),
        notes=tuple(merged.get("notes") or ()),
        metadata=dict(merged.get("metadata") or {}),
    )


def finding_from_regression_case(
    case: "RegressionCase",
    *,
    finding_id: Optional[str] = None,
    title: Optional[str] = None,
    severity: Optional[str] = None,
    regression_run: Optional["RegressionRun"] = None,
) -> ReportFinding:
    """Build a finding from a regression case.

    The case's reference signature and metadata are projected onto the
    finding. When ``regression_run`` is supplied, its status is
    recorded as the finding's regression status.
    """
    if case is None:
        raise ValueError("case must not be None")

    reference = getattr(case, "reference", None)
    resolved_id = finding_id or getattr(case, "case_id", None) or "finding"

    resolved_title = title
    if resolved_title is None:
        if reference is not None and getattr(reference, "signal_number", None) is not None:
            resolved_title = f"Regression: crash (signal {reference.signal_number})"
        elif reference is not None and getattr(reference, "timed_out", False):
            resolved_title = "Regression: hang"
        else:
            resolved_title = f"Regression case {resolved_id}"

    last_status = getattr(case, "last_run_status", None)
    last_status_str = getattr(last_status, "value", None) if last_status else None

    return ReportFinding(
        finding_id=str(resolved_id),
        title=resolved_title,
        severity=severity,
        crash_kind=None,
        classification=None,
        classification_label=None,
        fingerprint=getattr(reference, "fingerprint", None) if reference else None,
        sanitizer=None,
        input_digest=getattr(case, "input_digest", None),
        input_size=getattr(case, "input_size", None),
        input_path=None,
        exit_code=getattr(reference, "exit_code", None) if reference else None,
        signal_number=getattr(reference, "signal_number", None) if reference else None,
        signal_name=None,
        timed_out=(
            bool(getattr(reference, "timed_out", False)) if reference else None
        ),
        raw_output=None,
        stack_frames=(),
        source_location=None,
        fault_address=None,
        access_type=None,
        reproduction_status=None,
        reproduction_attempts=None,
        reproduction_matched=None,
        regression_status=last_status_str,
        regression_runs=getattr(case, "total_runs", None),
        discovered_at=getattr(case, "created_at", None),
        discovered_by=getattr(case, "source", None),
        tags=frozenset(getattr(case, "tags", frozenset()) or frozenset()),
        notes=(),
        metadata=dict(getattr(case, "metadata", {}) or {}),
    )


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

__version__ = "1.0.0"


# Needed for the module's own reference in `write_html`.
import os  # noqa: E402  (import after use in annotations is fine here)
