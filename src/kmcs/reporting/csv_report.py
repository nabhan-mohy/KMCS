# KMCS CSV Report
# ===============
#
# Spreadsheet-friendly rendering of KMCS findings.
#
# This reporter serialises the reporting layer's canonical data model
# into RFC 4180 CSV, with one row per finding. The output is intended
# for direct import into a spreadsheet application (Excel,
# LibreOffice, Google Sheets), or for consumption by data-analysis
# tooling that prefers a flat tabular shape over JSON.
#
# Design notes
# ------------
#
# * **One row per finding.** Each row carries the finding's identity,
#   classification, process outcome, source location, reproduction
#   status, and provenance. Findings are ordered by severity (most
#   severe first), then by discovery time (newest first), then by
#   finding identifier. This gives spreadsheets a natural, reviewable
#   ordering.
#
# * **Columns are data, not code.** Each column is a
#   :class:`CsvColumn` value that pairs a column name with a getter
#   and a value formatter. The reporter does not hard-code column
#   logic; callers can supply their own column set, or filter the
#   default set by name.
#
# * **Missing values are empty strings.** A finding field that is not
#   present produces an empty cell, not a fabricated default. This is
#   the CSV convention for absent data, and it lets spreadsheet
#   functions distinguish "no value" from "value is zero".
#
# * **Escaping is handled by the standard library.** Python's
#   :mod:`csv` module handles commas, quotation marks, embedded
#   newlines, and non-ASCII characters correctly. The reporter
#   configures the writer's dialect and quoting policy, but does not
#   reimplement quoting.
#
# * **Values are normalised to text.** Datetimes become ISO 8601
#   strings, booleans become ``"true"`` / ``"false"``, lists of tags
#   become semicolon-separated strings. The normalisation is
#   deterministic: the same bundle produces the same CSV bytes.
#
# * **The reporter never invents values.** Severity, counts, coverage,
#   and classification are read verbatim from the bundle. If a value
#   is not in the bundle, the cell is empty.
#
# Relationship to other reporters
# -------------------------------
#
# This module imports the shared :class:`ReportBundle` and
# :class:`ReportFinding` types from :mod:`kmcs.reporting.html`. It
# does not redefine them. A caller who builds a bundle once can
# render it as HTML, JSON, Markdown, CSV, or SARIF.
#
# Compatibility
# -------------
#
# Python 3.10+.

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    TextIO,
    Tuple,
    Union,
)


# ---------------------------------------------------------------------------
# Shared model import
# ---------------------------------------------------------------------------
#
# The reporting layer has exactly one data model, defined in
# kmcs.reporting.html. This reporter consumes that model rather than
# defining its own, so that findings rendered as CSV, as JSON, and as
# HTML all describe the same object.

try:
    from .html import (
        ReportBundle,
        ReportFinding,
        ReportMetadata,
        ReportCampaignSummary,
        ReportCorpusSummary,
        SeverityLevel,
        GENERATOR_NAME,
        GENERATOR_VERSION,
    )
except ImportError as _import_exc:  # pragma: no cover - depends on layout
    raise ImportError(
        "kmcs.reporting.csv_report requires kmcs.reporting.html to be "
        f"importable: {_import_exc}"
    ) from _import_exc


logger = logging.getLogger(__name__)


__all__ = [
    "CsvReporter",
    "CsvColumn",
    "CsvOptions",
    "CsvReportError",
    "CsvValidationError",
    "CsvSerializationError",
    "DEFAULT_COLUMNS",
    "DEFAULT_DIALECT",
    "DEFAULT_QUOTING",
    "DEFAULT_DELIMITER",
    "DEFAULT_LINE_TERMINATOR",
    "DEFAULT_ENCODING",
    "render_csv",
    "dump_csv",
    "dump_csv_string",
    "write_csv",
    "columns_by_name",
    "column_names",
    "describe_columns",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Default CSV dialect. ``"excel"`` produces comma-separated output
#: with CRLF line terminators and minimal quoting, which is the
#: format that Excel, LibreOffice, and Google Sheets all accept
#: without configuration.
DEFAULT_DIALECT: str = "excel"

#: Default quoting policy. ``"minimal"`` quotes only when necessary,
#: which produces the most compact and most idiomatic CSV.
DEFAULT_QUOTING: str = "minimal"

#: Default field delimiter.
DEFAULT_DELIMITER: str = ","

#: Default line terminator. CRLF is the RFC 4180 recommendation and
#: is what Excel expects.
DEFAULT_LINE_TERMINATOR: str = "\r\n"

#: Default text encoding when writing files.
DEFAULT_ENCODING: str = "utf-8"

#: Number of spaces used to encode multi-value fields (tags, notes)
#: as a single cell. Semicolons are used rather than commas so that
#: the encoded value does not itself need quoting.
_MULTI_VALUE_SEPARATOR: str = "; "


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CsvReportError(Exception):
    """Base class for all CSV reporter errors."""


class CsvValidationError(CsvReportError):
    """Raised when a bundle fails pre-render validation.

    Validation is limited to conditions that would produce a
    malformed table: duplicate column names, empty column names,
    findings without identifiers, duplicate finding identifiers.
    """


class CsvSerializationError(CsvReportError):
    """Raised when a value in the bundle cannot be rendered.

    In practice this is rare: the reporter is deliberately permissive
    about the shapes of values it accepts, and unknown types are
    stringified via :func:`str`.
    """


# ---------------------------------------------------------------------------
# Value formatters
# ---------------------------------------------------------------------------
#
# A formatter is a callable that takes a Python value (as produced by
# a column's getter) and returns the string that will be placed in
# the CSV cell. Formatters must never raise: on error they return an
# empty string. All formatters are pure functions.

def _format_empty(value: Any) -> str:
    """Return an empty string regardless of ``value``.

    Used by columns whose semantics are "render nothing when absent".
    """
    return ""


def _format_text(value: Any) -> str:
    """Render ``value`` as a plain string.

    Newlines are preserved as-is: the CSV writer will quote the field
    because it contains a newline, and consumers will see the
    original text. This is the correct behaviour for evidence
    fields.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    return str(value)


def _format_integer(value: Any) -> str:
    """Render ``value`` as a bare integer string.

    Non-integer values (including booleans) render as empty strings,
    so that a spreadsheet column typed as a number is not polluted by
    text.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return ""
    try:
        return str(int(value))
    except (TypeError, ValueError):
        return ""


def _format_float(value: Any) -> str:
    """Render ``value`` as a bare floating-point string."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        return repr(float(value))
    try:
        return repr(float(value))
    except (TypeError, ValueError):
        return ""


def _format_boolean(value: Any) -> str:
    """Render ``value`` as ``"true"`` or ``"false"``.

    Values that are not genuinely booleans render as empty strings,
    so that a spreadsheet boolean column is not polluted by text.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "false"):
            return lowered
    return ""


def _format_datetime(value: Any) -> str:
    """Render ``value`` as an ISO-8601 string.

    Naive datetimes are assumed to be UTC. Values that are not
    datetimes render as empty strings.
    """
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        try:
            return value.isoformat(timespec="seconds")
        except Exception:  # noqa: BLE001
            return str(value)
    return ""


def _format_multi_value(value: Any) -> str:
    """Render an iterable of strings as a semicolon-separated cell.

    Empty iterables and ``None`` render as empty strings. Elements are
    sorted if they are hashable and comparable; otherwise the original
    iteration order is preserved.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (frozenset, set)):
        try:
            items = sorted(str(v) for v in value)
        except TypeError:
            items = [str(v) for v in value]
    elif isinstance(value, (list, tuple)):
        items = [str(v) for v in value]
    else:
        return str(value)
    if not items:
        return ""
    return _MULTI_VALUE_SEPARATOR.join(items)


def _format_json(value: Any) -> str:
    """Render ``value`` as compact JSON.

    Used for metadata-shaped columns. Any value that cannot be
    serialised is stringified via :func:`str`.
    """
    if value is None:
        return ""
    try:
        return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


# ---------------------------------------------------------------------------
# Column definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CsvColumn:
    """A single column in the CSV output.

    Attributes
    ----------
    name:
        Header text for the column. Must be non-empty and unique
        within a column set.
    getter:
        Callable that takes a :class:`ReportFinding` and returns the
        raw value for the column. The getter must not raise; if it
        does, the reporter logs the failure and emits an empty cell.
    formatter:
        Callable that takes the raw value and returns the string that
        will be written into the cell. Defaults to
        :func:`_format_text`.
    description:
        Optional human-readable description, surfaced by
        :func:`describe_columns`.
    """

    name: str
    getter: Callable[[ReportFinding], Any]
    formatter: Callable[[Any], str] = field(default=_format_text)
    description: str = ""

    def extract(self, finding: ReportFinding) -> str:
        """Return the cell value for ``finding``.

        Never raises: any exception from the getter or formatter is
        logged at debug level and converted to an empty string.
        """
        try:
            raw = self.getter(finding)
        except Exception as exc:  # noqa: BLE001 - getter is untrusted
            logger.debug(
                "csv column %r getter raised: %s", self.name, exc
            )
            return ""
        try:
            rendered = self.formatter(raw)
        except Exception as exc:  # noqa: BLE001 - formatter is untrusted
            logger.debug(
                "csv column %r formatter raised: %s", self.name, exc
            )
            return ""
        if rendered is None:
            return ""
        if not isinstance(rendered, str):
            return str(rendered)
        return rendered

    def to_description(self) -> Dict[str, str]:
        return {"name": self.name, "description": self.description}


# ---------------------------------------------------------------------------
# Field accessors used by the default column set
# ---------------------------------------------------------------------------

def _loc_get(finding: ReportFinding, *keys: str) -> Any:
    """Return the first present field from a finding's source_location.

    Tolerant of missing or non-mapping locations. Returns ``None``
    when no key is present.
    """
    loc = getattr(finding, "source_location", None)
    if not isinstance(loc, Mapping):
        return None
    for key in keys:
        if key in loc and loc[key] is not None:
            return loc[key]
    return None


def _frame_get(finding: ReportFinding, *keys: str) -> Any:
    """Return the first present field from a finding's top stack frame.

    The top frame is conventionally the frame nearest the crash. If
    no frame is present, or the first frame is not a mapping,
    returns ``None``.
    """
    frames = getattr(finding, "stack_frames", None)
    if not frames:
        return None
    first = frames[0]
    if not isinstance(first, Mapping):
        return None
    for key in keys:
        if key in first and first[key] is not None:
            return first[key]
    return None


def _severity_level_name(value: Any) -> str:
    """Normalise an arbitrary severity value to a canonical name."""
    if value is None:
        return "unknown"
    try:
        parsed = SeverityLevel.parse(value)  # type: ignore[union-attr]
        name = getattr(parsed, "value", None)
        if isinstance(name, str):
            return name
    except Exception:  # noqa: BLE001
        pass
    text = str(value).strip().lower()
    if text in ("critical", "high", "medium", "low", "informational"):
        return text
    if text in ("info", "note", "informational"):
        return "informational"
    if text in ("severe",):
        return "high"
    if text in ("moderate", "med"):
        return "medium"
    return "unknown"


# ---------------------------------------------------------------------------
# Default column set
# ---------------------------------------------------------------------------

def _col_finding_id(f: ReportFinding) -> Any:
    return getattr(f, "finding_id", None)


def _col_title(f: ReportFinding) -> Any:
    return getattr(f, "title", None)


def _col_severity(f: ReportFinding) -> Any:
    return getattr(f, "severity", None)


def _col_severity_level(f: ReportFinding) -> Any:
    return _severity_level_name(getattr(f, "severity", None))


def _col_crash_kind(f: ReportFinding) -> Any:
    return getattr(f, "crash_kind", None)


def _col_classification(f: ReportFinding) -> Any:
    return getattr(f, "classification", None)


def _col_classification_label(f: ReportFinding) -> Any:
    return getattr(f, "classification_label", None)


def _col_sanitizer(f: ReportFinding) -> Any:
    return getattr(f, "sanitizer", None)


def _col_fingerprint(f: ReportFinding) -> Any:
    return getattr(f, "fingerprint", None)


def _col_input_digest(f: ReportFinding) -> Any:
    return getattr(f, "input_digest", None)


def _col_input_size(f: ReportFinding) -> Any:
    return getattr(f, "input_size", None)


def _col_input_path(f: ReportFinding) -> Any:
    return getattr(f, "input_path", None)


def _col_exit_code(f: ReportFinding) -> Any:
    return getattr(f, "exit_code", None)


def _col_signal_number(f: ReportFinding) -> Any:
    return getattr(f, "signal_number", None)


def _col_signal_name(f: ReportFinding) -> Any:
    return getattr(f, "signal_name", None)


def _col_timed_out(f: ReportFinding) -> Any:
    return getattr(f, "timed_out", None)


def _col_fault_address(f: ReportFinding) -> Any:
    return getattr(f, "fault_address", None)


def _col_access_type(f: ReportFinding) -> Any:
    return getattr(f, "access_type", None)


def _col_source_file(f: ReportFinding) -> Any:
    return _loc_get(f, "file", "filename", "path")


def _col_source_line(f: ReportFinding) -> Any:
    return _loc_get(f, "line", "lineno")


def _col_source_column(f: ReportFinding) -> Any:
    return _loc_get(f, "column", "col")


def _col_source_function(f: ReportFinding) -> Any:
    return _loc_get(f, "function", "func", "name")


def _col_reproduction_status(f: ReportFinding) -> Any:
    return getattr(f, "reproduction_status", None)


def _col_reproduction_attempts(f: ReportFinding) -> Any:
    return getattr(f, "reproduction_attempts", None)


def _col_reproduction_matched(f: ReportFinding) -> Any:
    return getattr(f, "reproduction_matched", None)


def _col_regression_status(f: ReportFinding) -> Any:
    return getattr(f, "regression_status", None)


def _col_regression_runs(f: ReportFinding) -> Any:
    return getattr(f, "regression_runs", None)


def _col_discovered_at(f: ReportFinding) -> Any:
    return getattr(f, "discovered_at", None)


def _col_discovered_by(f: ReportFinding) -> Any:
    return getattr(f, "discovered_by", None)


def _col_tags(f: ReportFinding) -> Any:
    return getattr(f, "tags", None)


def _col_notes(f: ReportFinding) -> Any:
    return getattr(f, "notes", None)


def _col_stack_frame_count(f: ReportFinding) -> Any:
    frames = getattr(f, "stack_frames", None)
    if frames is None:
        return None
    try:
        return len(frames)
    except TypeError:
        return None


def _col_top_frame_function(f: ReportFinding) -> Any:
    return _frame_get(f, "function", "func", "name")


def _col_top_frame_file(f: ReportFinding) -> Any:
    return _frame_get(f, "file", "filename", "path")


def _col_top_frame_line(f: ReportFinding) -> Any:
    return _frame_get(f, "line", "lineno")


def _col_metadata(f: ReportFinding) -> Any:
    return getattr(f, "metadata", None)


#: The default column set. Columns are ordered so that a spreadsheet
#: reading left to right sees identity, classification, process
#: outcome, source location, reproduction, and provenance in that
#: order.
DEFAULT_COLUMNS: Tuple[CsvColumn, ...] = (
    CsvColumn(
        name="finding_id",
        getter=_col_finding_id,
        formatter=_format_text,
        description="Unique identifier of the finding within the bundle.",
    ),
    CsvColumn(
        name="title",
        getter=_col_title,
        formatter=_format_text,
        description="Short human-readable title.",
    ),
    CsvColumn(
        name="severity",
        getter=_col_severity,
        formatter=_format_text,
        description="Severity as originally assigned by the analysis subsystem.",
    ),
    CsvColumn(
        name="severity_level",
        getter=_col_severity_level,
        formatter=_format_text,
        description=(
            "Canonical severity level: one of critical, high, medium, "
            "low, informational, unknown."
        ),
    ),
    CsvColumn(
        name="crash_kind",
        getter=_col_crash_kind,
        formatter=_format_text,
        description="Machine-readable crash kind.",
    ),
    CsvColumn(
        name="classification",
        getter=_col_classification,
        formatter=_format_text,
        description="Machine-readable classification identifier.",
    ),
    CsvColumn(
        name="classification_label",
        getter=_col_classification_label,
        formatter=_format_text,
        description="Human-readable classification label.",
    ),
    CsvColumn(
        name="sanitizer",
        getter=_col_sanitizer,
        formatter=_format_text,
        description="Sanitizer identifier, e.g. asan, ubsan.",
    ),
    CsvColumn(
        name="fingerprint",
        getter=_col_fingerprint,
        formatter=_format_text,
        description="Stable fingerprint of the crash.",
    ),
    CsvColumn(
        name="input_digest",
        getter=_col_input_digest,
        formatter=_format_text,
        description="SHA-256 digest of the input that triggered the finding.",
    ),
    CsvColumn(
        name="input_size",
        getter=_col_input_size,
        formatter=_format_integer,
        description="Size of the input in bytes.",
    ),
    CsvColumn(
        name="input_path",
        getter=_col_input_path,
        formatter=_format_text,
        description="Path to the input on disk, if recorded.",
    ),
    CsvColumn(
        name="exit_code",
        getter=_col_exit_code,
        formatter=_format_integer,
        description="Process exit code, if the target exited normally.",
    ),
    CsvColumn(
        name="signal_number",
        getter=_col_signal_number,
        formatter=_format_integer,
        description="Terminating signal number, if the target was killed.",
    ),
    CsvColumn(
        name="signal_name",
        getter=_col_signal_name,
        formatter=_format_text,
        description="Terminating signal name, if known.",
    ),
    CsvColumn(
        name="timed_out",
        getter=_col_timed_out,
        formatter=_format_boolean,
        description="Whether the run timed out.",
    ),
    CsvColumn(
        name="fault_address",
        getter=_col_fault_address,
        formatter=_format_text,
        description="Faulting memory address, when reported.",
    ),
    CsvColumn(
        name="access_type",
        getter=_col_access_type,
        formatter=_format_text,
        description="Access type, e.g. read or write, when reported.",
    ),
    CsvColumn(
        name="source_file",
        getter=_col_source_file,
        formatter=_format_text,
        description="Source file from the finding's source location.",
    ),
    CsvColumn(
        name="source_line",
        getter=_col_source_line,
        formatter=_format_integer,
        description="Source line from the finding's source location.",
    ),
    CsvColumn(
        name="source_column",
        getter=_col_source_column,
        formatter=_format_integer,
        description="Source column from the finding's source location.",
    ),
    CsvColumn(
        name="source_function",
        getter=_col_source_function,
        formatter=_format_text,
        description="Source function from the finding's source location.",
    ),
    CsvColumn(
        name="reproduction_status",
        getter=_col_reproduction_status,
        formatter=_format_text,
        description="Reproduction status as reported by the runner.",
    ),
    CsvColumn(
        name="reproduction_attempts",
        getter=_col_reproduction_attempts,
        formatter=_format_integer,
        description="Number of reproduction attempts made.",
    ),
    CsvColumn(
        name="reproduction_matched",
        getter=_col_reproduction_matched,
        formatter=_format_integer,
        description="Number of reproduction attempts that matched.",
    ),
    CsvColumn(
        name="regression_status",
        getter=_col_regression_status,
        formatter=_format_text,
        description="Regression status, when the finding is in the regression suite.",
    ),
    CsvColumn(
        name="regression_runs",
        getter=_col_regression_runs,
        formatter=_format_integer,
        description="Number of regression runs recorded.",
    ),
    CsvColumn(
        name="discovered_at",
        getter=_col_discovered_at,
        formatter=_format_datetime,
        description="When the finding was discovered.",
    ),
    CsvColumn(
        name="discovered_by",
        getter=_col_discovered_by,
        formatter=_format_text,
        description="Source that produced the finding.",
    ),
    CsvColumn(
        name="tags",
        getter=_col_tags,
        formatter=_format_multi_value,
        description="Semicolon-separated tags.",
    ),
    CsvColumn(
        name="notes",
        getter=_col_notes,
        formatter=_format_multi_value,
        description="Semicolon-separated notes.",
    ),
    CsvColumn(
        name="stack_frame_count",
        getter=_col_stack_frame_count,
        formatter=_format_integer,
        description="Number of stack frames in the finding's stack trace.",
    ),
    CsvColumn(
        name="top_frame_function",
        getter=_col_top_frame_function,
        formatter=_format_text,
        description="Function name of the top stack frame.",
    ),
    CsvColumn(
        name="top_frame_file",
        getter=_col_top_frame_file,
        formatter=_format_text,
        description="File name of the top stack frame.",
    ),
    CsvColumn(
        name="top_frame_line",
        getter=_col_top_frame_line,
        formatter=_format_integer,
        description="Line number of the top stack frame.",
    ),
)


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CsvOptions:
    """Immutable options for :class:`CsvReporter`.

    Attributes
    ----------
    dialect:
        Named CSV dialect understood by :mod:`csv`. Defaults to
        ``"excel"``. Recognised names are ``"excel"``,
        ``"excel-tab"``, and ``"unix"``.
    delimiter:
        Field delimiter. Overrides the dialect's default.
    quoting:
        Quoting policy: ``"minimal"``, ``"all"``, ``"nonnumeric"``,
        or ``"none"``. Defaults to ``"minimal"``.
    line_terminator:
        String written at the end of each row. Defaults to CRLF,
        matching RFC 4180 and Excel's expectations.
    write_header:
        When True (default), the first row contains column names.
    encoding:
        Text encoding used when writing to a file. Defaults to
        UTF-8. Callers who need Excel's BOM-based detection can set
        this to ``"utf-8-sig"``.
    trailing_newline:
        When True (default), a trailing line terminator is emitted
        after the last row. This matches the behaviour of most CSV
        writers and is what spreadsheets expect.
    include_raw_output:
        Reserved for future use. Currently the reporter does not
        include raw crash output in CSV columns by default, so this
        option has no effect unless the caller adds a custom column.
    """

    dialect: str = DEFAULT_DIALECT
    delimiter: str = DEFAULT_DELIMITER
    quoting: str = DEFAULT_QUOTING
    line_terminator: str = DEFAULT_LINE_TERMINATOR
    write_header: bool = True
    encoding: str = DEFAULT_ENCODING
    trailing_newline: bool = True
    include_raw_output: bool = False

    def __post_init__(self) -> None:
        if not self.delimiter:
            raise ValueError("delimiter must not be empty")
        if len(self.delimiter) != 1:
            raise ValueError("delimiter must be a single character")
        if not self.line_terminator:
            raise ValueError("line_terminator must not be empty")
        if self.quoting not in ("minimal", "all", "nonnumeric", "none"):
            raise ValueError(
                f"unknown quoting policy: {self.quoting!r}; expected one "
                "of 'minimal', 'all', 'nonnumeric', 'none'"
            )
        if not self.encoding:
            raise ValueError("encoding must not be empty")


# ---------------------------------------------------------------------------
# CsvReporter
# ---------------------------------------------------------------------------


class CsvReporter:
    """Renders a :class:`ReportBundle` as a CSV document.

    Parameters
    ----------
    options:
        Optional :class:`CsvOptions`. Defaults are used when omitted.
    columns:
        Optional sequence of :class:`CsvColumn`. When omitted, the
        module-level :data:`DEFAULT_COLUMNS` is used. Callers who
        want a subset of the default columns can build it with
        :func:`columns_by_name`.

    Notes
    -----
    A reporter instance is stateless with respect to the bundle.
    Rendering the same bundle twice with the same options produces
    byte-identical output. Options and columns are immutable, so a
    reporter may be shared safely across threads.
    """

    def __init__(
        self,
        options: Optional[CsvOptions] = None,
        columns: Optional[Sequence[CsvColumn]] = None,
    ) -> None:
        self._options = options or CsvOptions()
        self._columns: Tuple[CsvColumn, ...] = tuple(
            columns if columns is not None else DEFAULT_COLUMNS
        )
        self._validate_columns(self._columns)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def options(self) -> CsvOptions:
        return self._options

    @property
    def columns(self) -> Tuple[CsvColumn, ...]:
        return self._columns

    def column_names(self) -> List[str]:
        """Return the ordered column names."""
        return [c.name for c in self._columns]

    def render_string(self, bundle: ReportBundle) -> str:
        """Render ``bundle`` as a CSV string.

        Raises
        ------
        CsvValidationError
            If the bundle fails pre-render validation.
        CsvSerializationError
            If a row cannot be serialised.
        """
        if bundle is None:
            raise CsvValidationError("bundle must not be None")
        self._validate_bundle(bundle)

        findings = self._ordered_findings(bundle)
        rows = self._build_rows(findings)

        buf = io.StringIO(newline="")
        writer = self._make_writer(buf)
        if self._options.write_header:
            writer.writerow(self.column_names())
        for row in rows:
            writer.writerow(row)

        text = buf.getvalue()
        if not self._options.trailing_newline:
            # Strip a single trailing terminator.
            term = self._options.line_terminator
            if text.endswith(term):
                text = text[: -len(term)]
        return text

    def write(
        self,
        bundle: ReportBundle,
        path: Union[str, os.PathLike[str]],
    ) -> Path:
        """Render ``bundle`` and write it to ``path`` atomically.

        The file is written through a temporary sibling file, so that
        a partially-written report never appears on disk. Parent
        directories are created if necessary.

        Returns the absolute path of the written file.
        """
        target = Path(path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        text = self.render_string(bundle)
        data = text.encode(self._options.encoding, errors="replace")

        fd, tmp_name = tempfile.mkstemp(
            prefix=".kmcs-csv-", dir=str(target.parent)
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

    def write_stream(self, bundle: ReportBundle, stream: TextIO) -> None:
        """Write the CSV to an open text stream.

        The stream is not closed by this method. Callers are
        responsible for opening the stream with ``newline=""`` if
        they want the line terminator to be written verbatim.
        """
        text = self.render_string(bundle)
        stream.write(text)

    # ------------------------------------------------------------------
    # Internal: validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_columns(columns: Sequence[CsvColumn]) -> None:
        if not columns:
            raise CsvValidationError("column set must not be empty")
        seen: Dict[str, int] = {}
        for idx, col in enumerate(columns):
            if not isinstance(col, CsvColumn):
                raise CsvValidationError(
                    f"column at index {idx} is not a CsvColumn"
                )
            if not col.name:
                raise CsvValidationError(
                    f"column at index {idx} has an empty name"
                )
            if col.name in seen:
                raise CsvValidationError(
                    f"duplicate column name {col.name!r} "
                    f"(indices {seen[col.name]} and {idx})"
                )
            seen[col.name] = idx

    def _validate_bundle(self, bundle: ReportBundle) -> None:
        metadata = getattr(bundle, "metadata", None)
        if metadata is None:
            raise CsvValidationError("bundle has no metadata")
        title = getattr(metadata, "title", None)
        if not isinstance(title, str) or not title.strip():
            raise CsvValidationError("bundle metadata has no title")

        seen: Dict[str, int] = {}
        findings = getattr(bundle, "findings", None) or ()
        for idx, finding in enumerate(findings):
            fid = getattr(finding, "finding_id", None)
            if not isinstance(fid, str) or not fid:
                raise CsvValidationError(
                    f"finding at index {idx} has no identifier"
                )
            if fid in seen:
                raise CsvValidationError(
                    f"duplicate finding identifier {fid!r} "
                    f"(indices {seen[fid]} and {idx})"
                )
            seen[fid] = idx

    # ------------------------------------------------------------------
    # Internal: ordering
    # ------------------------------------------------------------------

    _SEVERITY_ORDER: Mapping[str, int] = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "informational": 4,
        "unknown": 5,
    }

    @classmethod
    def _ordered_findings(
        cls, bundle: ReportBundle
    ) -> List[ReportFinding]:
        findings = list(getattr(bundle, "findings", None) or ())

        def key(f: ReportFinding) -> Tuple[int, float, str]:
            level = _severity_level_name(getattr(f, "severity", None))
            rank = cls._SEVERITY_ORDER.get(level, 99)
            discovered = getattr(f, "discovered_at", None)
            if isinstance(discovered, datetime):
                ts = -discovered.timestamp()
            else:
                ts = 0.0
            fid = str(getattr(f, "finding_id", ""))
            return (rank, ts, fid)

        return sorted(findings, key=key)

    # ------------------------------------------------------------------
    # Internal: row construction
    # ------------------------------------------------------------------

    def _build_rows(
        self, findings: Sequence[ReportFinding]
    ) -> List[List[str]]:
        rows: List[List[str]] = []
        for finding in findings:
            row: List[str] = []
            for column in self._columns:
                row.append(column.extract(finding))
            rows.append(row)
        return rows

    # ------------------------------------------------------------------
    # Internal: writer construction
    # ------------------------------------------------------------------

    def _make_writer(self, buf: io.StringIO) -> "csv._writer":
        quoting_map = {
            "minimal": csv.QUOTE_MINIMAL,
            "all": csv.QUOTE_ALL,
            "nonnumeric": csv.QUOTE_NONNUMERIC,
            "none": csv.QUOTE_NONE,
        }
        quoting = quoting_map[self._options.quoting]

        try:
            dialect = csv.get_dialect(self._options.dialect)
            # Create a modified dialect via a subclass so we can
            # override delimiter, quoting, and line terminator
            # without mutating the global dialect registry.
            class _CustomDialect(csv.Dialect):  # type: ignore[misc]
                delimiter = self._options.delimiter
                quotechar = dialect.quotechar
                doublequote = dialect.doublequote
                skipinitialspace = dialect.skipinitialspace
                lineterminator = self._options.line_terminator
                quoting = quoting
                escapechar = dialect.escapechar

            writer = csv.writer(buf, dialect=_CustomDialect)
        except csv.Error:
            # Fall back to a minimal writer if the dialect name is
            # unknown. This is a defensive branch: the default
            # dialect is always present, and callers who set a
            # custom dialect name should validate it themselves.
            writer = csv.writer(
                buf,
                delimiter=self._options.delimiter,
                quoting=quoting,
                lineterminator=self._options.line_terminator,
            )
        return writer

    # ------------------------------------------------------------------
    # Representation
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"CsvReporter(columns={len(self._columns)}, "
            f"dialect={self._options.dialect!r}, "
            f"quoting={self._options.quoting!r})"
        )


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


def render_csv(
    bundle: ReportBundle,
    *,
    options: Optional[CsvOptions] = None,
    columns: Optional[Sequence[CsvColumn]] = None,
) -> str:
    """Render ``bundle`` as a CSV string.

    One-shot wrapper around :class:`CsvReporter`.
    """
    reporter = CsvReporter(options, columns)
    return reporter.render_string(bundle)


def dump_csv_string(
    bundle: ReportBundle,
    *,
    options: Optional[CsvOptions] = None,
    columns: Optional[Sequence[CsvColumn]] = None,
) -> str:
    """Alias for :func:`render_csv`, provided for naming symmetry."""
    return render_csv(bundle, options=options, columns=columns)


def dump_csv(
    bundle: ReportBundle,
    path: Union[str, os.PathLike[str]],
    *,
    options: Optional[CsvOptions] = None,
    columns: Optional[Sequence[CsvColumn]] = None,
) -> Path:
    """Render ``bundle`` and write it to ``path`` atomically."""
    reporter = CsvReporter(options, columns)
    return reporter.write(bundle, path)


def write_csv(
    bundle: ReportBundle,
    path: Union[str, os.PathLike[str]],
    *,
    options: Optional[CsvOptions] = None,
    columns: Optional[Sequence[CsvColumn]] = None,
) -> Path:
    """Alias for :func:`dump_csv`."""
    return dump_csv(bundle, path, options=options, columns=columns)


# ---------------------------------------------------------------------------
# Column utilities
# ---------------------------------------------------------------------------


def columns_by_name(
    names: Iterable[str],
    *,
    columns: Optional[Sequence[CsvColumn]] = None,
) -> Tuple[CsvColumn, ...]:
    """Return the subset of ``columns`` whose names appear in ``names``.

    Order follows the order of ``columns``, not the order of
    ``names``, so that the resulting CSV has a stable layout.

    Raises
    ------
    CsvValidationError
        If any requested name is not present in the source set.
    """
    source = tuple(columns if columns is not None else DEFAULT_COLUMNS)
    available = {col.name: col for col in source}
    requested: List[str] = []
    seen: set[str] = set()
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        if name not in available:
            raise CsvValidationError(
                f"unknown column: {name!r}; available: "
                f"{sorted(available.keys())}"
            )
        requested.append(name)
    # Preserve source ordering.
    requested_set = set(requested)
    return tuple(col for col in source if col.name in requested_set)


def column_names(
    *,
    columns: Optional[Sequence[CsvColumn]] = None,
) -> List[str]:
    """Return the ordered names of the given column set."""
    source = columns if columns is not None else DEFAULT_COLUMNS
    return [col.name for col in source]


def describe_columns(
    *,
    columns: Optional[Sequence[CsvColumn]] = None,
) -> List[Dict[str, str]]:
    """Return a list of ``{name, description}`` dicts for a column set.

    The output is intended for tooling that builds a schema preview
    or generates column-selection UIs.
    """
    source = columns if columns is not None else DEFAULT_COLUMNS
    return [col.to_description() for col in source]


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

__version__ = "1.0.0"
