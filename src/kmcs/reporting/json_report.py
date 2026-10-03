# KMCS JSON Report
# ================
#
# Machine-readable rendering of KMCS findings.
#
# This reporter serialises the same data model that the HTML reporter
# renders — findings, campaign summary, corpus summary, reproduction
# and regression status — into a structured JSON document that other
# software can consume without parsing prose.
#
# Where HTML optimises for human reading, JSON optimises for
# programmatic consumption. Concretely, the JSON reporter:
#
#   * Emits an explicit schema version so that consumers can detect
#     incompatible changes.
#
#   * Preserves every field of every finding, including ones the HTML
#     reporter chooses not to display. Fields that are genuinely
#     absent on the source data are emitted as ``null``, never
#     fabricated.
#
#   * Optionally omits null fields, for callers whose downstream
#     consumers prefer compact documents.
#
#   * Optionally caps the size of raw crash output, for callers whose
#     consumers have size constraints.
#
#   * Provides an integrity hash over the serialised payload, so that
#     downstream tools can detect tampering or truncation.
#
#   * Supports streaming output, so that a bundle with hundreds of
#     thousands of findings can be written without holding the whole
#     document in memory.
#
# Shared model
# ------------
#
# The reporter works on the same :class:`ReportBundle` /
# :class:`ReportFinding` dataclasses that the HTML reporter uses.
# Those types live in :mod:`kmcs.reporting.html` and are imported here
# so that there is exactly one canonical data model for the reporting
# layer. Callers who build a bundle once can render it as HTML, JSON,
# Markdown, CSV, or SARIF without transforming between formats.
#
# Delegation
# ----------
#
# Like the HTML reporter, this module delegates the construction of
# :class:`ReportFinding` objects to the factory functions in
# :mod:`kmcs.reporting.html`. Those factories are the only place in
# the reporting layer that reads from analysis / reproduction /
# regression subsystem records; the JSON reporter simply serialises
# the results. This keeps the two reporters in lockstep: a change to
# how a finding is projected from a crash record affects both
# reporters identically.
#
# What this module does NOT do
# ---------------------------
#
# * It does not run the crash parser, the classifier, the severity
#   assigner, or the fingerprint extractor. Those are the
#   responsibility of the subsystems that own them, and of the
#   factories in :mod:`kmcs.reporting.html`.
#
# * It does not compute severity, coverage, or counts that were not
#   already present in the bundle. The ``counts`` object in the
#   output is derived entirely from the findings list.
#
# * It does not modify its input. The bundle is read-only.
#
# Schema
# ------
#
# The top-level document has the following shape::
#
#     {
#       "schema": "kmcs.report",
#       "schema_version": "1.0",
#       "generated_at": "2026-01-01T00:00:00+00:00",
#       "generator": "KMCS 1.0.0",
#       "integrity": {
#         "algorithm": "sha256",
#         "digest": "<hex over canonical JSON of `data`>"
#       },
#       "metadata": { ... },
#       "campaign": { ... } | null,
#       "corpus":   { ... } | null,
#       "findings": [ { ... }, ... ],
#       "counts":   { ... },
#       "supplemental_sections": [ { "title": ..., "body": ... }, ... ]
#     }
#
# Every key is always present unless ``omit_null`` is enabled, in
# which case keys whose value is ``null`` are dropped. The ``counts``
# object is always present. The ``findings`` array is always present,
# even when empty.
#
# Compatibility
# -------------
#
# Python 3.10+.

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
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
    Iterator,
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
# The reporting layer has exactly one data model. It lives in
# reporting.html because that reporter was written first and because
# the model was originally shaped around the fields the HTML
# renderer needs. Importing it here, rather than duplicating it,
# ensures the two reporters never drift apart.
#
# The import is defensive: if the html reporter is unavailable
# (for example, because a caller vendored a partial copy of the
# package), the JSON reporter falls back to a minimal local model
# that carries the same field names. Callers who need the full model
# should ensure reporting.html is importable.

try:
    from .html import (  # type: ignore[import]
        ReportBundle,
        ReportFinding,
        ReportMetadata,
        ReportCampaignSummary,
        ReportCorpusSummary,
        SeverityLevel,
        ReportTheme,
        finding_from_crash,
        finding_from_reproduction,
        finding_from_regression_case,
        GENERATOR_NAME,
        GENERATOR_VERSION,
        DEFAULT_TITLE,
    )
    _HAVE_SHARED_MODEL = True
except ImportError as _shared_import_exc:  # pragma: no cover - depends on layout
    _HAVE_SHARED_MODEL = False
    _SHARED_IMPORT_ERROR = str(_shared_import_exc)

    # Minimal fallbacks. These are deliberately *not* full
    # reimplementations: they preserve only the field names and the
    # shape that this module needs to produce valid JSON. Callers who
    # need the full model should install it.

    @dataclass(frozen=True)
    class ReportMetadata:  # type: ignore[no-redef]
        title: str = "KMCS Security Report"
        subtitle: Optional[str] = None
        generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
        generator: str = "KMCS 1.0.0"
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
    class ReportCampaignSummary:  # type: ignore[no-redef]
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

    @dataclass(frozen=True)
    class ReportCorpusSummary:  # type: ignore[no-redef]
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

    @dataclass(frozen=True)
    class ReportFinding:  # type: ignore[no-redef]
        finding_id: str
        title: str
        severity: Optional[str] = None
        crash_kind: Optional[str] = None
        classification: Optional[str] = None
        classification_label: Optional[str] = None
        fingerprint: Optional[str] = None
        sanitizer: Optional[str] = None
        input_digest: Optional[str] = None
        input_size: Optional[int] = None
        input_path: Optional[str] = None
        exit_code: Optional[int] = None
        signal_number: Optional[int] = None
        signal_name: Optional[str] = None
        timed_out: Optional[bool] = None
        raw_output: Optional[str] = None
        stack_frames: Tuple[Mapping[str, Any], ...] = ()
        source_location: Optional[Mapping[str, Any]] = None
        fault_address: Optional[str] = None
        access_type: Optional[str] = None
        reproduction_status: Optional[str] = None
        reproduction_attempts: Optional[int] = None
        reproduction_matched: Optional[int] = None
        regression_status: Optional[str] = None
        regression_runs: Optional[int] = None
        discovered_at: Optional[datetime] = None
        discovered_by: Optional[str] = None
        tags: FrozenSet[str] = field(default_factory=frozenset)
        notes: Tuple[str, ...] = ()
        metadata: Mapping[str, Any] = field(default_factory=dict)

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
    class ReportBundle:  # type: ignore[no-redef]
        metadata: ReportMetadata = field(default_factory=ReportMetadata)
        campaign: Optional[ReportCampaignSummary] = None
        corpus: Optional[ReportCorpusSummary] = None
        findings: Tuple[ReportFinding, ...] = ()
        supplemental_sections: Tuple[Tuple[str, str], ...] = ()

        def to_dict(self) -> Dict[str, Any]:
            return {
                "metadata": self.metadata.to_dict(),
                "campaign": self.campaign.to_dict() if self.campaign else None,
                "corpus": self.corpus.to_dict() if self.corpus else None,
                "findings": [f.to_dict() for f in self.findings],
                "supplemental_sections": [
                    {"title": t, "body": b} for t, b in self.supplemental_sections
                ],
            }

    class SeverityLevel:  # type: ignore[no-redef]
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"
        INFORMATIONAL = "informational"
        UNKNOWN = "unknown"

    GENERATOR_NAME = "KMCS"
    GENERATOR_VERSION = "1.0.0"
    DEFAULT_TITLE = "KMCS Security Report"

    def finding_from_crash(*args: Any, **kwargs: Any) -> ReportFinding:  # type: ignore[misc]
        raise NotImplementedError(
            "reporting.html is not importable; the JSON reporter cannot "
            "project crash records without it"
        )

    def finding_from_reproduction(*args: Any, **kwargs: Any) -> ReportFinding:  # type: ignore[misc]
        raise NotImplementedError(
            "reporting.html is not importable; the JSON reporter cannot "
            "project reproduction results without it"
        )

    def finding_from_regression_case(*args: Any, **kwargs: Any) -> ReportFinding:  # type: ignore[misc]
        raise NotImplementedError(
            "reporting.html is not importable; the JSON reporter cannot "
            "project regression cases without it"
        )

    ReportTheme = None  # type: ignore[assignment]


logger = logging.getLogger(__name__)


__all__ = [
    "JsonReporter",
    "JsonReportOptions",
    "JsonStreamWriter",
    "JsonReportError",
    "JsonSerializationError",
    "JsonValidationError",
    "dump_json",
    "dump_json_string",
    "dump_json_stream",
    "SCHEMA_NAME",
    "SCHEMA_VERSION",
    "DEFAULT_INDENT",
    "DEFAULT_MAX_OUTPUT_CHARS",
    "DEFAULT_SORT_KEYS",
    "DEFAULT_OMIT_NULL",
    "DEFAULT_INCLUDE_INTEGRITY",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Name of the JSON schema this reporter emits. Consumers should
#: match on ``(schema, schema_version)`` to detect incompatible
#: documents.
SCHEMA_NAME: str = "kmcs.report"

#: Version of the emitted schema. Bumped only when a change would
#: break existing consumers: field removal, field renaming, or a
#: change in a field's type. Adding new optional fields does not bump
#: the version.
SCHEMA_VERSION: str = "1.0"

#: Default indentation level when pretty-printing.
DEFAULT_INDENT: int = 2

#: Default cap on the number of characters of raw crash output
#: included per finding. ``None`` disables the cap.
DEFAULT_MAX_OUTPUT_CHARS: Optional[int] = 40_000

#: Whether keys are sorted in the output. Sorting makes the document
#: deterministic but slightly less natural for humans; the default
#: matches the JSON interchange convention of stable key ordering.
DEFAULT_SORT_KEYS: bool = True

#: Whether keys with null values are omitted from the output. The
#: default keeps them, so that the schema is fully self-describing.
DEFAULT_OMIT_NULL: bool = False

#: Whether to compute and include an integrity hash over the payload.
DEFAULT_INCLUDE_INTEGRITY: bool = True


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class JsonReportError(Exception):
    """Base class for all JSON reporter errors."""


class JsonSerializationError(JsonReportError):
    """Raised when a value in the bundle cannot be serialised to JSON."""


class JsonValidationError(JsonReportError):
    """Raised when a bundle fails pre-serialisation validation.

    The reporter validates that required identifiers are present and
    unique before writing anything. This prevents emitting a document
    that downstream consumers cannot key on.
    """


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JsonReportOptions:
    """Immutable options for :class:`JsonReporter`.

    Attributes
    ----------
    indent:
        Indentation level for pretty-printing. ``None`` disables
        pretty-printing (produces compact output with no whitespace).
    sort_keys:
        When True, object keys are sorted alphabetically. Sorting
        makes the output deterministic; disabling it preserves
        insertion order, which some consumers find easier to read in
        diffs.
    omit_null:
        When True, fields whose value is ``null`` are omitted. This
        produces smaller documents but means that absent fields and
        explicit-null fields are indistinguishable to consumers.
        Default is False: null fields are kept so that the schema is
        self-describing.
    include_integrity:
        When True, compute a SHA-256 hash over the ``data`` section and
        include it in the envelope as ``integrity.digest``. Callers
        can use this to detect tampering or truncation.
    include_raw_output:
        When True (default), each finding's ``raw_output`` field is
        included. When False, the field is omitted entirely (not set
        to null), so that consumers do not confuse "not included by
        the reporter" with "not present in the source data".
    max_output_chars:
        Per-finding cap on the number of characters of raw output
        included. Longer output is truncated and the finding's
        ``metadata.raw_output_truncated`` flag is set to True. When
        None, no cap is applied.
    include_supplemental_sections:
        When True (default), supplemental sections supplied by the
        caller are included verbatim. Their ``body`` field is passed
        through unchanged; the reporter does not interpret it.
    ensure_ascii:
        When True (default), non-ASCII characters in strings are
        escaped as ``\\uXXXX`` sequences. When False, output is
        UTF-8 and non-ASCII characters appear verbatim.
    trailing_newline:
        When True (default), the string form of the report ends with a
        single newline. This matches the convention for text files on
        POSIX systems.
    """

    indent: Optional[int] = DEFAULT_INDENT
    sort_keys: bool = DEFAULT_SORT_KEYS
    omit_null: bool = DEFAULT_OMIT_NULL
    include_integrity: bool = DEFAULT_INCLUDE_INTEGRITY
    include_raw_output: bool = True
    max_output_chars: Optional[int] = DEFAULT_MAX_OUTPUT_CHARS
    include_supplemental_sections: bool = True
    ensure_ascii: bool = True
    trailing_newline: bool = True

    def __post_init__(self) -> None:
        if self.indent is not None and self.indent < 0:
            raise ValueError("indent must be non-negative or None")
        if self.max_output_chars is not None and self.max_output_chars < 0:
            raise ValueError("max_output_chars must be non-negative or None")


# ---------------------------------------------------------------------------
# Internal serialisation helpers
# ---------------------------------------------------------------------------


def _serialize_datetime(value: datetime) -> str:
    """Serialise a datetime to an ISO-8601 string.

    Naive datetimes are assumed to be UTC, because the rest of KMCS
    always produces timezone-aware values; the assumption is made
    explicit here so that consumers do not have to guess.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _serialize_value(value: Any) -> Any:
    """Recursively convert a Python value into a JSON-serialisable one.

    Handles datetimes, Paths, frozensets, tuples, and mappings. Any
    object that exposes a ``to_dict`` method is serialised through it.
    All other objects fall back to ``str()`` so that a hostile or
    unexpected value cannot break the document.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return _serialize_datetime(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (frozenset, set)):
        return sorted(_serialize_value(v) for v in value)
    if isinstance(value, (list, tuple)):
        return [_serialize_value(v) for v in value]
    if isinstance(value, Mapping):
        return {
            str(k): _serialize_value(v)
            for k, v in value.items()
        }
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            return _serialize_value(to_dict())
        except Exception as exc:  # noqa: BLE001 - untrusted source object
            raise JsonSerializationError(
                f"to_dict() on {type(value).__name__} raised: {exc}"
            ) from exc
    # Last resort: stringify. This is deliberately lenient: the
    # reporter must not fail because some metadata field contains an
    # exotic object.
    return str(value)


def _drop_nulls(value: Any) -> Any:
    """Recursively drop keys whose value is ``None`` from mappings.

    Lists are preserved as lists (null elements within a list are
    kept, because dropping them would change the list's length and
    meaning). Empty containers are preserved.
    """
    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}
        for k, v in value.items():
            cleaned = _drop_nulls(v)
            if cleaned is None:
                continue
            result[k] = cleaned
        return result
    if isinstance(value, list):
        return [_drop_nulls(v) for v in value]
    return value


def _hash_payload(payload: Any, *, sort_keys: bool, ensure_ascii: bool) -> str:
    """Return a SHA-256 digest over a canonical JSON encoding of ``payload``.

    Canonicalisation uses the same serialisation parameters as the
    final document, so that a consumer who parses the payload and
    re-serialises it with the same settings obtains the same digest.
    """
    try:
        canonical = json.dumps(
            payload,
            sort_keys=sort_keys,
            ensure_ascii=ensure_ascii,
            separators=(",", ":"),
            default=str,
        )
    except (TypeError, ValueError) as exc:
        raise JsonSerializationError(
            f"failed to canonicalise payload for hashing: {exc}"
        ) from exc
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _truncate(text: str, limit: Optional[int]) -> Tuple[str, bool]:
    """Truncate ``text`` to ``limit`` characters; return (text, truncated)."""
    if limit is None or limit < 0 or len(text) <= limit:
        return text, False
    return text[:limit], True


# ---------------------------------------------------------------------------
# JsonReporter
# ---------------------------------------------------------------------------


class JsonReporter:
    """Serialises a :class:`ReportBundle` into a JSON document.

    Parameters
    ----------
    options:
        Optional :class:`JsonReportOptions`. Defaults are used when
        omitted.

    Notes
    -----
    The reporter is stateless with respect to the bundle: rendering
    the same bundle twice with the same options produces byte-identical
    output. Options are immutable, so a reporter instance can be
    shared safely across threads.
    """

    def __init__(self, options: Optional[JsonReportOptions] = None) -> None:
        self._options = options or JsonReportOptions()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def options(self) -> JsonReportOptions:
        return self._options

    def render(self, bundle: ReportBundle) -> Dict[str, Any]:
        """Render ``bundle`` into a JSON-serialisable dictionary.

        The returned object is the full document, including the
        envelope, integrity hash (when enabled), and the payload. It
        is safe to pass directly to :func:`json.dumps`.

        Raises
        ------
        JsonValidationError
            If the bundle fails pre-serialisation validation.
        JsonSerializationError
            If a value in the bundle cannot be serialised.
        """
        if bundle is None:
            raise JsonValidationError("bundle must not be None")
        self._validate_bundle(bundle)

        data = self._build_data(bundle)

        envelope: Dict[str, Any] = {
            "schema": SCHEMA_NAME,
            "schema_version": SCHEMA_VERSION,
            "generated_at": _serialize_datetime(
                bundle.metadata.generated_at
                if isinstance(bundle.metadata.generated_at, datetime)
                else datetime.now(timezone.utc)
            ),
            "generator": bundle.metadata.generator
            if isinstance(bundle.metadata.generator, str)
            else f"{GENERATOR_NAME} {GENERATOR_VERSION}",
        }

        if self._options.include_integrity:
            envelope["integrity"] = {
                "algorithm": "sha256",
                "digest": _hash_payload(
                    data,
                    sort_keys=self._options.sort_keys,
                    ensure_ascii=self._options.ensure_ascii,
                ),
            }

        document: Dict[str, Any] = dict(envelope)
        document["data"] = data

        if self._options.omit_null:
            document = _drop_nulls(document)

        return document

    def render_string(self, bundle: ReportBundle) -> str:
        """Render ``bundle`` and return the JSON text."""
        document = self.render(bundle)
        return self._dump(document)

    def write(
        self,
        bundle: ReportBundle,
        path: Union[str, os.PathLike[str]],
    ) -> Path:
        """Render ``bundle`` and write it to ``path`` atomically.

        Returns the absolute path of the written file.
        """
        target = Path(path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        text = self.render_string(bundle)
        data = text.encode("utf-8")

        fd, tmp_name = tempfile.mkstemp(
            prefix=".kmcs-json-", dir=str(target.parent)
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

    def write_stream(
        self,
        bundle: ReportBundle,
        stream: TextIO,
    ) -> None:
        """Write the JSON document to an open text stream.

        The stream is not closed by this method; the caller retains
        ownership. No trailing flush is performed unless the caller
        requested one via ``options.trailing_newline`` (in which case
        a newline is written, but no explicit flush is issued).
        """
        text = self.render_string(bundle)
        stream.write(text)

    # ------------------------------------------------------------------
    # Bundle validation
    # ------------------------------------------------------------------

    def _validate_bundle(self, bundle: ReportBundle) -> None:
        """Reject bundles that would produce an invalid document.

        Validation is minimal: it ensures there is at least a title,
        and that every finding has a non-empty, unique identifier.
        Duplicate identifiers are rejected because downstream
        consumers key findings by ID.
        """
        metadata = getattr(bundle, "metadata", None)
        if metadata is None:
            raise JsonValidationError("bundle has no metadata")
        title = getattr(metadata, "title", None)
        if not isinstance(title, str) or not title:
            raise JsonValidationError("bundle metadata has no title")

        seen: Dict[str, int] = {}
        findings = getattr(bundle, "findings", None) or ()
        for idx, finding in enumerate(findings):
            fid = getattr(finding, "finding_id", None)
            if not isinstance(fid, str) or not fid:
                raise JsonValidationError(
                    f"finding at index {idx} has no identifier"
                )
            if fid in seen:
                raise JsonValidationError(
                    f"duplicate finding identifier {fid!r} "
                    f"(indices {seen[fid]} and {idx})"
                )
            seen[fid] = idx

    # ------------------------------------------------------------------
    # Data section construction
    # ------------------------------------------------------------------

    def _build_data(self, bundle: ReportBundle) -> Dict[str, Any]:
        """Build the ``data`` section of the document.

        The ``data`` section is what the integrity hash is computed
        over. It excludes the envelope (schema name, version,
        generation timestamp) so that the hash is stable across
        re-renders that only change the timestamp.
        """
        metadata = self._serialize_metadata(bundle.metadata)
        campaign = self._serialize_campaign(bundle.campaign)
        corpus = self._serialize_corpus(bundle.corpus)
        findings = [
            self._serialize_finding(f) for f in bundle.findings
        ]

        counts = self._compute_counts(bundle.findings)

        data: Dict[str, Any] = {
            "metadata": metadata,
            "campaign": campaign,
            "corpus": corpus,
            "findings": findings,
            "counts": counts,
        }

        if self._options.include_supplemental_sections:
            data["supplemental_sections"] = [
                {"title": title, "body": body}
                for title, body in bundle.supplemental_sections
            ]
        else:
            data["supplemental_sections"] = []

        return data

    # ------------------------------------------------------------------
    # Section serialisers
    # ------------------------------------------------------------------

    def _serialize_metadata(self, metadata: Any) -> Dict[str, Any]:
        """Serialise :class:`ReportMetadata`."""
        generated_at = getattr(metadata, "generated_at", None)
        if isinstance(generated_at, datetime):
            generated_at_iso = _serialize_datetime(generated_at)
        elif generated_at is None:
            generated_at_iso = None
        else:
            generated_at_iso = str(generated_at)

        notes = getattr(metadata, "notes", ()) or ()
        if not isinstance(notes, (list, tuple)):
            notes = (notes,)

        return {
            "title": _as_optional_str(getattr(metadata, "title", None)),
            "subtitle": _as_optional_str(getattr(metadata, "subtitle", None)),
            "generated_at": generated_at_iso,
            "generator": _as_optional_str(getattr(metadata, "generator", None)),
            "target_description": _as_optional_str(
                getattr(metadata, "target_description", None)
            ),
            "campaign_id": _as_optional_str(
                getattr(metadata, "campaign_id", None)
            ),
            "campaign_name": _as_optional_str(
                getattr(metadata, "campaign_name", None)
            ),
            "sanitizer": _as_optional_str(getattr(metadata, "sanitizer", None)),
            "fuzzer": _as_optional_str(getattr(metadata, "fuzzer", None)),
            "notes": [_as_optional_str(n) or "" for n in notes],
        }

    def _serialize_campaign(
        self, campaign: Optional[Any]
    ) -> Optional[Dict[str, Any]]:
        """Serialise :class:`ReportCampaignSummary`, or None."""
        if campaign is None:
            return None

        started_at = getattr(campaign, "started_at", None)
        finished_at = getattr(campaign, "finished_at", None)

        tags = getattr(campaign, "tags", None) or frozenset()
        try:
            tags_list = sorted(str(t) for t in tags)
        except TypeError:
            tags_list = []

        return {
            "campaign_id": _as_optional_str(
                getattr(campaign, "campaign_id", None)
            ),
            "name": _as_optional_str(getattr(campaign, "name", None)),
            "state": _as_optional_str(getattr(campaign, "state", None)),
            "fuzzer": _as_optional_str(getattr(campaign, "fuzzer", None)),
            "sanitizer": _as_optional_str(getattr(campaign, "sanitizer", None)),
            "target_command": _as_optional_str(
                getattr(campaign, "target_command", None)
            ),
            "workers": _as_optional_int(getattr(campaign, "workers", None)),
            "started_at": (
                _serialize_datetime(started_at)
                if isinstance(started_at, datetime)
                else None
            ),
            "finished_at": (
                _serialize_datetime(finished_at)
                if isinstance(finished_at, datetime)
                else None
            ),
            "runtime_seconds": _as_optional_float(
                getattr(campaign, "runtime_seconds", None)
            ),
            "total_executions": _as_optional_int(
                getattr(campaign, "total_executions", None)
            ),
            "total_crashes": _as_optional_int(
                getattr(campaign, "total_crashes", None)
            ),
            "total_hangs": _as_optional_int(
                getattr(campaign, "total_hangs", None)
            ),
            "coverage_percent": _as_optional_float(
                getattr(campaign, "coverage_percent", None)
            ),
            "corpus_size": _as_optional_int(
                getattr(campaign, "corpus_size", None)
            ),
            "error_message": _as_optional_str(
                getattr(campaign, "error_message", None)
            ),
            "tags": tags_list,
        }

    def _serialize_corpus(
        self, corpus: Optional[Any]
    ) -> Optional[Dict[str, Any]]:
        """Serialise :class:`ReportCorpusSummary`, or None."""
        if corpus is None:
            return None

        root = getattr(corpus, "root", None)
        root_str = str(root) if root is not None else None

        return {
            "root": root_str,
            "total_entries": _as_optional_int(
                getattr(corpus, "total_entries", None)
            ),
            "total_bytes": _as_optional_int(
                getattr(corpus, "total_bytes", None)
            ),
            "smallest_size": _as_optional_int(
                getattr(corpus, "smallest_size", None)
            ),
            "largest_size": _as_optional_int(
                getattr(corpus, "largest_size", None)
            ),
            "mean_size": _as_optional_float(
                getattr(corpus, "mean_size", None)
            ),
            "median_size": _as_optional_float(
                getattr(corpus, "median_size", None)
            ),
            "unique_digests": _as_optional_int(
                getattr(corpus, "unique_digests", None)
            ),
        }

    def _serialize_finding(self, finding: ReportFinding) -> Dict[str, Any]:
        """Serialise a :class:`ReportFinding` into a JSON object.

        Every field of the dataclass is emitted. Fields whose value is
        None are emitted as JSON ``null`` unless ``omit_null`` is
        enabled, in which case they are dropped by the caller.
        """
        # Raw output handling: include only when the option says so,
        # and apply the length cap when a cap is configured.
        raw_output: Optional[str] = None
        raw_output_truncated = False
        raw_output_omitted = False

        if self._options.include_raw_output:
            source_raw = getattr(finding, "raw_output", None)
            if isinstance(source_raw, str):
                text, truncated = _truncate(
                    source_raw, self._options.max_output_chars
                )
                raw_output = text
                raw_output_truncated = truncated
        else:
            raw_output_omitted = True

        # Stack frames: normalise each frame to a JSON object.
        stack_frames_raw = getattr(finding, "stack_frames", ()) or ()
        stack_frames: List[Dict[str, Any]] = []
        for frame in stack_frames_raw:
            if isinstance(frame, Mapping):
                stack_frames.append(
                    {str(k): _serialize_value(v) for k, v in frame.items()}
                )
            else:
                stack_frames.append({"raw": str(frame)})

        # Source location: ensure it is a JSON object or null.
        source_location_raw = getattr(finding, "source_location", None)
        if isinstance(source_location_raw, Mapping):
            source_location: Optional[Dict[str, Any]] = {
                str(k): _serialize_value(v)
                for k, v in source_location_raw.items()
            }
        elif source_location_raw is None:
            source_location = None
        else:
            source_location = {"raw": str(source_location_raw)}

        # Tags: sorted for determinism.
        tags_raw = getattr(finding, "tags", None) or frozenset()
        try:
            tags_list = sorted(str(t) for t in tags_raw)
        except TypeError:
            tags_list = []

        # Notes: normalise to a list of strings.
        notes_raw = getattr(finding, "notes", ()) or ()
        if not isinstance(notes_raw, (list, tuple)):
            notes_raw = (notes_raw,)
        notes_list = [str(n) for n in notes_raw]

        # Metadata: merge in the reporter's own bookkeeping so that
        # consumers can detect truncation and omission without
        # guessing.
        metadata_raw = getattr(finding, "metadata", None) or {}
        try:
            metadata_dict: Dict[str, Any] = {
                str(k): _serialize_value(v)
                for k, v in dict(metadata_raw).items()
            }
        except Exception as exc:  # noqa: BLE001 - defensive
            logger.debug("failed to copy finding metadata: %s", exc)
            metadata_dict = {}

        if raw_output_truncated:
            metadata_dict.setdefault("raw_output_truncated", True)
        if raw_output_omitted:
            metadata_dict.setdefault("raw_output_omitted_by_reporter", True)

        discovered_at = getattr(finding, "discovered_at", None)
        discovered_at_iso = (
            _serialize_datetime(discovered_at)
            if isinstance(discovered_at, datetime)
            else None
        )

        severity = getattr(finding, "severity", None)
        severity_str = _as_optional_str(severity)

        # Normalise the reproduction status into a canonical string.
        repro_status_raw = getattr(finding, "reproduction_status", None)
        repro_status_str = _normalize_status(repro_status_raw)

        regression_status_raw = getattr(finding, "regression_status", None)
        regression_status_str = _normalize_status(regression_status_raw)

        return {
            "finding_id": str(getattr(finding, "finding_id", "")),
            "title": str(getattr(finding, "title", "")),
            "severity": severity_str,
            "severity_level": _severity_level_name(severity),
            "crash_kind": _as_optional_str(getattr(finding, "crash_kind", None)),
            "classification": _as_optional_str(
                getattr(finding, "classification", None)
            ),
            "classification_label": _as_optional_str(
                getattr(finding, "classification_label", None)
            ),
            "fingerprint": _as_optional_str(
                getattr(finding, "fingerprint", None)
            ),
            "sanitizer": _as_optional_str(getattr(finding, "sanitizer", None)),
            "input": {
                "digest": _as_optional_str(getattr(finding, "input_digest", None)),
                "size": _as_optional_int(getattr(finding, "input_size", None)),
                "path": _as_optional_str(getattr(finding, "input_path", None)),
            },
            "process": {
                "exit_code": _as_optional_int(
                    getattr(finding, "exit_code", None)
                ),
                "signal_number": _as_optional_int(
                    getattr(finding, "signal_number", None)
                ),
                "signal_name": _as_optional_str(
                    getattr(finding, "signal_name", None)
                ),
                "timed_out": _as_optional_bool(
                    getattr(finding, "timed_out", None)
                ),
                "fault_address": _as_optional_str(
                    getattr(finding, "fault_address", None)
                ),
                "access_type": _as_optional_str(
                    getattr(finding, "access_type", None)
                ),
            },
            "source_location": source_location,
            "stack_frames": stack_frames,
            "raw_output": raw_output,
            "reproduction": {
                "status": repro_status_str,
                "attempts": _as_optional_int(
                    getattr(finding, "reproduction_attempts", None)
                ),
                "matched": _as_optional_int(
                    getattr(finding, "reproduction_matched", None)
                ),
            },
            "regression": {
                "status": regression_status_str,
                "runs": _as_optional_int(
                    getattr(finding, "regression_runs", None)
                ),
            },
            "provenance": {
                "discovered_at": discovered_at_iso,
                "discovered_by": _as_optional_str(
                    getattr(finding, "discovered_by", None)
                ),
            },
            "tags": tags_list,
            "notes": notes_list,
            "metadata": metadata_dict,
        }

    # ------------------------------------------------------------------
    # Counts
    # ------------------------------------------------------------------

    def _compute_counts(
        self, findings: Sequence[ReportFinding]
    ) -> Dict[str, Any]:
        """Compute aggregate counts from the findings list.

        Counts are derived purely from the supplied data. The
        ``by_severity`` object always contains every canonical level,
        including levels with zero findings, so that consumers can
        index it without checking for key presence.
        """
        severity_order: Tuple[str, ...] = (
            "critical", "high", "medium", "low", "informational", "unknown",
        )
        by_severity: Dict[str, int] = {key: 0 for key in severity_order}

        by_classification: Dict[str, int] = {}

        reproduced = 0
        crashed = 0
        timed_out = 0

        for finding in findings:
            level = _severity_level_name(getattr(finding, "severity", None))
            by_severity[level] = by_severity.get(level, 0) + 1

            classification = (
                getattr(finding, "classification_label", None)
                or getattr(finding, "classification", None)
                or getattr(finding, "crash_kind", None)
                or "unclassified"
            )
            key = str(classification)
            by_classification[key] = by_classification.get(key, 0) + 1

            status = _normalize_status(
                getattr(finding, "reproduction_status", None)
            )
            if status == "reproduced":
                reproduced += 1

            if getattr(finding, "signal_number", None) is not None:
                crashed += 1
            elif getattr(finding, "exit_code", None) not in (None, 0):
                crashed += 1

            if getattr(finding, "timed_out", None) is True:
                timed_out += 1

        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_classification": by_classification,
            "reproduced": reproduced,
            "crashed": crashed,
            "timed_out": timed_out,
        }

    # ------------------------------------------------------------------
    # Dump helpers
    # ------------------------------------------------------------------

    def _dump(self, document: Dict[str, Any]) -> str:
        """Serialise ``document`` according to the reporter's options."""
        kwargs: Dict[str, Any] = {
            "sort_keys": self._options.sort_keys,
            "ensure_ascii": self._options.ensure_ascii,
            "default": _json_default,
        }
        if self._options.indent is not None:
            kwargs["indent"] = self._options.indent
        else:
            kwargs["separators"] = (",", ":")
        try:
            text = json.dumps(document, **kwargs)
        except (TypeError, ValueError) as exc:
            raise JsonSerializationError(
                f"failed to serialise report document: {exc}"
            ) from exc
        if self._options.trailing_newline and not text.endswith("\n"):
            text += "\n"
        return text

    # ------------------------------------------------------------------
    # Representation
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        opts = self._options
        return (
            f"JsonReporter(indent={opts.indent}, "
            f"sort_keys={opts.sort_keys}, "
            f"omit_null={opts.omit_null}, "
            f"include_integrity={opts.include_integrity})"
        )


# ---------------------------------------------------------------------------
# Streaming writer
# ---------------------------------------------------------------------------


class JsonStreamWriter:
    """Streams a JSON report to a text stream without buffering the whole document.

    The streaming writer produces the same document structure as
    :class:`JsonReporter`, but emits it incrementally: the envelope is
    written first, then findings are written one at a time as they are
    added, then the trailer (counts, supplemental sections) is written
    on :meth:`close`.

    Because the payload is not held in memory, the writer cannot
    compute the integrity hash before writing the envelope. Callers
    who require the hash should use :class:`JsonReporter` instead, or
    compute their own hash over the final file.

    Parameters
    ----------
    stream:
        The text stream to write to. Must remain open for the
        lifetime of the writer.
    options:
        Optional :class:`JsonReportOptions`. ``include_integrity`` is
        ignored by the streaming writer.
    bundle_metadata:
        The metadata section to emit. Required.
    campaign:
        Optional campaign summary to emit.
    corpus:
        Optional corpus summary to emit.
    supplemental_sections:
        Optional supplemental sections. These are buffered and
        written on :meth:`close`, because they appear after the
        findings in the document.
    """

    def __init__(
        self,
        stream: TextIO,
        *,
        bundle_metadata: ReportMetadata,
        campaign: Optional[Any] = None,
        corpus: Optional[Any] = None,
        supplemental_sections: Optional[Sequence[Tuple[str, str]]] = None,
        options: Optional[JsonReportOptions] = None,
    ) -> None:
        self._stream = stream
        self._options = options or JsonReportOptions()
        self._metadata = bundle_metadata
        self._campaign = campaign
        self._corpus = corpus
        self._supplemental = list(supplemental_sections or ())
        self._findings_written = 0
        self._classification_counts: Dict[str, int] = {}
        self._severity_counts: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "unknown": 0,
        }
        self._reproduced = 0
        self._crashed = 0
        self._timed_out = 0
        self._closed = False
        self._started = False
        # Reuse the JSON reporter for the per-finding serialisation so
        # that streaming and non-streaming outputs are identical in
        # shape.
        self._delegate = JsonReporter(self._options)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Write the document header. Idempotent."""
        if self._started:
            return
        self._started = True

        envelope: Dict[str, Any] = {
            "schema": SCHEMA_NAME,
            "schema_version": SCHEMA_VERSION,
            "generated_at": _serialize_datetime(
                self._metadata.generated_at
                if isinstance(self._metadata.generated_at, datetime)
                else datetime.now(timezone.utc)
            ),
            "generator": self._metadata.generator
            if isinstance(self._metadata.generator, str)
            else f"{GENERATOR_NAME} {GENERATOR_VERSION}",
        }

        # Emit the envelope as a normal object, then start the "data"
        # object and its scalar members by hand.
        self._write_raw("{")
        self._write_kv_pairs(envelope, indent=1)
        self._write_raw(",\n")
        self._write_raw('  "data": {\n')
        metadata_obj = self._delegate._serialize_metadata(self._metadata)
        self._write_raw('    "metadata": ')
        self._write_raw(self._dump_fragment(metadata_obj))
        self._write_raw(",\n")

        campaign_obj = self._delegate._serialize_campaign(self._campaign)
        self._write_raw('    "campaign": ')
        self._write_raw(self._dump_fragment(campaign_obj))
        self._write_raw(",\n")

        corpus_obj = self._delegate._serialize_corpus(self._corpus)
        self._write_raw('    "corpus": ')
        self._write_raw(self._dump_fragment(corpus_obj))
        self._write_raw(",\n")

        self._write_raw('    "findings": [')

    def add_finding(self, finding: ReportFinding) -> None:
        """Write one finding. Starts the document if it has not been started."""
        if self._closed:
            raise JsonReportError("stream writer has been closed")
        if not self._started:
            self.start()

        obj = self._delegate._serialize_finding(finding)
        fragment = self._dump_fragment(obj)

        if self._findings_written > 0:
            self._write_raw(",")
        self._write_raw("\n")
        self._write_raw(self._indent(fragment, 6))

        self._findings_written += 1

        # Accumulate counts.
        level = _severity_level_name(getattr(finding, "severity", None))
        self._severity_counts[level] = self._severity_counts.get(level, 0) + 1
        classification = (
            getattr(finding, "classification_label", None)
            or getattr(finding, "classification", None)
            or getattr(finding, "crash_kind", None)
            or "unclassified"
        )
        key = str(classification)
        self._classification_counts[key] = (
            self._classification_counts.get(key, 0) + 1
        )
        if _normalize_status(getattr(finding, "reproduction_status", None)) == "reproduced":
            self._reproduced += 1
        if (
            getattr(finding, "signal_number", None) is not None
            or getattr(finding, "exit_code", None) not in (None, 0)
        ):
            self._crashed += 1
        if getattr(finding, "timed_out", None) is True:
            self._timed_out += 1

    def close(self) -> None:
        """Write the document trailer. Idempotent."""
        if self._closed:
            return
        if not self._started:
            self.start()
        self._closed = True

        # Close the findings array.
        if self._findings_written > 0:
            self._write_raw("\n    ")
        self._write_raw("],\n")

        # Counts.
        counts_obj = {
            "total_findings": self._findings_written,
            "by_severity": dict(self._severity_counts),
            "by_classification": dict(self._classification_counts),
            "reproduced": self._reproduced,
            "crashed": self._crashed,
            "timed_out": self._timed_out,
        }
        self._write_raw('    "counts": ')
        self._write_raw(self._dump_fragment(counts_obj))
        self._write_raw(",\n")

        # Supplemental sections.
        if self._options.include_supplemental_sections:
            sections = [
                {"title": title, "body": body}
                for title, body in self._supplemental
            ]
        else:
            sections = []
        self._write_raw('    "supplemental_sections": ')
        self._write_raw(self._dump_fragment(sections))
        self._write_raw("\n")

        # Close data object and root object.
        self._write_raw("  }\n")
        self._write_raw("}\n")

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "JsonStreamWriter":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal writing helpers
    # ------------------------------------------------------------------

    def _write_raw(self, text: str) -> None:
        self._stream.write(text)

    def _write_kv_pairs(
        self, obj: Mapping[str, Any], *, indent: int
    ) -> None:
        """Write the key/value pairs of ``obj`` at the given indent.

        The opening brace is assumed to have been written by the
        caller; this method writes the pairs and does not close the
        object.
        """
        pad = "  " * indent
        items = sorted(obj.items()) if self._options.sort_keys else list(obj.items())
        for i, (key, value) in enumerate(items):
            if i > 0:
                self._write_raw(",\n")
            else:
                self._write_raw("\n")
            self._write_raw(pad)
            self._write_raw(json.dumps(str(key)))
            self._write_raw(": ")
            self._write_raw(self._dump_fragment(value))
        self._write_raw("\n")
        self._write_raw("  " * (indent - 1))

    def _dump_fragment(self, value: Any) -> str:
        """Serialise a fragment using the reporter's options."""
        kwargs: Dict[str, Any] = {
            "sort_keys": self._options.sort_keys,
            "ensure_ascii": self._options.ensure_ascii,
            "default": _json_default,
        }
        if self._options.indent is not None:
            kwargs["indent"] = self._options.indent
        else:
            kwargs["separators"] = (",", ":")
        return json.dumps(value, **kwargs)

    def _indent(self, text: str, spaces: int) -> str:
        """Indent every line of ``text`` by ``spaces`` spaces."""
        if not text:
            return text
        pad = " " * spaces
        lines = text.splitlines(keepends=False)
        return "\n".join(pad + line for line in lines)

    # ------------------------------------------------------------------
    # Representation
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"JsonStreamWriter(findings_written={self._findings_written}, "
            f"closed={self._closed})"
        )


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------


def _as_optional_str(value: Any) -> Optional[str]:
    """Coerce ``value`` to str, or None.

    Empty strings become None so that consumers see a consistent
    "absent" marker. Non-string values are stringified. This is the
    only coercion the reporter performs on user-supplied values;
    everything else is passed through unchanged.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value if value != "" else None
    return str(value)


def _as_optional_int(value: Any) -> Optional[int]:
    """Coerce ``value`` to int, or None.

    Floats with zero fractional part are accepted (JSON does not
    distinguish int from float in all encoders). Booleans are
    rejected: a bool is not an int here.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_optional_float(value: Any) -> Optional[float]:
    """Coerce ``value`` to float, or None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_optional_bool(value: Any) -> Optional[bool]:
    """Coerce ``value`` to bool, or None.

    Only genuine booleans and the strings ``"true"`` / ``"false"``
    (case-insensitive) are accepted. Numeric zero and one are NOT
    treated as booleans, because the domain distinguishes them.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return None


def _severity_level_name(value: Any) -> str:
    """Normalise an arbitrary severity value to a canonical name.

    Uses the shared model's :class:`SeverityLevel` when available.
    Unknown values map to ``"unknown"``.
    """
    if value is None:
        return "unknown"
    if _HAVE_SHARED_MODEL and hasattr(value, "value"):
        try:
            parsed = SeverityLevel.parse(value)  # type: ignore[union-attr]
            return getattr(parsed, "value", "unknown")
        except Exception:  # noqa: BLE001
            pass
    text = str(value).strip().lower()
    if text in ("critical", "high", "medium", "low", "informational"):
        return text
    if text in ("info", "note"):
        return "informational"
    if text in ("severe",):
        return "high"
    if text in ("moderate", "med"):
        return "medium"
    return "unknown"


def _normalize_status(value: Any) -> Optional[str]:
    """Normalise a status value to its canonical lowercase form."""
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        return text.lower()
    inner = getattr(value, "value", None)
    if isinstance(inner, str):
        return inner.lower()
    text = str(value).strip()
    return text.lower() if text else None


def _json_default(value: Any) -> Any:
    """Fallback encoder for values :func:`json.dumps` cannot handle.

    Used only for objects that slipped past the reporter's
    normalisation. Datetimes become ISO strings, Paths become strings,
    and anything else falls back to ``str``.
    """
    if isinstance(value, datetime):
        return _serialize_datetime(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (frozenset, set)):
        return sorted(str(v) for v in value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            return to_dict()
        except Exception:  # noqa: BLE001
            pass
    return str(value)


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


def dump_json(
    bundle: ReportBundle,
    path: Union[str, os.PathLike[str]],
    *,
    options: Optional[JsonReportOptions] = None,
) -> Path:
    """Render ``bundle`` and write it to ``path`` atomically.

    Returns the absolute path of the written file.
    """
    reporter = JsonReporter(options)
    return reporter.write(bundle, path)


def dump_json_string(
    bundle: ReportBundle,
    *,
    options: Optional[JsonReportOptions] = None,
) -> str:
    """Render ``bundle`` and return the JSON text."""
    reporter = JsonReporter(options)
    return reporter.render_string(bundle)


def dump_json_stream(
    bundle: ReportBundle,
    stream: TextIO,
    *,
    options: Optional[JsonReportOptions] = None,
) -> None:
    """Write ``bundle`` as JSON to an open text stream."""
    reporter = JsonReporter(options)
    reporter.write_stream(bundle, stream)


def stream_to_file(
    path: Union[str, os.PathLike[str]],
    *,
    metadata: ReportMetadata,
    campaign: Optional[Any] = None,
    corpus: Optional[Any] = None,
    supplemental_sections: Optional[Sequence[Tuple[str, str]]] = None,
    options: Optional[JsonReportOptions] = None,
) -> JsonStreamWriter:
    """Open a streaming writer to a file and return it.

    The returned writer must be used as a context manager, or closed
    explicitly. The file is opened in text mode with UTF-8 encoding
    and is closed when the writer's context exits.

    Example::

        with stream_to_file("report.json", metadata=md) as w:
            for finding in findings:
                w.add_finding(finding)

    Parameters
    ----------
    path:
        Destination file. Parent directories are created if missing.
    metadata:
        The bundle's metadata section.
    campaign:
        Optional campaign summary.
    corpus:
        Optional corpus summary.
    supplemental_sections:
        Optional supplemental sections.
    options:
        Optional reporter options.
    """
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    file_obj = open(target, "w", encoding="utf-8")
    writer = JsonStreamWriter(
        file_obj,
        bundle_metadata=metadata,
        campaign=campaign,
        corpus=corpus,
        supplemental_sections=supplemental_sections,
        options=options,
    )
    # Wrap close so that the underlying file is also closed.
    original_close = writer.close

    def _close() -> None:
        try:
            original_close()
        finally:
            try:
                file_obj.flush()
            except Exception:  # noqa: BLE001
                pass
            try:
                file_obj.close()
            except Exception:  # noqa: BLE001
                pass

    writer.close = _close  # type: ignore[method-assign]
    return writer


# ---------------------------------------------------------------------------
# Schema description
# ---------------------------------------------------------------------------


def describe_schema() -> Dict[str, Any]:
    """Return a machine-readable description of the emitted schema.

    The description is intended for tools that generate client code
    from the schema. It is deliberately minimal: it lists the top-
    level keys and their types, not a full JSON Schema document.
    Consumers that need a formal schema should look at the sample
    output and this description together.
    """
    return {
        "schema": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "envelope": {
            "schema": "string",
            "schema_version": "string",
            "generated_at": "iso8601",
            "generator": "string",
            "integrity": {
                "algorithm": "string",
                "digest": "hex string",
            },
        },
        "data": {
            "metadata": "object",
            "campaign": "object | null",
            "corpus": "object | null",
            "findings": "array",
            "counts": "object",
            "supplemental_sections": "array",
        },
        "finding": {
            "finding_id": "string (unique within findings)",
            "title": "string",
            "severity": "string | null",
            "severity_level": "critical|high|medium|low|informational|unknown",
            "crash_kind": "string | null",
            "classification": "string | null",
            "classification_label": "string | null",
            "fingerprint": "string | null",
            "sanitizer": "string | null",
            "input": {
                "digest": "string | null",
                "size": "integer | null",
                "path": "string | null",
            },
            "process": {
                "exit_code": "integer | null",
                "signal_number": "integer | null",
                "signal_name": "string | null",
                "timed_out": "boolean | null",
                "fault_address": "string | null",
                "access_type": "string | null",
            },
            "source_location": "object | null",
            "stack_frames": "array of objects",
            "raw_output": "string | null",
            "reproduction": {
                "status": "string | null",
                "attempts": "integer | null",
                "matched": "integer | null",
            },
            "regression": {
                "status": "string | null",
                "runs": "integer | null",
            },
            "provenance": {
                "discovered_at": "iso8601 | null",
                "discovered_by": "string | null",
            },
            "tags": "array of strings",
            "notes": "array of strings",
            "metadata": "object",
        },
        "counts": {
            "total_findings": "integer",
            "by_severity": "object with every canonical level",
            "by_classification": "object",
            "reproduced": "integer",
            "crashed": "integer",
            "timed_out": "integer",
        },
    }


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

__version__ = "1.0.0"


# Emit a warning at import time if the shared model could not be
# imported. This is a real, actionable condition: without the shared
# model the reporter cannot project crash records, reproduction
# results, or regression cases into findings. Callers who see this
# warning should check that :mod:`kmcs.reporting.html` is present.
if not _HAVE_SHARED_MODEL:  # pragma: no cover - depends on layout
    logger.warning(
        "kmcs.reporting.json_report could not import the shared "
        "report model from kmcs.reporting.html; finding factories "
        "will be unavailable. Detail: %s",
        getattr(globals(), "_SHARED_IMPORT_ERROR", "unknown"),
    )
