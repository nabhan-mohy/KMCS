# KMCS SARIF Report
# =================
#
# Standardised, security-tool-friendly rendering of KMCS findings.
#
# SARIF (Static Analysis Results Interchange Format) is a JSON-based
# format for representing the output of static analysis tools. It is
# consumed by CI systems, code-scanning dashboards, and security
# automation platforms. KMCS is primarily a dynamic analysis platform
# (fuzzing, crash triage, reproduction), not a static analyzer, so
# the mapping between KMCS's model and SARIF's is deliberately
# partial: only those fields with a direct, accurate correspondence
# are emitted, and no unrelated KMCS data is forced into SARIF fields
# where it would be misleading.
#
# What this reporter maps
# -----------------------
#
# KMCS field                -> SARIF field
# -------------------------------------------------------------------
# metadata.generator        -> runs[0].tool.driver.name / .version
# metadata.title            -> runs[0].properties.kmcs.reportTitle
# metadata.campaign_id      -> runs[0].automationDetails.id
# campaign.target_command   -> runs[0].invocations[0].commandLine
# campaign.started_at       -> runs[0].invocations[0].startTimeUtc
# campaign.finished_at      -> runs[0].invocations[0].endTimeUtc
# campaign.error_message    -> runs[0].invocations[0].executionSuccessful
# finding.classification    -> runs[0].results[i].ruleId (derived)
# finding.severity          -> runs[0].results[i].level
# finding.title             -> runs[0].results[i].message.text
# finding.source_location   -> runs[0].results[i].locations[0]
# finding.stack_frames[0]   -> runs[0].results[i].locations[0] (fallback)
# finding.fingerprint       -> runs[0].results[i].partialFingerprints
# finding.input_digest      -> runs[0].artifacts[j].hashes["sha-256"]
# finding.input_path        -> runs[0].artifacts[j].location.uri
# finding.tags              -> rules[k].properties.tags
# finding.* (other)         -> runs[0].results[i].properties.kmcs.*
#
# What this reporter deliberately does not map
# --------------------------------------------
#
# * ``raw_output``: SARIF has no field that means "arbitrary tool
#   output". Stuffing it into ``message.markdown`` or a snippet would
#   misrepresent it. It is omitted.
#
# * ``exit_code``: SARIF is not a process-execution format. Process
#   outcomes are exposed through ``properties.kmcs.exitCode`` for
#   consumers who care, but they do not drive any native SARIF field.
#
# * ``reproduction_*`` / ``regression_*``: These describe KMCS's own
#   workflow, not the analysis result. They are exposed through
#   ``properties.kmcs.*`` but never as SARIF-native fields.
#
# Severity mapping
# ----------------
#
# SARIF's ``level`` field has exactly four legal values: ``none``,
# ``note``, ``warning``, ``error``. KMCS severities map as follows:
#
#     critical       -> error
#     high           -> error
#     medium         -> warning
#     low            -> note
#     informational  -> note
#     (unclassified) -> warning
#
# The unclassified case maps to ``warning`` rather than ``none`` so
# that an unclassified finding is not silently hidden by consumers
# that filter out ``none``-level results.
#
# Rule derivation
# ---------------
#
# One SARIF rule is created per unique rule ID. A rule ID is derived
# from the finding's ``classification`` (preferred) or ``crash_kind``
# (fallback) or the literal ``"unknown"``. The rule's default level
# is the maximum severity observed among findings with that rule ID,
# and its tags are the union of all such findings' tags.
#
# Artifact derivation
# -------------------
#
# One SARIF artifact is created per unique input path, in sorted order.
# When an input digest is present it is included as the artifact's
# ``hashes["sha-256"]``. When an input size is present it is included
# as the artifact's ``length``.
#
# Schema compliance
# -----------------
#
# The output conforms to SARIF v2.1.0:
#
#   * ``version`` is the literal ``"2.1.0"``.
#   * ``$schema`` points to the community-hosted schema.
#   * ``runs`` is a non-empty array.
#   * Every result has a non-empty ``message.text``.
#   * Every location has ``physicalLocation`` or ``logicalLocations``.
#   * Every ``level`` is one of ``none`` / ``note`` / ``warning`` / ``error``.
#
# Compatibility
# -------------
#
# Python 3.10+.

from __future__ import annotations

import hashlib
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
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    TextIO,
    Tuple,
    Union,
)


# ---------------------------------------------------------------------------
# Shared model import
# ---------------------------------------------------------------------------

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
        "kmcs.reporting.sarif requires kmcs.reporting.html to be "
        f"importable: {_import_exc}"
    ) from _import_exc


logger = logging.getLogger(__name__)


__all__ = [
    "SarifReporter",
    "SarifOptions",
    "SarifReportError",
    "SarifValidationError",
    "SarifSerializationError",
    "render_sarif",
    "dump_sarif",
    "dump_sarif_string",
    "write_sarif",
    "describe_mapping",
    "SARIF_VERSION",
    "SARIF_SCHEMA_URL",
    "KMCS_TOOL_NAME",
    "KMCS_TOOL_INFORMATION_URI",
    "RULE_ID_PREFIX",
    "FINGERPRINT_KEY",
    "DEFAULT_INDENT",
    "DEFAULT_SORT_KEYS",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: The SARIF version this reporter emits. Only this literal value is
#: valid in the ``version`` field of a SARIF document.
SARIF_VERSION: str = "2.1.0"

#: URL of the canonical SARIF v2.1.0 JSON schema. Consumers use this
#: to validate the document. The URL is stable and community-hosted.
SARIF_SCHEMA_URL: str = "https://json.schemastore.org/sarif-2.1.0.json"

#: Name under which KMCS results are reported in the tool driver.
KMCS_TOOL_NAME: str = "KMCS"

#: Information URI for the KMCS project. Used by SARIF consumers that
#: link back to the tool's documentation.
KMCS_TOOL_INFORMATION_URI: str = "https://example.invalid/kmcs"

#: Prefix for KMCS-derived rule IDs. All KMCS rules begin with this
#: string followed by a hyphen, so that they can be distinguished
#: from rules produced by other tools in a merged SARIF document.
RULE_ID_PREFIX: str = "kmcs"

#: Key used in ``partialFingerprints`` for the KMCS crash fingerprint.
#: The ``/v1`` suffix is the tool-convention way of versioning the
#: fingerprint algorithm without changing the key name.
FINGERPRINT_KEY: str = "kmcs/v1"

#: Default pretty-print indent for the emitted JSON. Set to ``None``
#: for compact output. SARIF documents are typically consumed by
#: machines, but a small indent makes diffs and manual inspection
#: much easier.
DEFAULT_INDENT: Optional[int] = 2

#: Whether to sort keys in the emitted JSON. Sorting makes the
#: document deterministic and diff-friendly but reorders fields away
#: from the SARIF schema's natural order. The default preserves
#: schema order.
DEFAULT_SORT_KEYS: bool = False

#: SARIF ``level`` values mapped from KMCS severity names. See the
#: module docstring for the rationale behind each choice.
_LEVEL_MAP: Mapping[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
    "unknown": "warning",
}

#: Numeric ranking used when computing a rule's default level from
#: the findings that share it. Higher is more severe.
_SEVERITY_RANK: Mapping[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "unknown": 0,
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SarifReportError(Exception):
    """Base class for all SARIF reporter errors."""


class SarifValidationError(SarifReportError):
    """Raised when a bundle fails pre-render validation."""


class SarifSerializationError(SarifReportError):
    """Raised when a value in the bundle cannot be serialised."""


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------


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


def _severity_to_level(value: Any) -> str:
    """Map a severity value to a SARIF ``level`` string."""
    return _LEVEL_MAP.get(_severity_level_name(value), "warning")


def _severity_rank(value: Any) -> int:
    """Return a numeric rank for a severity value."""
    return _SEVERITY_RANK.get(_severity_level_name(value), 0)


def _rank_to_level(rank: int) -> str:
    """Map a severity rank back to a SARIF ``level`` string."""
    for level_name, level_rank in _SEVERITY_RANK.items():
        if level_rank == rank:
            return _LEVEL_MAP.get(level_name, "warning")
    return "warning"


# ---------------------------------------------------------------------------
# Rule ID derivation
# ---------------------------------------------------------------------------

# Characters allowed in a rule ID. SARIF rule IDs must be non-empty
# strings; the spec does not restrict their character set beyond
# that, but many consumers assume alphanumeric-and-hyphen.
_RULE_ID_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9]+")


def _sanitize_rule_id(text: str) -> str:
    """Return a rule-ID-safe version of ``text``.

    Lowercase, replace runs of non-alphanumeric characters with a
    single hyphen, trim leading and trailing hyphens. An empty or
    all-non-alphanumeric input becomes ``"unknown"``.
    """
    if not text:
        return "unknown"
    sanitized = _RULE_ID_SANITIZE_RE.sub("-", str(text).strip().lower())
    sanitized = sanitized.strip("-")
    return sanitized or "unknown"


def _derive_rule_id(finding: ReportFinding) -> str:
    """Return the SARIF rule ID for a finding."""
    classification = getattr(finding, "classification", None)
    if classification:
        return f"{RULE_ID_PREFIX}-{_sanitize_rule_id(str(classification))}"
    crash_kind = getattr(finding, "crash_kind", None)
    if crash_kind:
        return f"{RULE_ID_PREFIX}-{_sanitize_rule_id(str(crash_kind))}"
    return f"{RULE_ID_PREFIX}-unknown"


def _derive_rule_display_name(finding: ReportFinding) -> str:
    """Return a human-readable display name for a finding's rule.

    Prefers the classification label, then a humanised version of
    the classification or crash kind, then the rule's title. Never
    returns an empty string.
    """
    label = getattr(finding, "classification_label", None)
    if label:
        return str(label)
    classification = getattr(finding, "classification", None)
    if classification:
        return _humanize(str(classification))
    crash_kind = getattr(finding, "crash_kind", None)
    if crash_kind:
        return _humanize(str(crash_kind))
    title = getattr(finding, "title", None)
    if title:
        return str(title)
    return "Unclassified"


def _humanize(text: str) -> str:
    """Convert a machine-readable identifier to a display name.

    ``"heap-buffer-overflow"`` becomes ``"Heap Buffer Overflow"``.
    Underscores and hyphens become spaces; word-initial letters are
    capitalised.
    """
    if not text:
        return ""
    spaced = re.sub(r"[-_]+", " ", text).strip()
    return " ".join(word.capitalize() for word in spaced.split())


def _rule_name_from_display(display: str) -> str:
    """Return a SARIF rule ``name`` from a display string.

    SARIF's ``name`` field is meant to be suitable for use as a
    configuration identifier: no spaces, no punctuation. The result
    is PascalCase.
    """
    if not display:
        return "UnnamedRule"
    words = re.split(r"[\s\-_]+", display)
    sanitized = "".join(
        "".join(c for c in w if c.isalnum()).capitalize()
        for w in words
        if w
    )
    return sanitized or "UnnamedRule"


# ---------------------------------------------------------------------------
# URI helpers
# ---------------------------------------------------------------------------


def _path_to_uri(path: Any) -> Optional[str]:
    """Return a URI suitable for use in SARIF artifact locations.

    Backslashes are converted to forward slashes, and spaces are
    percent-encoded. Values that already look like URIs are passed
    through unchanged.
    """
    if path is None:
        return None
    text = str(path)
    if not text:
        return None
    if "://" in text:
        return text
    normalized = text.replace("\\", "/")
    normalized = normalized.replace(" ", "%20")
    return normalized


# ---------------------------------------------------------------------------
# Location extraction
# ---------------------------------------------------------------------------


def _coerce_line(value: Any) -> Optional[int]:
    """Coerce a line or column value to a positive integer, or None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n < 1:
        return None
    return n


def _extract_source_location(
    finding: ReportFinding,
) -> Optional[Dict[str, Any]]:
    """Build a SARIF ``location`` object from a finding.

    Prefers the finding's ``source_location`` mapping. Falls back to
    the top stack frame when no source location is present. Returns
    ``None`` when the finding has neither.
    """
    loc = getattr(finding, "source_location", None)
    file_ = None
    line = None
    column = None
    function = None

    if isinstance(loc, Mapping):
        file_ = loc.get("file") or loc.get("filename") or loc.get("path")
        line = loc.get("line") or loc.get("lineno")
        column = loc.get("column") or loc.get("col")
        function = loc.get("function") or loc.get("func") or loc.get("name")

    if file_ is None and function is None:
        # Fall back to the top stack frame.
        frames = getattr(finding, "stack_frames", None) or ()
        if frames:
            first = frames[0]
            if isinstance(first, Mapping):
                file_ = (
                    first.get("file")
                    or first.get("filename")
                    or first.get("path")
                )
                line = first.get("line") or first.get("lineno")
                column = first.get("column") or first.get("col")
                function = (
                    first.get("function")
                    or first.get("func")
                    or first.get("name")
                )

    if file_ is None and function is None:
        return None

    location: Dict[str, Any] = {}

    if file_ is not None:
        uri = _path_to_uri(file_)
        if uri:
            physical: Dict[str, Any] = {
                "artifactLocation": {"uri": uri}
            }
            region: Dict[str, Any] = {}
            start_line = _coerce_line(line)
            if start_line is not None:
                region["startLine"] = start_line
            start_column = _coerce_line(column)
            if start_column is not None:
                region["startColumn"] = start_column
            if region:
                physical["region"] = region
            location["physicalLocation"] = physical

    if function is not None:
        location["logicalLocations"] = [
            {"name": str(function), "kind": "function"}
        ]

    if not location:
        return None
    return location


def _extract_artifact_uri(finding: ReportFinding) -> Optional[str]:
    """Return the artifact URI for a finding's input, or None."""
    path = getattr(finding, "input_path", None)
    if path:
        return _path_to_uri(path)
    digest = getattr(finding, "input_digest", None)
    if digest:
        # No path but a digest: synthesise a stable URI under the
        # kmcs scheme so that consumers can still key artifacts.
        return f"kmcs://input/{digest}"
    return None


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SarifOptions:
    """Immutable options for :class:`SarifReporter`.

    Attributes
    ----------
    indent:
        JSON indentation level. ``None`` produces compact output.
    sort_keys:
        Whether to sort object keys. The default (False) preserves
        SARIF's natural field order, which matches the schema's
        presentation order and reads more naturally.
    include_rules:
        Whether to emit the ``tool.driver.rules`` array. Disabling
        this produces a smaller document but means consumers cannot
        resolve rule metadata without consulting another source.
    include_artifacts:
        Whether to emit the ``run.artifacts`` array. Disabling this
        produces a smaller document but omits input hashes and sizes.
    include_invocations:
        Whether to emit the ``run.invocations`` array. Disabling this
        omits campaign timing and command line information.
    include_fingerprints:
        Whether to emit ``partialFingerprints`` on results. Fingerprints
        are used by code-scanning dashboards to track findings across
        runs, so this is enabled by default.
    include_result_properties:
        Whether to emit the ``properties`` bag on results. This is
        where KMCS-specific fields that have no SARIF-native
        equivalent are exposed.
    include_tool_properties:
        Whether to emit ``tool.driver.properties`` with KMCS-specific
        metadata.
    tool_name:
        Override for the tool name in the driver section.
    tool_version:
        Override for the tool version.
    tool_information_uri:
        Override for the tool's information URI.
    trailing_newline:
        Whether to append a newline to the string form.
    """

    indent: Optional[int] = DEFAULT_INDENT
    sort_keys: bool = DEFAULT_SORT_KEYS
    include_rules: bool = True
    include_artifacts: bool = True
    include_invocations: bool = True
    include_fingerprints: bool = True
    include_result_properties: bool = True
    include_tool_properties: bool = True
    tool_name: Optional[str] = None
    tool_version: Optional[str] = None
    tool_information_uri: Optional[str] = None
    trailing_newline: bool = True

    def __post_init__(self) -> None:
        if self.indent is not None and self.indent < 0:
            raise ValueError("indent must be non-negative or None")


# ---------------------------------------------------------------------------
# SarifReporter
# ---------------------------------------------------------------------------


class SarifReporter:
    """Renders a :class:`ReportBundle` as a SARIF v2.1.0 document.

    Parameters
    ----------
    options:
        Optional :class:`SarifOptions`. Defaults are used when
        omitted.

    Notes
    -----
    A reporter instance is stateless with respect to the bundle.
    Rendering the same bundle twice with the same options produces
    byte-identical output. Options are immutable, so a reporter may
    be shared safely across threads.
    """

    def __init__(self, options: Optional[SarifOptions] = None) -> None:
        self._options = options or SarifOptions()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def options(self) -> SarifOptions:
        return self._options

    def render(self, bundle: ReportBundle) -> Dict[str, Any]:
        """Render ``bundle`` as a SARIF document and return it as a dict.

        Raises
        ------
        SarifValidationError
            If the bundle fails pre-render validation.
        SarifSerializationError
            If a value cannot be serialised.
        """
        if bundle is None:
            raise SarifValidationError("bundle must not be None")
        self._validate(bundle)

        findings = self._ordered_findings(bundle)
        rules, rule_index = self._build_rules(findings)
        artifacts, artifact_index = self._build_artifacts(findings)
        results = self._build_results(
            findings, rule_index, artifact_index
        )

        run: Dict[str, Any] = {
            "tool": self._build_tool(bundle, rules),
        }

        if self._options.include_invocations:
            invocation = self._build_invocation(bundle)
            if invocation is not None:
                run["invocations"] = [invocation]

        if self._options.include_artifacts and artifacts:
            run["artifacts"] = artifacts

        run["results"] = results

        run["columnKind"] = "unicodeCodePoints"

        automation_details = self._build_automation_details(bundle)
        if automation_details is not None:
            run["automationDetails"] = automation_details

        run_props = self._build_run_properties(bundle)
        if run_props:
            run["properties"] = run_props

        return {
            "$schema": SARIF_SCHEMA_URL,
            "version": SARIF_VERSION,
            "runs": [run],
        }

    def render_string(self, bundle: ReportBundle) -> str:
        """Render ``bundle`` as a SARIF JSON string."""
        document = self.render(bundle)
        return self._dump(document)

    def write(
        self,
        bundle: ReportBundle,
        path: Union[str, os.PathLike[str]],
    ) -> Path:
        """Render ``bundle`` and write it to ``path`` atomically."""
        target = Path(path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        text = self.render_string(bundle)
        data = text.encode("utf-8")

        fd, tmp_name = tempfile.mkstemp(
            prefix=".kmcs-sarif-", dir=str(target.parent)
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
        """Write the SARIF document to an open text stream.

        The stream is not closed by this method.
        """
        text = self.render_string(bundle)
        stream.write(text)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self, bundle: ReportBundle) -> None:
        metadata = getattr(bundle, "metadata", None)
        if metadata is None:
            raise SarifValidationError("bundle has no metadata")
        title = getattr(metadata, "title", None)
        if not isinstance(title, str) or not title.strip():
            raise SarifValidationError("bundle metadata has no title")

        seen: Dict[str, int] = {}
        findings = getattr(bundle, "findings", None) or ()
        for idx, finding in enumerate(findings):
            fid = getattr(finding, "finding_id", None)
            if not isinstance(fid, str) or not fid:
                raise SarifValidationError(
                    f"finding at index {idx} has no identifier"
                )
            if fid in seen:
                raise SarifValidationError(
                    f"duplicate finding identifier {fid!r} "
                    f"(indices {seen[fid]} and {idx})"
                )
            seen[fid] = idx

    # ------------------------------------------------------------------
    # Ordering
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
    # Tool driver
    # ------------------------------------------------------------------

    def _build_tool(
        self,
        bundle: ReportBundle,
        rules: Sequence[Dict[str, Any]],
    ) -> Dict[str, Any]:
        metadata = bundle.metadata
        name = self._options.tool_name or self._resolve_tool_name(metadata)
        version = self._options.tool_version or self._resolve_tool_version(metadata)
        info_uri = (
            self._options.tool_information_uri or KMCS_TOOL_INFORMATION_URI
        )

        driver: Dict[str, Any] = {
            "name": name,
            "version": version,
            "informationUri": info_uri,
        }

        if self._options.include_tool_properties:
            props = self._build_driver_properties(bundle)
            if props:
                driver["properties"] = props

        if self._options.include_rules and rules:
            driver["rules"] = rules

        return {"driver": driver}

    @staticmethod
    def _resolve_tool_name(metadata: ReportMetadata) -> str:
        """Best-effort extraction of the tool name from metadata.generator."""
        generator = getattr(metadata, "generator", None)
        if isinstance(generator, str) and generator:
            # "KMCS 1.0.0" -> "KMCS"
            parts = generator.split()
            if parts:
                return parts[0]
        return KMCS_TOOL_NAME

    @staticmethod
    def _resolve_tool_version(metadata: ReportMetadata) -> str:
        """Best-effort extraction of the tool version from metadata.generator."""
        generator = getattr(metadata, "generator", None)
        if isinstance(generator, str) and generator:
            parts = generator.split(maxsplit=1)
            if len(parts) == 2:
                return parts[1]
        return GENERATOR_VERSION

    def _build_driver_properties(
        self, bundle: ReportBundle
    ) -> Dict[str, Any]:
        props: Dict[str, Any] = {}
        metadata = bundle.metadata

        title = getattr(metadata, "title", None)
        if title:
            props["reportTitle"] = str(title)
        subtitle = getattr(metadata, "subtitle", None)
        if subtitle:
            props["reportSubtitle"] = str(subtitle)
        campaign_id = getattr(metadata, "campaign_id", None)
        if campaign_id:
            props["campaignId"] = str(campaign_id)
        campaign_name = getattr(metadata, "campaign_name", None)
        if campaign_name:
            props["campaignName"] = str(campaign_name)
        fuzzer = getattr(metadata, "fuzzer", None)
        if fuzzer:
            props["fuzzer"] = str(fuzzer)
        sanitizer = getattr(metadata, "sanitizer", None)
        if sanitizer:
            props["sanitizer"] = str(sanitizer)

        return props

    # ------------------------------------------------------------------
    # Automation details
    # ------------------------------------------------------------------

    def _build_automation_details(
        self, bundle: ReportBundle
    ) -> Optional[Dict[str, Any]]:
        metadata = bundle.metadata
        campaign_id = getattr(metadata, "campaign_id", None)
        campaign_name = getattr(metadata, "campaign_name", None)
        if not campaign_id and not campaign_name:
            return None

        details: Dict[str, Any] = {}
        if campaign_id:
            details["id"] = f"kmcs/{campaign_id}"
        description_text = None
        if campaign_name and campaign_id:
            description_text = f"{campaign_name} ({campaign_id})"
        elif campaign_name:
            description_text = campaign_name
        elif campaign_id:
            description_text = campaign_id
        if description_text:
            details["description"] = {"text": description_text}
        return details

    # ------------------------------------------------------------------
    # Invocation
    # ------------------------------------------------------------------

    def _build_invocation(
        self, bundle: ReportBundle
    ) -> Optional[Dict[str, Any]]:
        campaign = bundle.campaign
        invocation: Dict[str, Any] = {
            "executionSuccessful": True,
        }

        if campaign is not None:
            started = getattr(campaign, "started_at", None)
            finished = getattr(campaign, "finished_at", None)
            if isinstance(started, datetime):
                invocation["startTimeUtc"] = _iso_utc(started)
            if isinstance(finished, datetime):
                invocation["endTimeUtc"] = _iso_utc(finished)
            command = getattr(campaign, "target_command", None)
            if command:
                invocation["commandLine"] = str(command)
            error = getattr(campaign, "error_message", None)
            if error:
                invocation["executionSuccessful"] = False
                invocation["toolExecutionNotifications"] = [
                    {
                        "level": "error",
                        "message": {"text": str(error)},
                    }
                ]

        # If nothing useful is present, omit the invocation rather
        # than emitting a bare "executionSuccessful": true.
        if len(invocation) <= 1:
            return None
        return invocation

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def _build_rules(
        self, findings: Sequence[ReportFinding]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
        if not self._options.include_rules:
            return [], {}

        # Group findings by derived rule ID.
        groups: Dict[str, List[ReportFinding]] = {}
        for finding in findings:
            rule_id = _derive_rule_id(finding)
            groups.setdefault(rule_id, []).append(finding)

        rules: List[Dict[str, Any]] = []
        index: Dict[str, int] = {}
        for rule_id in sorted(groups.keys()):
            rule_findings = groups[rule_id]
            rule = self._build_rule(rule_id, rule_findings)
            index[rule_id] = len(rules)
            rules.append(rule)
        return rules, index

    def _build_rule(
        self,
        rule_id: str,
        rule_findings: Sequence[ReportFinding],
    ) -> Dict[str, Any]:
        display = _derive_rule_display_name(rule_findings[0])
        name = _rule_name_from_display(display)

        # Max severity across all findings sharing the rule.
        max_rank = 0
        for f in rule_findings:
            rank = _severity_rank(getattr(f, "severity", None))
            if rank > max_rank:
                max_rank = rank
        level = _rank_to_level(max_rank)

        # Aggregate tags across all findings.
        tag_set: Set[str] = set()
        for f in rule_findings:
            for tag in (getattr(f, "tags", None) or ()):
                tag_set.add(str(tag))

        rule: Dict[str, Any] = {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": display},
            "defaultConfiguration": {"level": level},
        }

        # Full description: a slightly longer version of the display
        # name, including the count of findings that share the rule.
        count = len(rule_findings)
        full_text = (
            f"{display} — reported by KMCS for {count} "
            f"finding{'s' if count != 1 else ''}."
        )
        rule["fullDescription"] = {"text": full_text}

        if tag_set:
            rule["properties"] = {"tags": sorted(tag_set)}

        return rule

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def _build_artifacts(
        self, findings: Sequence[ReportFinding]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
        if not self._options.include_artifacts:
            return [], {}

        # Group findings by artifact URI.
        grouped: Dict[str, List[ReportFinding]] = {}
        for finding in findings:
            uri = _extract_artifact_uri(finding)
            if uri is None:
                continue
            grouped.setdefault(uri, []).append(finding)

        artifacts: List[Dict[str, Any]] = []
        index: Dict[str, int] = {}
        for uri in sorted(grouped.keys()):
            artifact = self._build_artifact(uri, grouped[uri])
            index[uri] = len(artifacts)
            artifacts.append(artifact)
        return artifacts, index

    def _build_artifact(
        self,
        uri: str,
        findings: Sequence[ReportFinding],
    ) -> Dict[str, Any]:
        # Collect the digests and sizes that appear across the
        # grouped findings. When a digest is available, use it as
        # the artifact hash. When multiple distinct digests appear
        # for the same URI (which should be rare), use the first one
        # in the sorted order so that the output is deterministic.
        digests = set()
        sizes = set()
        for f in findings:
            digest = getattr(f, "input_digest", None)
            if digest:
                digests.add(str(digest))
            size = getattr(f, "input_size", None)
            if size is not None:
                try:
                    sizes.add(int(size))
                except (TypeError, ValueError):
                    pass

        artifact: Dict[str, Any] = {
            "location": {"uri": uri},
        }

        if digests:
            primary = sorted(digests)[0]
            # Normalise hex casing for the hash.
            artifact["hashes"] = {"sha-256": primary.lower()}

        if sizes and len(sizes) == 1:
            artifact["length"] = next(iter(sizes))

        return artifact

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def _build_results(
        self,
        findings: Sequence[ReportFinding],
        rule_index: Mapping[str, int],
        artifact_index: Mapping[str, int],
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for finding in findings:
            result = self._build_result(
                finding, rule_index, artifact_index
            )
            results.append(result)
        return results

    def _build_result(
        self,
        finding: ReportFinding,
        rule_index: Mapping[str, int],
        artifact_index: Mapping[str, int],
    ) -> Dict[str, Any]:
        rule_id = _derive_rule_id(finding)
        level = _severity_to_level(getattr(finding, "severity", None))

        message_text = self._build_message_text(finding)
        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
        }

        if rule_id in rule_index:
            result["ruleIndex"] = rule_index[rule_id]

        location = _extract_source_location(finding)
        if location is not None:
            # If the finding has an artifact URI, attach its index
            # to the physical location so that consumers can link
            # hashes to the referenced input.
            artifact_uri = _extract_artifact_uri(finding)
            if artifact_uri is not None and artifact_uri in artifact_index:
                physical = location.get("physicalLocation")
                if isinstance(physical, dict):
                    artifact_loc = physical.get("artifactLocation")
                    if isinstance(artifact_loc, dict):
                        # Only attach an index; the URI already
                        # identifies the artifact. Adding both would
                        # be redundant and can confuse strict
                        # consumers.
                        artifact_loc["index"] = artifact_index[
                            artifact_uri
                        ]
            result["locations"] = [location]

        if self._options.include_fingerprints:
            fp = _build_partial_fingerprints(finding)
            if fp:
                result["partialFingerprints"] = fp

        if self._options.include_result_properties:
            props = self._build_result_properties(finding)
            if props:
                result["properties"] = props

        return result

    @staticmethod
    def _build_message_text(finding: ReportFinding) -> str:
        """Return a non-empty message text for the result.

        SARIF requires ``message.text`` to be a non-empty string.
        The finding's title is preferred; when it is absent, a
        stable identifier-based fallback is used.
        """
        title = getattr(finding, "title", None)
        if isinstance(title, str) and title.strip():
            return title.strip()
        fid = getattr(finding, "finding_id", None)
        if fid:
            return f"Finding {fid}"
        return "Finding"

    def _build_result_properties(
        self, finding: ReportFinding
    ) -> Dict[str, Any]:
        props: Dict[str, Any] = {}

        def put(key: str, value: Any) -> None:
            if value is None:
                return
            if isinstance(value, (list, tuple, set, frozenset)):
                if not value:
                    return
                value = sorted(str(v) for v in value)
            props[key] = value

        put("findingId", getattr(finding, "finding_id", None))
        put("severity", getattr(finding, "severity", None))
        put(
            "severityLevel",
            _severity_level_name(getattr(finding, "severity", None)),
        )
        put("crashKind", getattr(finding, "crash_kind", None))
        put("classification", getattr(finding, "classification", None))
        put(
            "classificationLabel",
            getattr(finding, "classification_label", None),
        )
        put("sanitizer", getattr(finding, "sanitizer", None))
        put("inputDigest", getattr(finding, "input_digest", None))
        put("inputSize", getattr(finding, "input_size", None))
        put("inputPath", getattr(finding, "input_path", None))
        put("exitCode", getattr(finding, "exit_code", None))
        put("signalNumber", getattr(finding, "signal_number", None))
        put("signalName", getattr(finding, "signal_name", None))
        put("timedOut", getattr(finding, "timed_out", None))
        put("faultAddress", getattr(finding, "fault_address", None))
        put("accessType", getattr(finding, "access_type", None))
        put(
            "reproductionStatus",
            getattr(finding, "reproduction_status", None),
        )
        put(
            "reproductionAttempts",
            getattr(finding, "reproduction_attempts", None),
        )
        put(
            "reproductionMatched",
            getattr(finding, "reproduction_matched", None),
        )
        put(
            "regressionStatus",
            getattr(finding, "regression_status", None),
        )
        put("regressionRuns", getattr(finding, "regression_runs", None))
        put("discoveredBy", getattr(finding, "discovered_by", None))
        discovered_at = getattr(finding, "discovered_at", None)
        if isinstance(discovered_at, datetime):
            put("discoveredAt", _iso_utc(discovered_at))
        tags = getattr(finding, "tags", None)
        if tags:
            put("tags", tags)

        return props

    # ------------------------------------------------------------------
    # Run properties
    # ------------------------------------------------------------------

    def _build_run_properties(
        self, bundle: ReportBundle
    ) -> Dict[str, Any]:
        props: Dict[str, Any] = {}

        metadata = bundle.metadata
        put_list: List[Tuple[str, Any]] = [
            ("reportTitle", getattr(metadata, "title", None)),
            ("reportSubtitle", getattr(metadata, "subtitle", None)),
        ]
        for key, value in put_list:
            if value is not None:
                props[key] = value

        generated = getattr(metadata, "generated_at", None)
        if isinstance(generated, datetime):
            props["reportGeneratedAt"] = _iso_utc(generated)

        campaign = bundle.campaign
        if campaign is not None:
            for key, value in (
                ("campaignId", getattr(campaign, "campaign_id", None)),
                ("campaignName", getattr(campaign, "name", None)),
                ("campaignState", getattr(campaign, "state", None)),
                ("fuzzer", getattr(campaign, "fuzzer", None)),
                ("sanitizer", getattr(campaign, "sanitizer", None)),
                ("workers", getattr(campaign, "workers", None)),
                (
                    "totalExecutions",
                    getattr(campaign, "total_executions", None),
                ),
                (
                    "totalCrashes",
                    getattr(campaign, "total_crashes", None),
                ),
                ("totalHangs", getattr(campaign, "total_hangs", None)),
                (
                    "coveragePercent",
                    getattr(campaign, "coverage_percent", None),
                ),
                ("corpusSize", getattr(campaign, "corpus_size", None)),
            ):
                if value is not None:
                    props[key] = value

        corpus = bundle.corpus
        if corpus is not None:
            for key, value in (
                ("corpusRoot", getattr(corpus, "root", None)),
                (
                    "corpusTotalEntries",
                    getattr(corpus, "total_entries", None),
                ),
                (
                    "corpusTotalBytes",
                    getattr(corpus, "total_bytes", None),
                ),
                (
                    "corpusUniqueDigests",
                    getattr(corpus, "unique_digests", None),
                ),
            ):
                if value is not None:
                    props[key] = value

        return props

    # ------------------------------------------------------------------
    # JSON dump
    # ------------------------------------------------------------------

    def _dump(self, document: Dict[str, Any]) -> str:
        kwargs: Dict[str, Any] = {
            "ensure_ascii": False,
            "sort_keys": self._options.sort_keys,
        }
        if self._options.indent is not None:
            kwargs["indent"] = self._options.indent
        else:
            kwargs["separators"] = (",", ":")
        try:
            text = json.dumps(document, **kwargs)
        except (TypeError, ValueError) as exc:
            raise SarifSerializationError(
                f"failed to serialise SARIF document: {exc}"
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
            f"SarifReporter(include_rules={opts.include_rules}, "
            f"include_artifacts={opts.include_artifacts}, "
            f"include_invocations={opts.include_invocations})"
        )


# ---------------------------------------------------------------------------
# Fingerprint helpers
# ---------------------------------------------------------------------------


def _build_partial_fingerprints(
    finding: ReportFinding,
) -> Dict[str, str]:
    """Return the SARIF ``partialFingerprints`` object for a finding.

    The KMCS fingerprint is emitted under :data:`FINGERPRINT_KEY`.
    When the finding has no fingerprint, an empty mapping is
    returned; the caller is expected to omit the field.
    """
    fp = getattr(finding, "fingerprint", None)
    if not fp:
        return {}
    text = str(fp).strip()
    if not text:
        return {}
    return {FINGERPRINT_KEY: text}


# ---------------------------------------------------------------------------
# Datetime helper
# ---------------------------------------------------------------------------


def _iso_utc(value: datetime) -> str:
    """Return an ISO-8601 UTC string for a datetime.

    Naive datetimes are assumed to be UTC. The output always ends
    with ``Z`` so that SARIF consumers see an unambiguous UTC
    marker.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    # SARIF spec prefers the "Z" suffix over "+00:00".
    text = value.isoformat(timespec="seconds")
    if text.endswith("+00:00"):
        text = text[:-6] + "Z"
    return text


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


def render_sarif(
    bundle: ReportBundle,
    *,
    options: Optional[SarifOptions] = None,
) -> Dict[str, Any]:
    """Render ``bundle`` as a SARIF document and return it as a dict."""
    reporter = SarifReporter(options)
    return reporter.render(bundle)


def dump_sarif_string(
    bundle: ReportBundle,
    *,
    options: Optional[SarifOptions] = None,
) -> str:
    """Render ``bundle`` and return the SARIF JSON string."""
    reporter = SarifReporter(options)
    return reporter.render_string(bundle)


def dump_sarif(
    bundle: ReportBundle,
    path: Union[str, os.PathLike[str]],
    *,
    options: Optional[SarifOptions] = None,
) -> Path:
    """Render ``bundle`` and write it to ``path`` atomically."""
    reporter = SarifReporter(options)
    return reporter.write(bundle, path)


def write_sarif(
    bundle: ReportBundle,
    path: Union[str, os.PathLike[str]],
    *,
    options: Optional[SarifOptions] = None,
) -> Path:
    """Alias for :func:`dump_sarif`."""
    return dump_sarif(bundle, path, options=options)


# ---------------------------------------------------------------------------
# Mapping description
# ---------------------------------------------------------------------------


def describe_mapping() -> Dict[str, Any]:
    """Return a machine-readable description of the KMCS-to-SARIF mapping.

    Intended for tooling that previews or documents the reporter.
    """
    return {
        "sarif_version": SARIF_VERSION,
        "schema_url": SARIF_SCHEMA_URL,
        "tool_name": KMCS_TOOL_NAME,
        "rule_id_prefix": RULE_ID_PREFIX,
        "fingerprint_key": FINGERPRINT_KEY,
        "severity_mapping": dict(_LEVEL_MAP),
        "field_mapping": {
            "finding.classification": "results[].ruleId (via rule derivation)",
            "finding.crash_kind": "results[].ruleId (fallback)",
            "finding.severity": "results[].level",
            "finding.title": "results[].message.text",
            "finding.source_location": "results[].locations[0].physicalLocation",
            "finding.stack_frames[0]": (
                "results[].locations[0] (fallback when source_location is absent)"
            ),
            "finding.fingerprint": "results[].partialFingerprints[<key>]",
            "finding.input_digest": "artifacts[].hashes['sha-256']",
            "finding.input_path": "artifacts[].location.uri",
            "finding.input_size": "artifacts[].length",
            "finding.tags": "rules[].properties.tags",
            "finding.finding_id": "results[].properties.findingId",
            "finding.reproduction_*": "results[].properties.reproduction*",
            "finding.regression_*": "results[].properties.regression*",
            "campaign.target_command": "runs[0].invocations[0].commandLine",
            "campaign.started_at": "runs[0].invocations[0].startTimeUtc",
            "campaign.finished_at": "runs[0].invocations[0].endTimeUtc",
            "campaign.error_message": (
                "runs[0].invocations[0].toolExecutionNotifications"
            ),
            "metadata.campaign_id": "runs[0].automationDetails.id",
        },
        "explicitly_not_mapped": {
            "finding.raw_output": (
                "SARIF has no field for arbitrary tool output; it would "
                "be misleading to place it in message or snippet."
            ),
            "finding.exit_code": (
                "SARIF is not a process-execution format; exposed via "
                "properties instead."
            ),
            "process_outcomes": (
                "Exposed via properties; not mapped to SARIF-native "
                "fields to avoid misrepresentation."
            ),
        },
    }


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

__version__ = "1.0.0"
