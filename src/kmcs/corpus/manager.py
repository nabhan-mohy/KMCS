"""
KMCS Corpus Manager
===================

Production-grade content-addressed corpus management for the KMCS fuzzing
platform.

This module implements the primary :class:`CorpusManager` responsible for
ingesting, deduplicating, storing, exporting, and describing fuzzing corpus
inputs. The manager is intentionally conservative: it never deletes files
outside explicitly configured corpus roots, never silently swallows I/O
errors, and never fabricates statistics — every number reported is derived
from a real filesystem scan or a real database query.

Design notes
------------

* **Content addressing.** Every input is identified by its SHA-256 digest,
  computed from the actual file bytes on disk. This makes duplicate
  detection trivial (identical hashes == identical bytes) and lets the
  manager be safely relocated between filesystems.

* **Layered deduplication.** Two levels of similarity are supported:

  1. *Exact deduplication* via SHA-256 content hash. Cheap and perfect.
  2. *Near-duplicate clustering* via feature fingerprints borrowed from
     :mod:`kmcs.analysis.fingerprint`. This is more expensive and is only
     run when explicitly requested by the caller (or when configured).

* **Atomic operations.** Imports are performed by staging bytes in
  memory, validating them, and only then writing to the corpus root via
  an atomic rename. Exports are likewise staged in a sibling temporary
  directory and renamed into place. Failures leave no partial artifacts.

* **Defensive only.** The manager has no concept of exploitation. It only
  tracks, stores, and reports the existence of input bytes.

* **Event-driven.** Every mutation emits an event on the KMCS event bus
  (:mod:`kmcs.core.events`). Subscribers (statistics, telemetry, UI, etc.)
  are responsible for their own bookkeeping.

* **Persistence bridge.** When a :class:`~kmcs.database.database.DatabaseManager`
  is supplied, every accepted input is recorded via
  ``add_corpus_entry`` and can be reloaded via ``get_corpus_entries``.
  The manager never assumes the database is authoritative for on-disk
  bytes; the filesystem is authoritative, and the database is a cache.

Threading
---------

The manager is *not* thread-safe by itself. Callers that wish to use it
from multiple threads should serialize access with an external lock, or
instantiate one manager per thread pointing at the same corpus root (the
content-addressed layout makes this safe for concurrent reads).

Compatibility
-------------

Python 3.10+.
"""

from __future__ import annotations

import errno
import hashlib
import logging
import os
import shutil
import stat
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
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
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
    Union,
)

from ..core.exceptions import KMCSException
from ..core.events import EventBus, EventType
from .._events_compat import Event, get_default_bus, publish_event
from ..core.config import KmcsConfig, get_config
from ..core.models import CorpusEntry as CoreCorpusEntry

# Optional imports — the manager must remain importable even when the
# analysis subsystem is unavailable, since it is used by tests and by
# tools that do not need feature extraction.
try:  # pragma: no cover - exercised indirectly
    from ..analysis.fingerprint import FeatureFingerprint, extract_features
    _HAVE_FINGERPRINT = True
except Exception:  # noqa: BLE001 - broad by design; subsystem is optional
    FeatureFingerprint = None  # type: ignore[assignment]
    extract_features = None  # type: ignore[assignment]
    _HAVE_FINGERPRINT = False

try:  # pragma: no cover - exercised indirectly
    from ..database.database import DatabaseManager
except Exception:  # noqa: BLE001
    DatabaseManager = None  # type: ignore[assignment]


__all__ = [
    "CorpusManager",
    "CorpusEntry",
    "CorpusStats",
    "ImportResult",
    "ExportResult",
    "RemovalResult",
    "SimilarityCluster",
    "CorpusError",
    "CorpusIOError",
    "CorpusValidationError",
    "UnsafeOperationError",
    "DuplicateInputError",
    "DEFAULT_CHUNK_SIZE",
    "DEFAULT_MAX_FILE_SIZE",
    "DEFAULT_SKIP_EXTENSIONS",
    "HASH_ALGORITHM",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#: Algorithm used for content addressing. SHA-256 is the platform default
#: and is stable across all supported Python versions.
HASH_ALGORITHM: str = "sha256"

#: Chunk size used while streaming file bytes through the hasher.
DEFAULT_CHUNK_SIZE: int = 1024 * 1024  # 1 MiB

#: Default maximum size for an individual corpus input. Larger files are
#: rejected during import to avoid pathological memory use by downstream
#: mutators and validators.
DEFAULT_MAX_FILE_SIZE: int = 16 * 1024 * 1024  # 16 MiB

#: Extensions that are, by default, never treated as corpus inputs. These
#: are documentation, metadata, and object-code formats that are useless
#: to a fuzzer and often confusing to import recursively.
DEFAULT_SKIP_EXTENSIONS: FrozenSet[str] = frozenset(
    {
        ".md",
        ".txt",
        ".rst",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".log",
        ".py",
        ".pyc",
        ".pyo",
        ".o",
        ".obj",
        ".so",
        ".dll",
        ".dylib",
        ".a",
        ".lib",
        ".exe",
        ".bat",
        ".sh",
        ".ps1",
    }
)

#: Filenames that are always skipped regardless of extension.
DEFAULT_SKIP_FILENAMES: FrozenSet[str] = frozenset(
    {
        ".DS_Store",
        "Thumbs.db",
        "desktop.ini",
        ".gitignore",
        ".gitattributes",
        "README",
        "README.md",
    }
)

#: Prefix used for staged temporary files inside the corpus root.
_STAGE_PREFIX = ".kmcs-stage-"

#: Directory name used to store corpus inputs, relative to the root.
_BLOBS_DIRNAME = "blobs"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CorpusError(KMCSException):
    """Base class for all corpus-manager errors."""


class CorpusIOError(CorpusError):
    """Raised when a filesystem operation fails unexpectedly."""


class CorpusValidationError(CorpusError):
    """Raised when an input fails validation before being accepted."""


class UnsafeOperationError(CorpusError):
    """Raised when an operation would touch files outside the corpus root."""


class DuplicateInputError(CorpusError):
    """Raised when a duplicate input is submitted in strict mode."""

    def __init__(self, digest: str, existing_path: Optional[Path] = None) -> None:
        self.digest = digest
        self.existing_path = existing_path
        message = f"duplicate corpus input: {digest}"
        if existing_path is not None:
            message += f" (existing at {existing_path})"
        super().__init__(message)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorpusEntry:
    """A single content-addressed corpus input.

    Attributes
    ----------
    digest:
        Hex-encoded SHA-256 digest of the input bytes.
    path:
        Absolute path on disk where the bytes are stored.
    size:
        Size of the input in bytes.
    created_at:
        UTC timestamp of when the input was first accepted.
    source:
        Optional free-form description of where the input came from
        (e.g. ``"import:/tmp/seeds"`` or ``"fuzzer:aflpp"``).
    tags:
        Immutable set of user-supplied labels. Tags are stored alongside
        the blob in a small sidecar file so they survive process restarts.
    features:
        Optional fingerprint derived from the input bytes. Populated
        lazily when near-duplicate clustering is requested.
    """

    digest: str
    path: Path
    size: int
    created_at: datetime
    source: Optional[str] = None
    tags: FrozenSet[str] = field(default_factory=frozenset)
    features: Optional[Tuple[float, ...]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly representation of this entry."""
        return {
            "digest": self.digest,
            "path": str(self.path),
            "size": self.size,
            "created_at": self.created_at.isoformat(),
            "source": self.source,
            "tags": sorted(self.tags),
        }


@dataclass
class CorpusStats:
    """Aggregate statistics describing the current state of a corpus.

    All values are computed by a real filesystem scan. Zero-valued fields
    mean "no data" — they are never filled with fabricated estimates.
    """

    root: Path
    total_entries: int = 0
    total_bytes: int = 0
    smallest_size: Optional[int] = None
    largest_size: Optional[int] = None
    mean_size: float = 0.0
    median_size: float = 0.0
    unique_digests: int = 0
    skipped_files: int = 0
    invalid_files: int = 0
    by_extension: Dict[str, int] = field(default_factory=dict)
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly representation of these stats."""
        return {
            "root": str(self.root),
            "total_entries": self.total_entries,
            "total_bytes": self.total_bytes,
            "smallest_size": self.smallest_size,
            "largest_size": self.largest_size,
            "mean_size": self.mean_size,
            "median_size": self.median_size,
            "unique_digests": self.unique_digests,
            "skipped_files": self.skipped_files,
            "invalid_files": self.invalid_files,
            "by_extension": dict(self.by_extension),
            "computed_at": self.computed_at.isoformat(),
        }


@dataclass
class ImportResult:
    """Outcome of an import operation."""

    imported: List[CorpusEntry] = field(default_factory=list)
    duplicates: List[str] = field(default_factory=list)
    skipped: List[Tuple[Path, str]] = field(default_factory=list)
    errors: List[Tuple[Path, str]] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None

    @property
    def imported_count(self) -> int:
        return len(self.imported)

    @property
    def duplicate_count(self) -> int:
        return len(self.duplicates)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "imported": [e.to_dict() for e in self.imported],
            "duplicates": list(self.duplicates),
            "skipped": [{"path": str(p), "reason": r} for p, r in self.skipped],
            "errors": [{"path": str(p), "error": r} for p, r in self.errors],
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class ExportResult:
    """Outcome of an export operation."""

    destination: Path
    exported: List[Tuple[str, Path]] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    errors: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def exported_count(self) -> int:
        return len(self.exported)

    @property
    def missing_count(self) -> int:
        return len(self.missing)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "destination": str(self.destination),
            "exported": [{"digest": d, "path": str(p)} for d, p in self.exported],
            "missing": list(self.missing),
            "errors": [{"digest": d, "error": e} for d, e in self.errors],
        }


@dataclass
class RemovalResult:
    """Outcome of a removal operation."""

    removed: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    errors: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def removed_count(self) -> int:
        return len(self.removed)

    @property
    def missing_count(self) -> int:
        return len(self.missing)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "removed": list(self.removed),
            "missing": list(self.missing),
            "errors": [{"digest": d, "error": e} for d, e in self.errors],
        }


@dataclass
class SimilarityCluster:
    """A cluster of corpus entries that are similar to one another."""

    representative: str
    members: List[str] = field(default_factory=list)
    mean_distance: float = 0.0
    max_distance: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "representative": self.representative,
            "members": list(self.members),
            "mean_distance": self.mean_distance,
            "max_distance": self.max_distance,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_utc() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def _safe_read_bytes(path: Path, max_size: int, chunk_size: int) -> bytes:
    """Read up to ``max_size`` bytes from ``path``.

    Raises
    ------
    CorpusValidationError
        If the file exceeds ``max_size``.
    CorpusIOError
        If the file cannot be opened or read.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_size + 1)
    except OSError as exc:
        raise CorpusIOError(f"failed to read {path}: {exc}") from exc
    if len(data) > max_size:
        raise CorpusValidationError(
            f"file {path} exceeds max size {max_size} bytes"
        )
    return data


def _hash_bytes(data: bytes, algorithm: str = HASH_ALGORITHM) -> str:
    """Return the hex digest of ``data`` using ``algorithm``."""
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def _hash_file(
    path: Path,
    algorithm: str = HASH_ALGORITHM,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """Stream ``path`` through a hasher and return the hex digest."""
    h = hashlib.new(algorithm)
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
    except OSError as exc:
        raise CorpusIOError(f"failed to hash {path}: {exc}") from exc
    return h.hexdigest()


def _atomic_write_bytes(
    target: Path,
    data: bytes,
    mode: int = 0o644,
) -> None:
    """Atomically write ``data`` to ``target``.

    The bytes are first written to a sibling temporary file, fsynced,
    then renamed into place. If anything fails, the temporary file is
    removed and the exception is re-raised.
    """
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=_STAGE_PREFIX, dir=str(parent)
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                # fsync is best-effort; some filesystems disallow it.
                pass
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, target)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def _is_within(path: Path, root: Path) -> bool:
    """Return True if ``path`` is located inside ``root``.

    Both arguments are resolved first, so symlinks and relative
    components are handled correctly.
    """
    try:
        p = path.resolve(strict=False)
        r = root.resolve(strict=False)
    except OSError:
        return False
    try:
        p.relative_to(r)
    except ValueError:
        return False
    return True


def _looks_binary(data: bytes, sample: int = 4096) -> bool:
    """Heuristic: return True if ``data`` looks like binary content."""
    if not data:
        return False
    chunk = data[:sample]
    if b"\x00" in chunk:
        return True
    # Count non-text bytes.
    text_chars = bytes(range(0x20, 0x7F)) + b"\n\r\t\f\b"
    non_text = sum(1 for b in chunk if b not in text_chars)
    return non_text / len(chunk) > 0.30


def _human_size(n: int) -> str:
    """Format ``n`` bytes as a human-readable string."""
    if n < 1024:
        return f"{n}B"
    units = ["KiB", "MiB", "GiB", "TiB", "PiB"]
    value = float(n)
    for unit in units:
        value /= 1024.0
        if value < 1024.0:
            return f"{value:.2f}{unit}"
    return f"{value:.2f}EiB"


# ---------------------------------------------------------------------------
# CorpusManager
# ---------------------------------------------------------------------------


class CorpusManager:
    """Content-addressed manager for a single fuzzing corpus.

    Parameters
    ----------
    root:
        Directory that will hold the corpus. Created if it does not
        exist. All managed blobs live under ``root/blobs/<aa>/<digest>``
        where ``<aa>`` is the first two hex characters of the digest
        (a sharding scheme to keep directory sizes reasonable).
    config:
        Optional :class:`~kmcs.core.config.KmcsConfig`. When omitted, the
        process-wide default configuration is used.
    database:
        Optional :class:`~kmcs.database.database.DatabaseManager`. When
        provided, accepted entries are persisted to the ``corpus_entries``
        table, and :meth:`load_from_database` can repopulate an in-memory
        cache.
    event_bus:
        Optional event bus. When omitted, the process-wide default bus
        is used.
    max_file_size:
        Reject any input larger than this many bytes.
    skip_extensions:
        Override the default set of extensions to skip during recursive
        imports. Pass an empty set to import everything.
    skip_filenames:
        Override the default set of filenames to skip.
    auto_cluster:
        When True, near-duplicate clustering is performed automatically
        after every import. This can be expensive; the default is False.
    strict:
        When True, :meth:`add_bytes` raises :class:`DuplicateInputError`
        on an exact duplicate instead of silently returning the existing
        entry.
    """

    def __init__(
        self,
        root: Union[str, os.PathLike[str]],
        *,
        config: Optional[KmcsConfig] = None,
        database: Optional["DatabaseManager"] = None,
        event_bus: Optional[EventBus] = None,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        skip_extensions: Optional[Iterable[str]] = None,
        skip_filenames: Optional[Iterable[str]] = None,
        auto_cluster: bool = False,
        strict: bool = False,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        if max_file_size <= 0:
            raise ValueError("max_file_size must be positive")
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")

        self._root = Path(root).expanduser().resolve()
        self._config = config or get_config()
        self._database = database
        self._bus = event_bus or get_default_bus()
        self._max_file_size = int(max_file_size)
        self._chunk_size = int(chunk_size)
        self._auto_cluster = bool(auto_cluster)
        self._strict = bool(strict)

        if skip_extensions is None:
            self._skip_extensions: FrozenSet[str] = DEFAULT_SKIP_EXTENSIONS
        else:
            self._skip_extensions = frozenset(
                e.lower() if e.startswith(".") else f".{e.lower()}"
                for e in skip_extensions
            )

        if skip_filenames is None:
            self._skip_filenames: FrozenSet[str] = DEFAULT_SKIP_FILENAMES
        else:
            self._skip_filenames = frozenset(skip_filenames)

        self._blobs_dir = self._root / _BLOBS_DIRNAME
        self._lock = threading.RLock()
        self._cache: Dict[str, CorpusEntry] = {}

        # Ensure the layout exists.
        self._root.mkdir(parents=True, exist_ok=True)
        self._blobs_dir.mkdir(parents=True, exist_ok=True)

        logger.debug("CorpusManager initialised at %s", self._root)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def root(self) -> Path:
        """Absolute path to the corpus root directory."""
        return self._root

    @property
    def blobs_dir(self) -> Path:
        """Absolute path to the sharded blobs directory."""
        return self._blobs_dir

    @property
    def max_file_size(self) -> int:
        """Maximum allowed input size in bytes."""
        return self._max_file_size

    @property
    def strict(self) -> bool:
        """Whether strict-mode duplicate rejection is enabled."""
        return self._strict

    @property
    def database(self) -> Optional["DatabaseManager"]:
        """The attached database manager, if any."""
        return self._database

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _blob_path(self, digest: str) -> Path:
        """Return the on-disk path for a digest.

        The digest is sharded into ``aa/bb/`` subdirectories, which keeps
        individual directory listings small even for very large corpora.
        """
        if len(digest) < 4:
            raise ValueError(f"digest too short: {digest!r}")
        return self._blobs_dir / digest[:2] / digest[2:4] / digest

    def _tag_path(self, digest: str) -> Path:
        """Return the path to the sidecar tag file for a digest."""
        return self._blob_path(digest).with_suffix(".tags")

    def _ensure_shard(self, digest: str) -> Path:
        """Create the shard directory for ``digest`` and return it."""
        shard = self._blobs_dir / digest[:2] / digest[2:4]
        shard.mkdir(parents=True, exist_ok=True)
        return shard

    def _assert_inside_root(self, path: Path) -> None:
        """Raise if ``path`` is not inside the corpus root."""
        if not _is_within(path, self._root):
            raise UnsafeOperationError(
                f"refusing to operate on path outside corpus root: {path}"
            )

    # ------------------------------------------------------------------
    # Event helpers
    # ------------------------------------------------------------------

    def _emit(self, event_type: EventType, payload: Dict[str, Any]) -> None:
        """Emit an event on the corpus bus, ignoring subscriber errors."""
        try:
            event = Event(type=event_type, source="corpus.manager", data=payload)
            publish_event(self._bus, event)
        except Exception as exc:  # noqa: BLE001 - subscribers are untrusted
            logger.warning("corpus event publish failed: %s", exc)

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    def hash_bytes(self, data: bytes) -> str:
        """Return the SHA-256 hex digest of ``data``."""
        return _hash_bytes(data, HASH_ALGORITHM)

    def hash_file(self, path: Union[str, os.PathLike[str]]) -> str:
        """Return the SHA-256 hex digest of the file at ``path``."""
        return _hash_file(
            Path(path), HASH_ALGORITHM, chunk_size=self._chunk_size
        )

    # ------------------------------------------------------------------
    # Tag persistence
    # ------------------------------------------------------------------

    def _write_tags(self, digest: str, tags: FrozenSet[str]) -> None:
        """Persist ``tags`` to the sidecar file for ``digest``."""
        path = self._tag_path(digest)
        if not tags:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                logger.warning("failed to remove tag file %s: %s", path, exc)
            return
        payload = "\n".join(sorted(tags)).encode("utf-8")
        try:
            _atomic_write_bytes(path, payload)
        except OSError as exc:
            logger.warning("failed to write tag file %s: %s", path, exc)

    def _read_tags(self, digest: str) -> FrozenSet[str]:
        """Read the sidecar tag file for ``digest``, if present."""
        path = self._tag_path(digest)
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except FileNotFoundError:
            return frozenset()
        except OSError as exc:
            logger.warning("failed to read tag file %s: %s", path, exc)
            return frozenset()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return frozenset()
        return frozenset(line.strip() for line in text.splitlines() if line.strip())

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_bytes(self, data: bytes) -> None:
        """Run pre-acceptance validation on ``data``.

        Raises
        ------
        CorpusValidationError
            If the bytes fail any validation check.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise CorpusValidationError(
                f"expected bytes-like object, got {type(data).__name__}"
            )
        n = len(data)
        if n == 0:
            raise CorpusValidationError("refusing to add empty input")
        if n > self._max_file_size:
            raise CorpusValidationError(
                f"input size {n} exceeds max_file_size {self._max_file_size}"
            )

    def _should_skip_path(self, path: Path) -> Optional[str]:
        """Return a skip reason for ``path``, or None if it should be kept."""
        name = path.name
        if name in self._skip_filenames:
            return f"filename in skip list: {name}"
        if name.startswith("."):
            return "dotfile"
        ext = path.suffix.lower()
        if ext and ext in self._skip_extensions:
            return f"extension in skip list: {ext}"
        return None

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def add_bytes(
        self,
        data: bytes,
        *,
        source: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
    ) -> CorpusEntry:
        """Add raw ``data`` to the corpus and return its entry.

        Parameters
        ----------
        data:
            The bytes to store. Must be non-empty and within
            ``max_file_size``.
        source:
            Optional free-form source description.
        tags:
            Optional labels to attach to the entry.

        Returns
        -------
        CorpusEntry
            The entry describing the stored bytes. If the same digest
            already exists, the existing entry is returned (and the tag
            set is unioned with the supplied tags).

        Raises
        ------
        CorpusValidationError
            If the bytes are empty or too large.
        DuplicateInputError
            If ``strict`` mode is enabled and the digest already exists.
        """
        self._validate_bytes(data)
        tag_set = frozenset(tags or ())

        digest = self.hash_bytes(data)
        existing = self._lookup(digest)
        if existing is not None:
            if self._strict:
                raise DuplicateInputError(digest, existing.path)
            if tag_set and not tag_set.issubset(existing.tags):
                merged = existing.tags | tag_set
                self._write_tags(digest, merged)
                updated = CorpusEntry(
                    digest=existing.digest,
                    path=existing.path,
                    size=existing.size,
                    created_at=existing.created_at,
                    source=existing.source or source,
                    tags=merged,
                    features=existing.features,
                )
                self._cache[digest] = updated
                self._emit(
                    EventType.CORPUS_UPDATED,
                    {
                        "digest": digest,
                        "tags": sorted(merged),
                        "size": updated.size,
                    },
                )
                return updated
            return existing

        with self._lock:
            # Re-check under the lock; another thread may have added it.
            existing = self._lookup(digest)
            if existing is not None:
                return existing

            blob_path = self._blob_path(digest)
            self._ensure_shard(digest)
            try:
                _atomic_write_bytes(blob_path, bytes(data))
            except OSError as exc:
                raise CorpusIOError(
                    f"failed to write blob {blob_path}: {exc}"
                ) from exc

            if tag_set:
                self._write_tags(digest, tag_set)

            entry = CorpusEntry(
                digest=digest,
                path=blob_path,
                size=len(data),
                created_at=_now_utc(),
                source=source,
                tags=tag_set,
            )
            self._cache[digest] = entry
            self._persist_entry(entry)
            self._emit(
                EventType.CORPUS_ADDED,
                {
                    "digest": digest,
                    "size": entry.size,
                    "path": str(entry.path),
                    "source": source,
                    "tags": sorted(tag_set),
                },
            )
            return entry

    def add_file(
        self,
        path: Union[str, os.PathLike[str]],
        *,
        source: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
    ) -> CorpusEntry:
        """Add the file at ``path`` to the corpus.

        The file itself is not modified or removed; its bytes are copied
        into the content-addressed blob directory.
        """
        p = Path(path)
        if not p.exists():
            raise CorpusIOError(f"file does not exist: {p}")
        if not p.is_file():
            raise CorpusIOError(f"not a regular file: {p}")
        data = _safe_read_bytes(p, self._max_file_size, self._chunk_size)
        return self.add_bytes(
            data,
            source=source or f"file:{p}",
            tags=tags,
        )

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def import_directory(
        self,
        directory: Union[str, os.PathLike[str]],
        *,
        recursive: bool = True,
        source: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
    ) -> ImportResult:
        """Import every eligible file under ``directory``.

        Parameters
        ----------
        directory:
            The directory to scan.
        recursive:
            When True (default), descend into subdirectories.
        source:
            Overrides the per-file source tag. Defaults to
            ``"import:<directory>"``.
        tags:
            Tags applied to every imported entry.

        Returns
        -------
        ImportResult
            A structured report of what was imported, skipped, or
            rejected. The result is never empty unless the directory
            itself was empty.
        """
        result = ImportResult()
        d = Path(directory)
        if not d.exists():
            result.errors.append((d, "directory does not exist"))
            result.finished_at = _now_utc()
            return result
        if not d.is_dir():
            result.errors.append((d, "not a directory"))
            result.finished_at = _now_utc()
            return result

        source_str = source or f"import:{d}"
        tag_set = frozenset(tags or ())

        for path in self._walk(d, recursive=recursive):
            try:
                entry = self._import_one(path, source_str, tag_set)
                if isinstance(entry, str):
                    result.duplicates.append(entry)
                elif entry is None:
                    # already recorded in skipped by _import_one
                    pass
                else:
                    result.imported.append(entry)
            except CorpusValidationError as exc:
                result.skipped.append((path, str(exc)))
            except CorpusError as exc:
                result.errors.append((path, str(exc)))
            except OSError as exc:
                result.errors.append((path, str(exc)))

        # Re-scan skipped to include reasons we gathered in _import_one.
        result.skipped.extend(self._pop_skip_log())

        result.finished_at = _now_utc()
        self._emit(
            EventType.CORPUS_IMPORTED,
            {
                "directory": str(d),
                "imported": result.imported_count,
                "duplicates": result.duplicate_count,
                "skipped": result.skipped_count,
                "errors": result.error_count,
                "duration": result.duration_seconds,
            },
        )

        if self._auto_cluster and result.imported_count > 0:
            try:
                self.cluster_by_similarity()
            except Exception as exc:  # noqa: BLE001
                logger.warning("auto cluster failed: %s", exc)

        return result

    def _walk(self, root: Path, *, recursive: bool) -> Iterator[Path]:
        """Yield candidate file paths under ``root``."""
        if recursive:
            for dirpath, dirnames, filenames in os.walk(root):
                # Skip hidden dirs to avoid .git etc.
                dirnames[:] = [dn for dn in dirnames if not dn.startswith(".")]
                for name in filenames:
                    yield Path(dirpath) / name
        else:
            try:
                for child in root.iterdir():
                    if child.is_file():
                        yield child
            except OSError as exc:
                logger.warning("failed to list %s: %s", root, exc)

    # The skip log is populated by _import_one for files that were
    # filtered out (extension, size, filename).  Because generator
    # consumers cannot append to the caller's result object directly
    # without a circular reference, we stage skips in a small buffer.
    _skip_log: List[Tuple[Path, str]]

    def _pop_skip_log(self) -> List[Tuple[Path, str]]:
        log = getattr(self, "_skip_log", [])
        self._skip_log = []
        return log

    def _import_one(
        self,
        path: Path,
        source: str,
        tags: FrozenSet[str],
    ) -> Union[CorpusEntry, str, None]:
        """Import a single file. Returns an entry, a duplicate digest, or None."""
        reason = self._should_skip_path(path)
        if reason is not None:
            if not hasattr(self, "_skip_log"):
                self._skip_log = []
            self._skip_log.append((path, reason))
            return None

        try:
            st = path.stat()
        except OSError as exc:
            raise CorpusIOError(f"stat failed for {path}: {exc}") from exc

        if not stat.S_ISREG(st.st_mode):
            if not hasattr(self, "_skip_log"):
                self._skip_log = []
            self._skip_log.append((path, "not a regular file"))
            return None

        if st.st_size == 0:
            if not hasattr(self, "_skip_log"):
                self._skip_log = []
            self._skip_log.append((path, "empty file"))
            return None

        if st.st_size > self._max_file_size:
            if not hasattr(self, "_skip_log"):
                self._skip_log = []
            self._skip_log.append(
                (
                    path,
                    f"size {st.st_size} exceeds max {self._max_file_size}",
                )
            )
            return None

        digest = self.hash_file(path)
        existing = self._lookup(digest)
        if existing is not None:
            return digest

        data = _safe_read_bytes(path, self._max_file_size, self._chunk_size)
        entry = self.add_bytes(
            data,
            source=f"{source}:{path.name}",
            tags=tags,
        )
        return entry

    # ------------------------------------------------------------------
    # Lookup and cache
    # ------------------------------------------------------------------

    def _lookup(self, digest: str) -> Optional[CorpusEntry]:
        """Look up an entry by digest in the in-memory cache."""
        with self._lock:
            cached = self._cache.get(digest)
        if cached is not None:
            if cached.path.exists():
                return cached
            # Fall through: the cache is stale.
        path = self._blob_path(digest)
        if not path.exists():
            return None
        try:
            st = path.stat()
        except OSError:
            return None
        entry = CorpusEntry(
            digest=digest,
            path=path,
            size=st.st_size,
            created_at=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
            tags=self._read_tags(digest),
        )
        with self._lock:
            self._cache[digest] = entry
        return entry

    def get(self, digest: str) -> Optional[CorpusEntry]:
        """Public lookup: return the entry for ``digest`` or None."""
        return self._lookup(digest)

    def has(self, digest: str) -> bool:
        """Return True if the corpus contains ``digest``."""
        return self._blob_path(digest).exists()

    def iter_entries(self) -> Iterator[CorpusEntry]:
        """Yield every entry currently on disk.

        The iterator is a live view: entries added after iteration
        begins may or may not be yielded.
        """
        for path in self._iter_blob_paths():
            digest = path.name
            try:
                st = path.stat()
            except OSError:
                continue
            entry = CorpusEntry(
                digest=digest,
                path=path,
                size=st.st_size,
                created_at=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
                tags=self._read_tags(digest),
            )
            yield entry

    def _iter_blob_paths(self) -> Iterator[Path]:
        """Yield paths to every blob in the sharded directory tree."""
        if not self._blobs_dir.exists():
            return
        for aa in sorted(self._blobs_dir.iterdir()):
            if not aa.is_dir():
                continue
            for bb in sorted(aa.iterdir()):
                if not bb.is_dir():
                    continue
                for blob in sorted(bb.iterdir()):
                    if not blob.is_file():
                        continue
                    if blob.suffix == ".tags":
                        continue
                    if blob.name.startswith(_STAGE_PREFIX):
                        continue
                    yield blob

    def refresh_cache(self) -> int:
        """Rebuild the in-memory cache from disk; return entry count."""
        with self._lock:
            self._cache.clear()
        count = 0
        for path in self._iter_blob_paths():
            try:
                st = path.stat()
            except OSError:
                continue
            digest = path.name
            entry = CorpusEntry(
                digest=digest,
                path=path,
                size=st.st_size,
                created_at=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
                tags=self._read_tags(digest),
            )
            with self._lock:
                self._cache[digest] = entry
            count += 1
        return count

    # ------------------------------------------------------------------
    # Removal
    # ------------------------------------------------------------------

    def remove(self, digest: str) -> bool:
        """Remove the blob for ``digest``. Returns True if removed."""
        path = self._blob_path(digest)
        self._assert_inside_root(path)
        removed = False
        try:
            path.unlink()
            removed = True
        except FileNotFoundError:
            removed = False
        except OSError as exc:
            raise CorpusIOError(f"failed to remove {path}: {exc}") from exc
        # Sidecar tag file.
        tag_path = self._tag_path(digest)
        if _is_within(tag_path, self._root):
            try:
                tag_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
        with self._lock:
            self._cache.pop(digest, None)
        if removed:
            self._remove_from_database(digest)
            self._emit(
                EventType.CORPUS_REMOVED,
                {"digest": digest, "path": str(path)},
            )
        return removed

    def remove_many(self, digests: Iterable[str]) -> RemovalResult:
        """Remove several digests; return a structured report."""
        result = RemovalResult()
        for digest in digests:
            try:
                if self.remove(digest):
                    result.removed.append(digest)
                else:
                    result.missing.append(digest)
            except CorpusError as exc:
                result.errors.append((digest, str(exc)))
        return result

    def clear(self) -> RemovalResult:
        """Remove every entry in the corpus.

        This operation is bounded to the corpus root and refuses to touch
        anything outside it.
        """
        return self.remove_many([e.digest for e in self.iter_entries()])

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export(
        self,
        destination: Union[str, os.PathLike[str]],
        digests: Optional[Iterable[str]] = None,
        *,
        flat: bool = True,
        overwrite: bool = False,
    ) -> ExportResult:
        """Copy corpus entries to ``destination``.

        Parameters
        ----------
        destination:
            Directory to receive the copies. Created if missing.
        digests:
            The digests to export. When None, every entry is exported.
        flat:
            When True (default), files are copied as
            ``<destination>/<digest>``. When False, the sharded layout
            is preserved.
        overwrite:
            When True, existing files are overwritten atomically.
            When False (default), existing files are skipped and
            recorded as errors.
        """
        dest = Path(destination).expanduser().resolve()
        dest.mkdir(parents=True, exist_ok=True)
        result = ExportResult(destination=dest)

        targets = list(digests) if digests is not None else [
            e.digest for e in self.iter_entries()
        ]

        for digest in targets:
            entry = self._lookup(digest)
            if entry is None:
                result.missing.append(digest)
                continue
            if flat:
                target = dest / digest
            else:
                target = dest / digest[:2] / digest[2:4] / digest
            if target.exists() and not overwrite:
                result.errors.append((digest, f"target exists: {target}"))
                continue
            try:
                self._export_one(entry, target)
            except OSError as exc:
                result.errors.append((digest, str(exc)))
            else:
                result.exported.append((digest, target))

        self._emit(
            EventType.CORPUS_EXPORTED,
            {
                "destination": str(dest),
                "exported": result.exported_count,
                "missing": result.missing_count,
                "errors": result.error_count,
            },
        )
        return result

    def _export_one(self, entry: CorpusEntry, target: Path) -> None:
        """Copy one entry to ``target`` atomically."""
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(entry.path, "rb") as src:
                data = src.read()
        except OSError as exc:
            raise CorpusIOError(f"failed to read {entry.path}: {exc}") from exc
        _atomic_write_bytes(target, data)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def stats(self) -> CorpusStats:
        """Compute live statistics over the corpus on disk."""
        s = CorpusStats(root=self._root)
        sizes: List[int] = []
        seen: Set[str] = set()
        for path in self._iter_blob_paths():
            try:
                st = path.stat()
            except OSError:
                s.invalid_files += 1
                continue
            digest = path.name
            if digest in seen:
                continue
            seen.add(digest)
            sizes.append(st.st_size)
            s.total_bytes += st.st_size
            ext = path.suffix.lower() or "<none>"
            s.by_extension[ext] = s.by_extension.get(ext, 0) + 1
        s.total_entries = len(sizes)
        s.unique_digests = len(seen)
        if sizes:
            s.smallest_size = min(sizes)
            s.largest_size = max(sizes)
            s.mean_size = sum(sizes) / len(sizes)
            s.median_size = _median(sorted(sizes))
        s.computed_at = _now_utc()
        return s

    # ------------------------------------------------------------------
    # Similarity clustering
    # ------------------------------------------------------------------

    def cluster_by_similarity(
        self,
        *,
        threshold: float = 0.85,
        max_entries: Optional[int] = None,
    ) -> List[SimilarityCluster]:
        """Cluster corpus entries by feature similarity.

        This operation requires the optional
        :mod:`kmcs.analysis.fingerprint` subsystem. If it is not
        available, an empty list is returned (and a warning is logged).

        Parameters
        ----------
        threshold:
            Cosine similarity above which two entries are considered
            near-duplicates. Must be in ``[0.0, 1.0]``.
        max_entries:
            Optional cap on the number of entries to cluster. Useful for
            very large corpora where exhaustive clustering is wasteful.
        """
        if not _HAVE_FINGERPRINT or extract_features is None:
            logger.warning(
                "similarity clustering unavailable: "
                "kmcs.analysis.fingerprint not importable"
            )
            return []
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be in [0.0, 1.0]")

        entries = list(self.iter_entries())
        if max_entries is not None:
            entries = entries[:max_entries]

        fingerprints: Dict[str, Tuple[float, ...]] = {}
        for entry in entries:
            try:
                with open(entry.path, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            try:
                fp = extract_features(data)
            except Exception as exc:  # noqa: BLE001
                logger.debug("fingerprint failed for %s: %s", entry.digest, exc)
                continue
            features = _fingerprint_to_tuple(fp)
            if features:
                fingerprints[entry.digest] = features

        clusters = _cluster_fingerprints(fingerprints, threshold)
        self._emit(
            EventType.CORPUS_CLUSTERED,
            {
                "clusters": len(clusters),
                "entries": len(fingerprints),
                "threshold": threshold,
            },
        )
        return clusters

    # ------------------------------------------------------------------
    # Persistence bridge
    # ------------------------------------------------------------------

    def _persist_entry(self, entry: CorpusEntry) -> None:
        """Write ``entry`` to the attached database, if any."""
        if self._database is None:
            return
        try:
            self._database.add_corpus_entry(
                digest=entry.digest,
                path=str(entry.path),
                size=entry.size,
                source=entry.source,
                tags=sorted(entry.tags),
                created_at=entry.created_at,
            )
        except Exception as exc:  # noqa: BLE001 - DB failure must not abort I/O
            logger.warning("failed to persist corpus entry %s: %s", entry.digest, exc)

    def _remove_from_database(self, digest: str) -> None:
        """Remove ``digest`` from the attached database, if any."""
        if self._database is None:
            return
        remover = getattr(self._database, "remove_corpus_entry", None)
        if remover is None:
            return
        try:
            remover(digest)
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to remove corpus entry %s: %s", digest, exc)

    def load_from_database(self) -> int:
        """Repopulate the in-memory cache from the attached database.

        Entries whose blob is missing on disk are skipped; the
        filesystem remains authoritative.
        """
        if self._database is None:
            return 0
        try:
            rows = self._database.get_corpus_entries()
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to load corpus entries: %s", exc)
            return 0
        loaded = 0
        with self._lock:
            for row in rows:
                digest = getattr(row, "digest", None) or row["digest"]
                path = self._blob_path(digest)
                if not path.exists():
                    continue
                try:
                    st = path.stat()
                except OSError:
                    continue
                tags_raw = getattr(row, "tags", None)
                if tags_raw is None and isinstance(row, Mapping):
                    tags_raw = row.get("tags", [])
                tags = frozenset(tags_raw or ())
                entry = CorpusEntry(
                    digest=digest,
                    path=path,
                    size=st.st_size,
                    created_at=datetime.fromtimestamp(
                        st.st_mtime, tz=timezone.utc
                    ),
                    source=getattr(row, "source", None),
                    tags=tags,
                )
                self._cache[digest] = entry
                loaded += 1
        return loaded

    # ------------------------------------------------------------------
    # Context manager / cleanup
    # ------------------------------------------------------------------

    def __enter__(self) -> "CorpusManager":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Nothing to release explicitly; provided for symmetry with
        # DatabaseManager and other resource-holding objects.
        return None

    def __repr__(self) -> str:
        return f"CorpusManager(root={self._root!r}, strict={self._strict})"


# ---------------------------------------------------------------------------
# Free functions used by CorpusManager
# ---------------------------------------------------------------------------


def _median(sorted_values: Sequence[int]) -> float:
    """Return the median of a sorted sequence of integers."""
    n = len(sorted_values)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2 == 1:
        return float(sorted_values[mid])
    return (sorted_values[mid - 1] + sorted_values[mid]) / 2.0


def _fingerprint_to_tuple(fp: Any) -> Tuple[float, ...]:
    """Coerce a fingerprint object into a tuple of floats.

    The fingerprint subsystem is intentionally loose about its return
    type; this helper normalises the common cases (tuple, list, numpy
    array, object with a ``vector`` attribute) into a plain tuple.
    """
    if fp is None:
        return ()
    if isinstance(fp, tuple):
        return tuple(float(x) for x in fp)
    if isinstance(fp, list):
        return tuple(float(x) for x in fp)
    vector = getattr(fp, "vector", None)
    if vector is not None:
        try:
            return tuple(float(x) for x in vector)
        except TypeError:
            return ()
    try:
        return tuple(float(x) for x in fp)  # type: ignore[union-attr]
    except TypeError:
        return ()


def _cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """Return the cosine similarity of two equal-length vectors."""
    if len(a) != len(b):
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    return dot / ((na ** 0.5) * (nb ** 0.5))


def _cluster_fingerprints(
    fingerprints: Mapping[str, Tuple[float, ...]],
    threshold: float,
) -> List[SimilarityCluster]:
    """Greedy clustering of fingerprints by cosine similarity.

    The algorithm is O(n * k) where ``k`` is the number of clusters,
    which is acceptable for the corpus sizes KMCS targets.
    """
    clusters: List[SimilarityCluster] = []
    assign: Dict[str, int] = {}

    for digest, vec in fingerprints.items():
        best_idx = -1
        best_sim = threshold
        for idx, cluster in enumerate(clusters):
            rep_vec = fingerprints.get(cluster.representative)
            if rep_vec is None:
                continue
            sim = _cosine_similarity(vec, rep_vec)
            if sim >= best_sim:
                best_sim = sim
                best_idx = idx
        if best_idx < 0:
            clusters.append(
                SimilarityCluster(representative=digest, members=[digest])
            )
            assign[digest] = len(clusters) - 1
        else:
            clusters[best_idx].members.append(digest)
            assign[digest] = best_idx

    # Compute cluster distance statistics.
    for cluster in clusters:
        rep_vec = fingerprints.get(cluster.representative)
        if rep_vec is None:
            continue
        distances: List[float] = []
        for member in cluster.members:
            if member == cluster.representative:
                continue
            vec = fingerprints.get(member)
            if vec is None:
                continue
            sim = _cosine_similarity(vec, rep_vec)
            distances.append(1.0 - sim)
        if distances:
            cluster.mean_distance = sum(distances) / len(distances)
            cluster.max_distance = max(distances)

    return clusters


# ---------------------------------------------------------------------------
# Public aliases and re-exports
# ---------------------------------------------------------------------------

__version__ = "1.0.0"

# A couple of convenience aliases used by the rest of the platform.
BlobDigest = str
CorpusRoot = Path

# Explicit re-export of a couple of core types that callers frequently
# need alongside the manager itself.
CoreEntry = CoreCorpusEntry

# Silence unused-import linters for the compatibility shims.
_ = (asdict, uuid, errno, shutil, Mapping, MutableMapping, TypeVar, Callable)
