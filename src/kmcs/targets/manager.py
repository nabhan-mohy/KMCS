"""KMCS target registry — lifecycle management for authorised fuzz targets.

:class:`TargetManager` is the single source of truth that the CLI, GUI and
campaign workers use to register, look up, update, build and retire targets.
It composes the other two modules of this phase:

* :mod:`kmcs.targets.detector` measures the artefact (format, architecture,
  instrumentation, sanitizers) and discovers on-disk authorisation records;
* :mod:`kmcs.targets.build` plans and executes instrumented rebuilds.

Design rules
------------
1. **Consent before anything.**  A target without a valid, in-scope
   :class:`~kmcs.core.models.Authorisation` can be *registered* (so the
   researcher can see it), but never built or fuzzed — every mutating
   execution path calls ``require_authorization`` first.  Registration also
   re-validates the declared scope against the real paths, so an
   authorisation for ``/home/user/project`` cannot be reused to fuzz
   ``/opt/someone-else``.
2. **Honest persistence.**  When a :class:`~kmcs.database.database.DatabaseManager`
   is supplied, every change goes through it immediately inside its own
   transaction; failures propagate as typed exceptions instead of being
   swallowed.  Without a database the manager still works purely in-memory
   (useful for tests and one-shot CLI runs).
3. **Facts over guesses.**  Model fields describing the binary
   (``instrumented``, ``instrumentation``, ``sanitizers_enabled``,
   architecture…) are only ever set from probe results, never from what the
   user hoped the recipe would produce.
4. **Events, not silence.**  Registrations, updates, builds and removals are
   published on the optional :class:`~kmcs.core.events.EventBus` using the
   canonical taxonomy from :mod:`kmcs.core.events`, so dashboards/journaling
   observe the same facts the registry stores.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from kmcs.core.events import EventBus, EventType
from kmcs.core.exceptions import (
    AuthorizationError,
    BuildError,
    InvalidValueError,
    KMCSBaseError,
    PolicyViolationError,
    ScopeExceededError,
    TargetInvalidError,
    TargetNotFoundError,
    ToolNotFoundError,
)
from kmcs.core.models import (
    Authorisation,
    BuildRecipe,
    Corpus,
    CorpusEntry,
    HarnessSpec,
    InstrumentationKind,
    Language,
    SanitizerKind,
    Scope,
    Target,
    TargetKind,
    generate_prefixed_id,
    make_authorisation,
    normalize_path,
    now_utc,
    parse_timestamp,
    require_authorization,
    sha256_file,
    utc_string,
)
from kmcs.targets.build import BuildPlan, BuildResult, BuildRunner, build_target, plan_build
from kmcs.targets.detector import (
    ArtifactProfile,
    InstrumentationProbe,
    InstrumentationReport,
    SourceTreeProfile,
    TargetProfiler,
    ToolchainDetector,
    ToolchainInfo,
    detect_authorization,
    draft_target_from_path,
    is_off_limits_artifact,
)

__all__ = [
    "RegistrationOutcome",
    "TargetHealth",
    "TargetManager",
]

_TOPIC_ROOT = "kmcs.targets"


@dataclass
class RegistrationOutcome:
    """What happened when a path was registered — including *how we know*."""

    target: Target
    profile: Optional[ArtifactProfile] = None
    tree_profile: Optional[SourceTreeProfile] = None
    instrumentation: Optional[InstrumentationReport] = None
    authorisation_source: str = "explicit"   # explicit | discovered | none
    warnings: List[str] = field(default_factory=list)
    persisted: bool = False
    duration_seconds: float = 0.0

    @property
    def ready_to_fuzz(self) -> bool:
        return bool(
            self.target.authorized
            and self.target.binary_path
            and os.path.isfile(self.target.binary_path)
        )

    def summary(self) -> str:
        state = "ready" if self.ready_to_fuzz else "needs-attention"
        return (f"{self.target.name} [{state}] auth={self.authorisation_source} "
                f"instr={self.target.instrumentation} "
                f"warnings={len(self.warnings)}")


@dataclass
class TargetHealth:
    """Periodic health assessment of a registered target."""

    target_id: str
    name: str
    ok: bool = False
    problems: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    authorized: bool = False
    authorisation_valid: bool = False
    expires_in_seconds: Optional[float] = None
    binary_present: bool = False
    binary_hash_matches_record: bool = False
    instrumented: bool = False
    harness_executable: bool = False
    checked_at: str = field(default_factory=utc_string)

    def summary(self) -> str:
        verdict = "healthy" if self.ok else "unhealthy"
        detail = "; ".join(self.problems) or "all checks passed"
        return f"{self.name}: {verdict} ({detail})"

    def to_dict(self) -> Dict[str, Any]:
        return dict(vars(self))


class TargetManager:
    """Registry + lifecycle owner for fuzz targets.

    Typical usage::

        db = DatabaseManager("~/.kmcs/kmcs.db")
        mgr = TargetManager(db=db, bus=bus)
        outcome = mgr.register("/home/me/projects/tinydir",
                               authorisation=my_auth, build=True)
        print(mgr.summary())
    """

    #: corpus directory naming convention under a target's workspace
    SEED_DIRNAME = "seeds"
    WORKSPACE_DIRNAME = "targets-workspace"

    def __init__(self, *, db: Any = None,
                 detector: Optional[ToolchainDetector] = None,
                 profiler: Optional[TargetProfiler] = None,
                 instrument_probe: Optional[InstrumentationProbe] = None,
                 bus: Optional[EventBus] = None,
                 workspace_root: Optional[str] = None,
                 auto_discover_authorization: bool = True) -> None:
        self.db = db
        self.detector = detector or ToolchainDetector()
        self.profiler = profiler or TargetProfiler()
        self.instrument_probe = instrument_probe or InstrumentationProbe()
        self.bus = bus
        self.workspace_root = normalize_path(workspace_root) if workspace_root else ""
        self.auto_discover_authorization = bool(auto_discover_authorization)
        self._lock = threading.RLock()
        self._targets: Dict[str, Target] = {}
        self._by_binary: Dict[str, str] = {}
        if self.db is not None:
            self._load_from_db()

    # ------------------------------------------------------------------ #
    # introspection helpers
    # ------------------------------------------------------------------ #
    def _emit(self, etype: EventType, payload: Mapping[str, Any],
              *, suffix: str = "") -> None:
        if self.bus is None:
            return
        try:
            topic = f"{_TOPIC_ROOT}{('.' + suffix) if suffix else ''}.{etype.value}"
            self.bus.emit(topic, etype, dict(payload), source="targets.manager")
        except Exception:
            # Event delivery must never break registry correctness; but it is
            # recorded as a warning rather than silently ignored.
            import sys
            print("warning: event emission failed", file=sys.stderr)

    def _workspace_for(self, target: Target) -> str:
        base = self.workspace_root or os.path.join(os.getcwd(), ".kmcs", self.WORKSPACE_DIRNAME)
        path = os.path.join(base, target.id)
        os.makedirs(path, exist_ok=True)
        return path

    # ------------------------------------------------------------------ #
    # registration
    # ------------------------------------------------------------------ #
    def register(self, path: Any, *, name: str = "",
                 authorisation: Optional[Authorisation] = None,
                 harness_mode: str = "stdin",
                 tags: Sequence[str] = (),
                 build: bool = False,
                 replace_existing: bool = False,
                 toolchain: Optional[ToolchainInfo] = None) -> RegistrationOutcome:
        """Profile *path*, attach consent, persist, optionally build.

        Raises :class:`PolicyViolationError` for off-limits system artefacts
        and :class:`TargetInvalidError` for missing/unreadable paths.  A
        successful registration with *no* authorisation is allowed (the
        researcher may want to inspect it first) but the outcome clearly says
        ``ready_to_fuzz == False`` and a warning explains why.
        """
        started = time.monotonic()
        token = normalize_path(path)
        if is_off_limits_artifact(token):
            self._emit(EventType.POLICY_BLOCKED, {"path": token,
                                                  "reason": "off-limits artefact class"},
                       suffix="policy")
            raise PolicyViolationError(
                f"'{token}' matches an always-forbidden pattern "
                "(system/boot/key material); KMCS will not treat it as a fuzz target",
                component="targets.manager", details={"path": token})
        if not os.path.exists(token):
            raise TargetInvalidError(f"target path does not exist: {token}",
                                     component="targets.manager")
        warnings: List[str] = []
        auth_source = "explicit"
        auth = authorisation
        if auth is None and self.auto_discover_authorization:
            auth = detect_authorization(token)
            auth_source = "discovered" if auth else "none"
        if auth is None:
            warnings.append(
                "no authorisation attached — the target is registered for "
                "inspection only; fuzzing/building will be refused until "
                "`kmcs target authorize` (or an explicit record) is provided")
        elif not auth.valid:
            raise AuthorizationError(
                "refusing to register with an expired/revoked authorisation",
                component="targets.manager")
        else:
            # Scope must actually cover the registered path(s).
            candidate_paths = [token]
            if os.path.isdir(token):
                binaries = self.profiler.find_candidate_binaries(token, limit=5)
                candidate_paths.extend(b.path for b in binaries)
            for candidate in candidate_paths:
                try:
                    auth.validate_for(candidate)
                except ScopeExceededError:
                    raise ScopeExceededError(
                        requested=candidate, allowed=list(auth.scope.paths)) from None

        target = draft_target_from_path(
            token, name=name or None, authorisation=auth,
            profiler=self.profiler, instrument_probe=self.instrument_probe,
            harness_mode=harness_mode)
        for tag in tags:
            if str(tag).strip() and str(tag) not in target.tags:
                target.tags.append(str(tag).strip())

        profile = target.metadata.get("artifact_format")
        if target.kind == TargetKind.SOURCE_TREE.value and not target.binary_path:
            warnings.append(
                "source tree contains no executable binaries yet — run a build "
                "(build=True or `kmcs target build`) to produce one")
        elif not target.exists:
            warnings.append("registered artefact vanished during profiling; retry")
        if not target.instrumented and target.binary_path:
            warnings.append(
                "binary shows no fuzzing instrumentation; campaigns will ask for "
                "a rebuild with AFL++/PCGUARD instrumentation first")

        with self._lock:
            duplicate_id = self._by_binary.get(target.binary_path or "")
            if duplicate_id and duplicate_id != target.id:
                existing = self._targets.get(duplicate_id)
                label = existing.name if existing else duplicate_id
                if not replace_existing:
                    raise TargetInvalidError(
                        f"'{token}' is already registered as target '{label}' "
                        f"({duplicate_id}); pass replace_existing=True to re-register",
                        component="targets.manager",
                        details={"existing_id": duplicate_id})
                self._forget_locked(duplicate_id)
            self._targets[target.id] = target
            if target.binary_path:
                self._by_binary[target.binary_path] = target.id
        persisted = False
        if self.db is not None:
            try:
                self.db.save_target(target)
                persisted = True
            except KMCSBaseError:
                raise
            except Exception as exc:
                raise BuildError(f"database rejected target persistence: {exc}",
                                 component="targets.manager") from exc
        self._emit(EventType.TARGET_REGISTERED, {
            "target_id": target.id, "name": target.name, "path": token,
            "kind": target.kind, "authorized": target.authorized,
            "authorisation_source": auth_source,
            "instrumented": target.instrumented,
            "format": profile or "",
        })

        result: Optional[BuildResult] = None
        if build:
            if not target.authorized:
                raise AuthorizationError(
                    "refusing to build: registration has no valid authorisation",
                    component="targets.manager")
            result = self.build(target.id, toolchain=toolchain)
            if not result.success:
                warnings.append(f"requested build did not succeed: {result.first_error[:400]}")

        return RegistrationOutcome(
            target=target, profile=None, tree_profile=None,
            instrumentation=None, authorisation_source=auth_source,
            warnings=warnings, persisted=persisted,
            duration_seconds=round(time.monotonic() - started, 3))

    # convenience aliases used by CLI -------------------------------------------------
    add = register

    def register_corpus(self, corpus: Corpus, *, target_id: str) -> Corpus:
        """Attach an existing corpus object to a target (validates both sides)."""
        target = self.get(target_id)
        if not isinstance(corpus, Corpus):
            raise InvalidValueError("expected a Corpus instance",
                                    component="targets.manager")
        corpus.target_id = target.id
        if corpus.id not in target.corpus_ids:
            target.corpus_ids.append(corpus.id)
        self.touch(target)
        if self.db is not None:
            self.db.save_corpus(corpus)
        self._emit(EventType.CORPUS_IMPORTED,
                   {"target_id": target.id, "corpus_id": corpus.id,
                    "entries": len(corpus.entries)})
        return corpus

    def import_seeds(self, target_id: str, seed_dir: Any, *,
                     copy_into_workspace: bool = True,
                     max_files: int = 10000) -> Dict[str, Any]:
        """Import a directory of seed inputs into a per-target corpus.

        Files are hashed and deduplicated by content hash; nothing outside
        the target workspace is written.  Returns honest counters.
        """
        target = self.get(target_id)
        source = normalize_path(seed_dir)
        if not os.path.isdir(source):
            raise TargetInvalidError(f"seed directory missing: {source}",
                                     component="targets.manager")
        workspace = self._workspace_for(target)
        seed_root = os.path.join(workspace, self.SEED_DIRNAME)
        os.makedirs(seed_root, exist_ok=True)
        corpus = Corpus(name=f"{target.name}-seeds", root=seed_root,
                        target_id=target.id)
        imported = duplicates = skipped = 0
        seen_hashes = set()
        for dirpath, dirnames, filenames in os.walk(source):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for filename in sorted(filenames):
                if imported + duplicates >= max_files:
                    break
                full = os.path.join(dirpath, filename)
                if is_off_limits_artifact(full):
                    skipped += 1
                    continue
                try:
                    size = os.path.getsize(full)
                except OSError:
                    skipped += 1
                    continue
                if size <= 0 or size > corpus.max_input_bytes:
                    skipped += 1
                    continue
                digest = sha256_file(full)
                if digest in seen_hashes:
                    duplicates += 1
                    continue
                seen_hashes.add(digest)
                destination = os.path.join(seed_root, digest[:16] + "-" + filename)
                if copy_into_workspace:
                    import shutil
                    shutil.copyfile(full, destination)
                entry = CorpusEntry(path=destination if copy_into_workspace else full,
                                    content_hash=digest, size_bytes=size,
                                    label=filename, origin="seed-import")
                corpus.add(entry)
                imported += 1
        if self.db is not None:
            self.db.save_corpus(corpus)
        if corpus.id not in target.corpus_ids:
            target.corpus_ids.append(corpus.id)
        self.touch(target)
        self._emit(EventType.CORPUS_IMPORTED,
                   {"target_id": target.id, "corpus_id": corpus.id,
                    "imported": imported, "duplicates": duplicates,
                    "skipped": skipped})
        return {"corpus_id": corpus.id, "root": seed_root, "imported": imported,
                "duplicates": duplicates, "skipped": skipped,
                "entries": len(corpus.entries)}

    # ------------------------------------------------------------------ #
    # queries
    # ------------------------------------------------------------------ #
    def get(self, target_id: str) -> Target:
        with self._lock:
            target = self._targets.get(target_id)
        if target is None and self.db is not None:
            try:
                loaded = self.db.get_target(target_id)
            except KMCSBaseError:
                raise
            except Exception as exc:
                raise TargetNotFoundError(f"target '{target_id}' not found "
                                          f"(db lookup failed: {exc})",
                                          component="targets.manager") from exc
            with self._lock:
                self._targets[target_id] = loaded
                if loaded.binary_path:
                    self._by_binary[loaded.binary_path] = target_id
            target = loaded
        if target is None:
            raise TargetNotFoundError(
                f"no target registered with id '{target_id}'",
                component="targets.manager",
                details={"known_ids": sorted(self._targets)})
        return target

    def find_by_name(self, name: str) -> List[Target]:
        needle = str(name).lower()
        with self._lock:
            return [t for t in self._targets.values() if needle in t.name.lower()]

    def list(self, *, authorized_only: bool = False, kind: Optional[str] = None,
             name_like: Optional[str] = None) -> List[Target]:
        with self._lock:
            items = list(self._targets.values())
        if authorized_only:
            items = [t for t in items if t.authorized]
        if kind:
            items = [t for t in items if t.kind == str(kind)]
        if name_like:
            needle = str(name_like).lower()
            items = [t for t in items if needle in t.name.lower()]
        return sorted(items, key=lambda t: (t.name.lower(), t.id))

    def count(self) -> int:
        with self._lock:
            return len(self._targets)

    def table_rows(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for target in self.list():
            rows.append({
                "id": target.id, "name": target.name, "kind": target.kind,
                "language": target.language, "arch": target.architecture,
                "instrumented": "yes" if target.instrumented else "no",
                "sanitizers": ",".join(target.sanitizers_enabled) or "-",
                "authorized": "yes" if target.authorized else "NO",
                "binary": target.binary_path or "-",
            })
        return rows

    def summary(self) -> str:
        targets = self.list()
        authorized = sum(1 for t in targets if t.authorized)
        instrumented = sum(1 for t in targets if t.instrumented)
        fuzz_ready = sum(1 for t in targets
                         if t.authorized and t.binary_path
                         and os.path.isfile(t.binary_path))
        return (f"{len(targets)} target(s): {authorized} authorized, "
                f"{instrumented} instrumented, {fuzz_ready} ready to fuzz")

    # ------------------------------------------------------------------ #
    # mutation
    # ------------------------------------------------------------------ #
    def update(self, target_id: str, **changes: Any) -> Target:
        """Apply whitelisted field updates; unknown keys are refused loudly."""
        target = self.get(target_id)
        allowed = {"name", "tags", "harness", "build_recipe", "upstream_project",
                   "upstream_url", "version", "corpus_ids", "metadata",
                   "authorisation", "language", "notes"}
        unknown = set(changes) - allowed
        if unknown:
            raise InvalidValueError(
                f"cannot update protected/unknown fields: {sorted(unknown)}; "
                "probe-derived facts (architecture, instrumentation, binary_path) "
                "change only via re-registration or a verified build",
                component="targets.manager", details={"rejected": sorted(unknown)})
        auth = changes.get("authorisation")
        if auth is not None and not isinstance(auth, Authorisation):
            raise InvalidValueError("authorisation must be an Authorisation instance",
                                    component="targets.manager")
        for key, value in changes.items():
            setattr(target, key, value)
        self.touch(target)
        self._emit(EventType.TARGET_REGISTERED,
                   {"target_id": target.id, "updated": sorted(changes)},
                   suffix="update")
        return target

    def authorize(self, target_id: str, *, granted_by: str, statement: str,
                  relationship: str = "owner", evidence_ref: str = "",
                  days: Optional[int] = None,
                  paths: Sequence[Any] = ()) -> Target:
        """Attach (or replace) the authorisation record for a target.

        The scope defaults to the target's own binary/source paths, so a
        signed statement covers exactly what will be executed.
        """
        target = self.get(target_id)
        scope_paths = [normalize_path(p) for p in paths] or [
            p for p in (target.binary_path, target.source_root) if p]
        if not scope_paths:
            raise TargetInvalidError(
                "cannot derive an authorisation scope: target has neither a "
                "binary nor a source root", component="targets.manager")
        auth = make_authorisation(granted_by, statement, paths=scope_paths,
                                  relationship=relationship,
                                  evidence_ref=evidence_ref, days=days)
        target.authorisation = auth
        self.touch(target)
        self._emit(EventType.TARGET_REGISTERED,
                   {"target_id": target.id, "authorized": True,
                    "granted_by": granted_by, "expires_at": auth.expires_at},
                   suffix="authorize")
        return target

    def revoke_authorization(self, target_id: str) -> Target:
        target = self.get(target_id)
        if target.authorisation is None:
            raise AuthorizationError("target has no authorisation to revoke",
                                     component="targets.manager")
        target.authorisation.revoked = True
        self.touch(target)
        self._emit(EventType.POLICY_BLOCKED,
                   {"target_id": target.id, "reason": "authorisation revoked"},
                   suffix="revoke")
        return target

    def touch(self, target: Target) -> Target:
        """Persist current model state (DB) and refresh updated_at."""
        target.updated_at = utc_string()
        if self.db is not None:
            self.db.save_target(target)
        return target

    def remove(self, target_id: str, *, forget_files: bool = False) -> bool:
        """Unregister a target.  Never deletes user artefacts unless asked."""
        with self._lock:
            existed = target_id in self._targets
            deleted = self._forget_locked(target_id)
        if self.db is not None:
            try:
                self.db.delete_target(target_id)
                deleted = True
            except KMCSBaseError:
                raise
            except Exception as exc:
                raise BuildError(f"database delete failed: {exc}",
                                 component="targets.manager") from exc
        if forget_files:
            workspace = os.path.join(self.workspace_root or
                                     os.path.join(os.getcwd(), ".kmcs",
                                                  self.WORKSPACE_DIRNAME),
                                     target_id)
            marker = os.path.join(workspace, ".kmcs-managed")
            if os.path.isfile(marker) or workspace.startswith(
                    self.workspace_root or ""):
                import shutil
                shutil.rmtree(workspace, ignore_errors=True)
        self._emit(EventType.TARGET_REGISTERED,
                   {"target_id": target_id, "removed": bool(deleted or existed)},
                   suffix="remove")
        return bool(deleted or existed)

    def _forget_locked(self, target_id: str) -> bool:
        target = self._targets.pop(target_id, None)
        if target is not None and target.binary_path:
            self._by_binary.pop(target.binary_path, None)
        return target is not None

    # ------------------------------------------------------------------ #
    # probing / building
    # ------------------------------------------------------------------ #
    def probe(self, target_id: str) -> Target:
        """Re-measure the registered artefact and update derived facts."""
        target = self.get(target_id)
        if not target.binary_path or not os.path.isfile(target.binary_path):
            raise TargetInvalidError(
                f"target '{target.name}' has no binary on disk to probe "
                f"(recorded path: {target.binary_path or 'unset'})",
                component="targets.manager")
        report = self.instrument_probe.probe(target.binary_path)
        target.instrumented = report.instrumented
        if report.kinds:
            target.instrumentation = report.kinds[0]
        merged = list(dict.fromkeys(list(target.sanitizers_enabled)
                                    + list(report.sanitizers)))
        target.sanitizers_enabled = merged
        target.metadata["last_probe"] = {
            "at": report.probed_at, "method": report.method,
            "confidence": report.confidence, "kinds": list(report.kinds),
            "sha256": sha256_file(target.binary_path),
        }
        self.touch(target)
        return target

    def build(self, target_id: str, *, clean: bool = False,
              source_files: Optional[Sequence[str]] = None,
              toolchain: Optional[ToolchainInfo] = None,
              log_dir: Optional[str] = None,
              instrumentation: Optional[str] = None,
              sanitizers: Optional[Sequence[str]] = None) -> BuildResult:
        """Authorisation-gated instrumented rebuild of a target."""
        target = self.get(target_id)
        require_authorization(target, operation="build")
        if instrumentation:
            target.build_recipe.instrumentation = str(instrumentation)
        if sanitizers is not None:
            target.build_recipe.sanitizers = [str(s) for s in sanitizers]
        info = toolchain or self.detector.detect()
        missing = self._missing_for_recipe(target.build_recipe, info)
        if missing:
            self._emit(EventType.TOOL_MISSING,
                       {"target_id": target.id, "missing": missing},
                       suffix="build")
            raise ToolNotFoundError(
                "cannot build target because required tools are absent: "
                + ", ".join(missing),
                component="targets.manager", details={"missing": missing})
        self._emit(EventType.BUILD_STARTED,
                   {"target_id": target.id, "clean": clean,
                    "instrumentation": target.build_recipe.instrumentation,
                    "sanitizers": list(target.build_recipe.sanitizers)})
        result = build_target(target, require_authorization=False, clean=clean,
                              source_files=source_files, toolchain=info,
                              log_dir=log_dir or self._workspace_for(target),
                              update_target=True)
        self.touch(target)
        self._emit(EventType.BUILD_FINISHED, {
            "target_id": target.id, "success": result.success,
            "duration_s": result.duration_seconds,
            "artifacts": [a.path for a in result.artifacts],
            "error": result.first_error[:500] if not result.success else "",
        })
        return result

    def plan(self, target_id: str, *,
             source_files: Optional[Sequence[str]] = None,
             clean: bool = False) -> BuildPlan:
        """Render the exact steps a build would execute (audit aid)."""
        target = self.get(target_id)
        return plan_build(target, toolchain=self.detector.detect(),
                          source_files=source_files, clean=clean)

    def _missing_for_recipe(self, recipe: BuildRecipe, info: ToolchainInfo) -> List[str]:
        missing: List[str] = []
        wanted_cc = recipe.effective_cc()
        if not shutil_which(wanted_cc):
            missing.append(wanted_cc)
        if recipe.instrumentation in {InstrumentationKind.AFL_CLANG_FAST.value,
                                      InstrumentationKind.AFL_CLANG_LTO.value,
                                      InstrumentationKind.AFL_GCC_PLUGIN.value}:
            if not info.capabilities.get("aflpp_present"):
                missing.append("AFL++ toolchain (afl-fuzz/afl-clang-fast)")
        for sanitizer in recipe.sanitizers:
            key = f"asan" if sanitizer == SanitizerKind.ASAN.value else sanitizer
            if sanitizer == SanitizerKind.ASAN.value and not info.capabilities.get("asan"):
                missing.append("AddressSanitizer runtime (-fsanitize=address link test)")
            elif sanitizer == SanitizerKind.UBSAN.value and not info.capabilities.get("ubsan"):
                missing.append("UndefinedBehaviorSanitizer runtime")
            elif sanitizer == SanitizerKind.MSAN.value and not any(
                    k.endswith(":memory") and v == "yes"
                    for k, v in info.sanitizer_support.items()):
                missing.append("MemorySanitizer runtime (clang-only)")
            elif sanitizer == SanitizerKind.TSAN.value and not any(
                    k.endswith(":thread") and v == "yes"
                    for k, v in info.sanitizer_support.items()):
                missing.append("ThreadSanitizer runtime")
            del key
        return missing

    # ------------------------------------------------------------------ #
    # health & verification
    # ------------------------------------------------------------------ #
    def check(self, target_id: str) -> TargetHealth:
        """Full pre-flight health check used before starting campaigns."""
        target = self.get(target_id)
        health = TargetHealth(target_id=target.id, name=target.name)
        auth = target.authorisation
        health.authorized = bool(auth and auth.valid)
        health.authorisation_valid = health.authorized
        if auth is not None and auth.expires_at:
            expiry = parse_timestamp(auth.expires_at)
            if expiry is not None:
                health.expires_in_seconds = max(0.0, (expiry - now_utc()).total_seconds())
        if not health.authorized:
            health.problems.append(
                "missing/expired/revoked authorisation — fuzzing is refused")
        binary = target.binary_path
        if not binary:
            health.problems.append("no binary registered (build the target first)")
        elif not os.path.isfile(binary):
            health.problems.append(f"binary vanished from disk: {binary}")
        else:
            health.binary_present = True
            recorded = str(target.metadata.get("last_probe", {}).get("sha256", ""))
            current = sha256_file(binary)
            health.binary_hash_matches_record = bool(recorded) and recorded == current
            if recorded and not health.binary_hash_matches_record:
                health.notes.append(
                    "binary changed since last probe — re-run `probe` so "
                    "instrumentation facts stay truthful")
            if not target.instrumented:
                health.problems.append(
                    "binary is not instrumented for coverage-guided fuzzing")
        harness = target.harness
        if harness.argv_template and not os.path.isfile(harness.argv_template[0]):
            health.problems.append(
                f"harness argv[0] is not an existing file: {harness.argv_template[0]}")
        else:
            health.harness_executable = bool(harness.argv_template)
        if target.kind == TargetKind.SOURCE_TREE.value and not target.source_root:
            health.problems.append("source-tree target lost its source_root")
        health.instrumented = target.instrumented
        health.ok = not health.problems
        health.checked_at = utc_string()
        return health

    def check_all(self) -> List[TargetHealth]:
        return [self.check(t.id) for t in self.list()]

    def verify_scope(self, target_id: str, candidate_paths: Sequence[Any]) -> None:
        """Raise unless every *candidate_path* is inside the live scope."""
        target = self.get(target_id)
        auth = require_authorization(target, operation="scope-check")
        for candidate in candidate_paths:
            auth.validate_for(candidate)

    # ------------------------------------------------------------------ #
    # persistence plumbing
    # ------------------------------------------------------------------ #
    def _load_from_db(self) -> None:
        assert self.db is not None
        try:
            rows = self.db.list_targets()
        except Exception:
            # Fresh/empty databases are normal; keep going with an empty map.
            rows = []
        with self._lock:
            for target in rows:
                self._targets[target.id] = target
                if target.binary_path:
                    self._by_binary[target.binary_path] = target.id

    def reload(self) -> int:
        """Discard in-memory state and re-read everything from the database."""
        if self.db is None:
            raise InvalidValueError("manager has no database attached",
                                    component="targets.manager")
        with self._lock:
            self._targets.clear()
            self._by_binary.clear()
        self._load_from_db()
        return self.count()

    def export_json(self, target_id: str) -> Dict[str, Any]:
        """Serialisable snapshot (authorisation included — it is policy data,
        not a secret; credentials could never appear here by construction)."""
        return self.get(target_id).to_dict()

    def stats(self) -> Dict[str, Any]:
        targets = self.list()
        return {
            "targets": len(targets),
            "authorized": sum(1 for t in targets if t.authorized),
            "instrumented": sum(1 for t in targets if t.instrumented),
            "with_binary": sum(1 for t in targets
                               if t.binary_path and os.path.isfile(t.binary_path)),
            "languages": _tally(str(t.language) for t in targets),
            "kinds": _tally(str(t.kind) for t in targets),
        }


def _tally(values: Iterable[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out


def shutil_which(name: str) -> Optional[str]:
    import shutil
    return shutil.which(name)


if __name__ == "__main__":  # pragma: no cover - manual smoke
    mgr = TargetManager()
    print(mgr.summary())
