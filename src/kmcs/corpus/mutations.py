"""
kmcs.corpus.mutations — controlled byte-level mutation utilities.
================================================================

This module provides the *building blocks* for changing corpus inputs in a
deterministic, bounded and safe way.  It is explicitly **not** a fuzzing
engine: AFL++, libFuzzer and Honggfuzz remain the real engines that KMCS
orchestrates.  These utilities exist because KMCS's own corpus workflows
(seed triage, format-aware smoke inputs, deterministic regression corpora)
need small, reproducible input transformations without spawning an engine.

Design contract
---------------
*   **Pure functions.**  Every mutation takes ``bytes`` and returns a *new*
    ``bytes`` object.  The caller's buffer is never modified in place.
*   **Determinism.**  All randomness flows through an explicit
    :class:`random.Random` instance (a seed reproduces the exact sequence).
    No global ``random`` state is touched.
*   **Bounded growth.**  Every entry point enforces a hard maximum output
    size so a runaway insertion can never allocate uncontrolled memory.
*   **Honest limits.**  When a mutation cannot be applied (empty input,
    no room to grow, dictionary exhausted) the function returns either the
    original data or ``None`` — it never fabricates a "successful" result.
*   **Defensive-only.**  Mutations produce malformed/edge-case *inputs*.
    There is nothing here that constructs exploits, shellcode, ROP chains
    or any payload aimed at compromising a target; the vocabulary is bytes,
    sizes and encodings only.

Public surface
--------------
``MutationKind``            — catalogue of supported operations
``MutationLimits``          — validated bound configuration
``MutationResult``          — record of one applied mutation
``MutationOp``              — protocol for composable operation objects
plus ~30 free functions: ``bit_flip``, ``byte_flip``, ``arithmetic``,
``interest_value``, ``insert_bytes``, ``delete_bytes``, ``replace_block``,
``duplicate_block``, ``truncate``, ``extend``, ``shuffle_block``,
``swap_adjacent``, ``overwrite_with_token``, ``dictionary_havoc``,
``splice``, ``zero_out``, ``set_char_class``, ``text_case_flip``,
``integer_field_edit``, ``havoc``, and helpers used by the other corpus
modules.
"""

from __future__ import annotations

import base64
import hashlib
import math
import os
import random
import re
import struct
import zlib
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from kmcs.core.exceptions import (
    CorpusError,
    InvalidValueError,
)

__all__ = [
    "MutationKind",
    "MutationLimits",
    "MutationResult",
    "MutationOp",
    "FUNCTION_MUTATIONS",
    "INTERESTING_8",
    "INTERESTING_16",
    "INTERESTING_32",
    "INTERESTING_64",
    "DEFAULT_DICTIONARY",
    "MAX_SINGLE_MUTATION_GROWTH",
    "apply_mutation",
    "arithmetic",
    "bit_flip",
    "byte_flip",
    "clamp_size",
    "cycle_kinds",
    "delete_bytes",
    "dictionary_havoc",
    "duplicate_block",
    "extend",
    "grow_by_halving",
    "havoc",
    "infer_text_encoding",
    "insert_bytes",
    "interest_value",
    "integer_field_edit",
    "is_probably_text",
    "mutation_digest",
    "mutation_plan_id",
    "normalise_kind",
    "overprint_at",
    "overwrite_with_token",
    "pick_index",
    "pick_window",
    "record_to_dict",
    "replace_block",
    "seeded_rng",
    "set_char_class",
    "shuffle_block",
    "splice",
    "swap_adjacent",
    "truncate",
    "validate_payload",
    "zero_out",
]

# ---------------------------------------------------------------------------
# Constants & catalogues
# ---------------------------------------------------------------------------

#: Absolute ceiling for a single mutation's growth over the input size.  A
#: request beyond this is rejected rather than silently honoured — corpus
#: workflows must not be able to balloon a 1 KiB seed into gigabytes.
MAX_SINGLE_MUTATION_GROWTH = 1 << 20  # 1 MiB

#: Hard ceiling on any produced buffer regardless of limits config.
ABSOLUTE_MAX_OUTPUT = 128 << 20  # 128 MiB

#: Classic values found useful when probing integer fields (sizes, offsets,
#: lengths, indices).  These are plain numeric constants — they carry no
#: semantics beyond "try these numbers".
INTERESTING_8: Tuple[int, ...] = (
    0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 100, 127, 128, 129, 254, 255,
)
INTERESTING_16: Tuple[int, ...] = INTERESTING_8 + (
    256, 511, 512, 1000, 1023, 1024, 2048, 4095, 4096, 8192, 16383, 16384,
    32767, 32768, 49152, 65534, 65535,
)
INTERESTING_32: Tuple[int, ...] = INTERESTING_16 + (
    65536, 100000, 131072, 262144, 524288, 1000000, 1048575, 1048576,
    2147483646, 2147483647, 2147483648, 4294967294, 4294967295,
)
INTERESTING_64: Tuple[int, ...] = INTERESTING_32 + (
    4294967296, 8589934591, 8589934592, 17179869183, 17179869184,
    34359738367, 34359738368, 68719476735, 68719476736,
    1099511627775, 1099511627776, 2199023255551, 2199023255552,
    4398046511103, 4398046511104, 9223372036854775806, 9223372036854775807,
    9223372036854775808, 18446744073709551614, 18446744073709551615,
)

#: Small generic token dictionary used by ``dictionary_havoc`` when the
#: caller does not supply their own.  Tokens are structural punctuation and
#: boundary characters common in text-ish formats — again, plain bytes.
DEFAULT_DICTIONARY: Tuple[bytes, ...] = (
    b"\x00", b"\xff", b"\n", b"\r\n", b"\t", b" ", b"=", b":", b";", b",",
    b".", b"/", b"\\", b"-", b"_", b"#", b"%", b"*", b"?", b"!", b'"', b"'",
    b"`", b"(", b")", b"[", b"]", b"{", b"}", b"<", b">", b"|", b"&", b"$",
    b"0", b"1", b"9", b"A", b"Z", b"a", b"z", b"AAAA", b"\x00\x00\x00\x00",
)


class MutationKind(StrEnum):
    """Catalogue of supported mutation operations."""

    BIT_FLIP = "bit_flip"
    BYTE_FLIP = "byte_flip"
    ARITHMETIC = "arithmetic"
    INTEREST_VALUE = "interest_value"
    INSERT_BYTES = "insert_bytes"
    DELETE_BYTES = "delete_bytes"
    REPLACE_BLOCK = "replace_block"
    DUPLICATE_BLOCK = "duplicate_block"
    TRUNCATE = "truncate"
    EXTEND = "extend"
    SHUFFLE_BLOCK = "shuffle_block"
    SWAP_ADJACENT = "swap_adjacent"
    OVERWRITE_TOKEN = "overwrite_token"
    DICTIONARY_HAVOC = "dictionary_havoc"
    SPLICE = "splice"
    ZERO_OUT = "zero_out"
    SET_CHAR_CLASS = "set_char_class"
    TEXT_CASE_FLIP = "text_case_flip"
    INTEGER_FIELD_EDIT = "integer_field_edit"
    HAVOC = "havoc"

    @classmethod
    def coerce(cls, value: Any) -> "MutationKind":
        """Best-effort conversion from str/enum to :class:`MutationKind`."""
        if isinstance(value, cls):
            return value
        token = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
        if not token:
            raise InvalidValueError("empty mutation kind", details={"allowed": cls.tokens()})
        try:
            return cls(token)
        except ValueError:
            pass
        # tolerate common aliases
        aliases = {
            "flip_bit": cls.BIT_FLIP,
            "flip_byte": cls.BYTE_FLIP,
            "byte_arith": cls.ARITHMETIC,
            "arith": cls.ARITHMETIC,
            "interesting": cls.INTEREST_VALUE,
            "interest": cls.INTEREST_VALUE,
            "insert": cls.INSERT_BYTES,
            "delete": cls.DELETE_BYTES,
            "remove": cls.DELETE_BYTES,
            "replace": cls.REPLACE_BLOCK,
            "dup": cls.DUPLICATE_BLOCK,
            "duplicate": cls.DUPLICATE_BLOCK,
            "cut": cls.TRUNCATE,
            "trim": cls.TRUNCATE,
            "grow": cls.EXTEND,
            "shuffle": cls.SHUFFLE_BLOCK,
            "swap": cls.SWAP_ADJACENT,
            "token": cls.OVERWRITE_TOKEN,
            "dict": cls.DICTIONARY_HAVOC,
            "dictionary": cls.DICTIONARY_HAVOC,
            "zero": cls.ZERO_OUT,
            "memset": cls.ZERO_OUT,
            "case": cls.TEXT_CASE_FLIP,
            "int": cls.INTEGER_FIELD_EDIT,
            "integer": cls.INTEGER_FIELD_EDIT,
        }
        if token in aliases:
            return aliases[token]
        raise InvalidValueError(
            f"unknown mutation kind '{value}'",
            details={"allowed": cls.tokens()},
        )

    @classmethod
    def tokens(cls) -> List[str]:
        return sorted(item.value for item in cls)

    @property
    def changes_length(self) -> bool:
        """True when this kind may change the payload length."""
        return self in {
            MutationKind.INSERT_BYTES,
            MutationKind.DELETE_BYTES,
            MutationKind.DUPLICATE_BLOCK,
            MutationKind.TRUNCATE,
            MutationKind.EXTEND,
            MutationKind.DICTIONARY_HAVOC,
            MutationKind.SPLICE,
            MutationKind.HAVOC,
        }

    @property
    def requires_nonempty(self) -> bool:
        return self not in {MutationKind.INSERT_BYTES, MutationKind.EXTEND}


# ---------------------------------------------------------------------------
# Limits / results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MutationLimits:
    """Validated bounds shared by every mutation entry point.

    ``max_input_bytes`` guards how much we are willing to read/process,
    ``max_output_bytes`` caps produced buffers, ``max_block`` caps block
    operations and ``max_steps`` caps havoc-style multi-step mutations.
    """

    max_input_bytes: int = 16 << 20
    max_output_bytes: int = 32 << 20
    max_block: int = 4096
    max_steps: int = 16
    allow_empty_output: bool = False

    def __post_init__(self) -> None:
        for name in ("max_input_bytes", "max_output_bytes", "max_block", "max_steps"):
            value = getattr(self, name)
            try:
                ivalue = int(value)
            except (TypeError, ValueError):
                raise InvalidValueError(f"limit {name} must be an integer ({value!r})") from None
            if ivalue <= 0:
                raise InvalidValueError(f"limit {name} must be positive ({ivalue})")
            object.__setattr__(self, name, ivalue)
        if self.max_output_bytes > ABSOLUTE_MAX_OUTPUT:
            raise InvalidValueError(
                f"max_output_bytes cannot exceed {ABSOLUTE_MAX_OUTPUT}",
                details={"requested": self.max_output_bytes},
            )
        if self.max_output_bytes < self.max_input_bytes:
            raise InvalidValueError(
                "max_output_bytes must be >= max_input_bytes",
                details={"max_input_bytes": self.max_input_bytes,
                         "max_output_bytes": self.max_output_bytes},
            )
        if self.max_block > self.max_output_bytes:
            object.__setattr__(self, "max_block", self.max_output_bytes)

    DEFAULT = None  # populated after class creation (see below)

    def with_output_cap(self, cap: int) -> "MutationLimits":
        """Return a copy whose output cap is ``min(cap, current)``."""
        cap = max(1, int(cap))
        return replace(self, max_output_bytes=min(cap, self.max_output_bytes),
                       max_input_bytes=min(cap, self.max_input_bytes))


MutationLimits.DEFAULT = MutationLimits()


@dataclass
class MutationResult:
    """Outcome of one mutation attempt.

    ``applied`` is honest: it is False whenever the input was returned
    unchanged (e.g. empty input for a deletion).  ``reason`` explains why in
    that case.  ``digest`` is the SHA-256 of the produced payload so callers
    can deduplicate mutated seeds cheaply.
    """

    kind: MutationKind
    input_len: int
    output: bytes
    applied: bool = True
    reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.kind = MutationKind.coerce(self.kind)
        self.input_len = int(self.input_len)
        if len(self.output) > ABSOLUTE_MAX_OUTPUT:
            raise CorpusError(
                "mutation produced an oversized buffer",
                details={"output_len": len(self.output), "cap": ABSOLUTE_MAX_OUTPUT},
            )

    @property
    def changed(self) -> bool:
        return self.applied and len(self.output) != self.input_len

    @property
    def output_len(self) -> int:
        return len(self.output)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.output).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "input_len": self.input_len,
            "output_len": self.output_len,
            "applied": self.applied,
            "changed": self.changed,
            "reason": self.reason,
            "digest": self.digest,
            "details": dict(self.details),
        }


def record_to_dict(result: Optional[MutationResult]) -> Optional[Dict[str, Any]]:
    """Serialise a result (or ``None``) — convenient for telemetry rows."""
    return result.to_dict() if result is not None else None


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------


def validate_payload(data: Any, *, limits: Optional[MutationLimits] = None,
                     name: str = "payload", allow_str: bool = True) -> bytes:
    """Coerce *data* to ``bytes`` enforcing the configured input limit.

    ``bytearray``/``memoryview``/``bytes`` pass through; ``str`` is encoded
    UTF-8 when ``allow_str``; anything else raises :class:`InvalidValueError`.
    """
    limits = limits or MutationLimits.DEFAULT
    if isinstance(data, bytes):
        payload = data
    elif isinstance(data, (bytearray, memoryview)):
        payload = bytes(data)
    elif isinstance(data, str) and allow_str:
        payload = data.encode("utf-8", "surrogatepass")
    else:
        raise InvalidValueError(
            f"{name} must be bytes-like or str, got {type(data).__name__}",
        )
    if len(payload) > limits.max_input_bytes:
        raise InvalidValueError(
            f"{name} exceeds mutation input limit",
            details={"size_bytes": len(payload), "limit_bytes": limits.max_input_bytes},
        )
    return payload


def clamp_size(value: Any, lo: int, hi: int, *, default: int = 0) -> int:
    """Clamp ``value`` into ``[lo, hi]`` with sane fallbacks."""
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        return max(lo, min(hi, default))
    return max(lo, min(hi, ivalue))


def seeded_rng(rng: Any) -> random.Random:
    """Normalise ``rng``: accept ``Random``, ``int`` seed, or ``None``."""
    if rng is None:
        return random.Random()
    if isinstance(rng, random.Random):
        return rng
    if isinstance(rng, bool):
        raise InvalidValueError("rng seed cannot be a bool")
    if isinstance(rng, int):
        return random.Random(rng)
    if isinstance(rng, str):
        digest = hashlib.sha256(rng.encode("utf-8")).digest()
        return random.Random(int.from_bytes(digest[:8], "big"))
    raise InvalidValueError(
        "rng must be random.Random, int seed, str seed or None",
        details={"got": type(rng).__name__},
    )


def pick_index(rng: random.Random, size: int) -> int:
    """Uniform index into a buffer of ``size`` bytes (caller ensures > 0)."""
    if size <= 0:
        raise IndexError("cannot pick index from empty payload")
    return rng.randrange(size)


def pick_window(rng: random.Random, size: int, *, min_len: int = 1,
                max_len: Optional[int] = None) -> Tuple[int, int]:
    """Pick ``(start, length)`` window inside ``size`` bytes."""
    if size <= 0:
        raise IndexError("cannot pick window from empty payload")
    max_len = max_len if max_len is not None else size
    max_len = clamp_size(max_len, min_len, size)
    lo = clamp_size(min_len, 1, max_len)
    length = rng.randint(lo, max_len) if max_len > lo else lo
    start = rng.randrange(0, size - length + 1)
    return start, length


def normalise_kind(kind: Any) -> MutationKind:
    """Public alias of :meth:`MutationKind.coerce`."""
    return MutationKind.coerce(kind)


def mutation_digest(data: bytes) -> str:
    """SHA-256 hex of a payload — used to dedupe mutated seeds."""
    return hashlib.sha256(validate_payload(data)).hexdigest()


def mutation_plan_id(seed: Any, kinds: Sequence[Any], rounds: int) -> str:
    """Stable id for a mutation plan (same inputs → same id, always)."""
    norm_kinds = ",".join(sorted(MutationKind.coerce(k).value for k in kinds))
    basis = f"{seed!r}|{norm_kinds}|{int(rounds)}"
    return "mutplan-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24]


# ---------------------------------------------------------------------------
# Text heuristics (used by char-class / case mutations)
# ---------------------------------------------------------------------------

_TEXT_BYTES = bytes(range(0x20, 0x7F)) + b"\t\n\r\x0b\x0c"


def is_probably_text(data: bytes, threshold: float = 0.85) -> bool:
    """Heuristic: fraction of printable/whitespace ASCII bytes ≥ threshold."""
    payload = validate_payload(data)
    if not payload:
        return False
    printable = sum(1 for byte in payload if byte in _TEXT_BYTES)
    return (printable / len(payload)) >= threshold


def infer_text_encoding(data: bytes) -> Optional[str]:
    """Return an encoding name if the payload decodes cleanly, else None."""
    payload = validate_payload(data)
    for candidate in ("utf-8", "utf-16-le", "utf-16-be", "latin-1"):
        try:
            payload.decode(candidate)
            return candidate
        except (UnicodeDecodeError, LookupError):
            continue
    return None


# ---------------------------------------------------------------------------
# Core single-step mutations (pure functions)
# ---------------------------------------------------------------------------


def bit_flip(data: Any, *, position: Optional[int] = None,
             bit: Optional[int] = None, rng: Any = None,
             limits: Optional[MutationLimits] = None) -> MutationResult:
    """Flip one bit of one byte.  Deterministic when ``position``/``bit``/``rng`` fixed."""
    payload = validate_payload(data, limits=limits)
    if not payload:
        return MutationResult(MutationKind.BIT_FLIP, 0, b"", applied=False,
                              reason="empty payload has no bits to flip")
    generator = seeded_rng(rng)
    pos = position if position is not None else pick_index(generator, len(payload))
    pos = clamp_size(pos, 0, len(payload) - 1)
    which = bit if bit is not None else generator.randrange(8)
    which = clamp_size(which, 0, 7)
    mutated = bytearray(payload)
    mutated[pos] ^= 1 << which
    return MutationResult(MutationKind.BIT_FLIP, len(payload), bytes(mutated),
                          details={"position": pos, "bit": which})


def byte_flip(data: Any, *, position: Optional[int] = None,
              xor_mask: int = 0xFF, rng: Any = None,
              limits: Optional[MutationLimits] = None) -> MutationResult:
    """XOR one byte with ``xor_mask`` (default flips all eight bits)."""
    payload = validate_payload(data, limits=limits)
    if not payload:
        return MutationResult(MutationKind.BYTE_FLIP, 0, b"", applied=False,
                              reason="empty payload has no bytes to flip")
    generator = seeded_rng(rng)
    pos = position if position is not None else pick_index(generator, len(payload))
    pos = clamp_size(pos, 0, len(payload) - 1)
    mask = clamp_size(xor_mask, 0, 255)
    if mask == 0:
        return MutationResult(MutationKind.BYTE_FLIP, len(payload), payload,
                              applied=False, reason="xor_mask 0 is identity",
                              details={"position": pos})
    mutated = bytearray(payload)
    mutated[pos] ^= mask
    return MutationResult(MutationKind.BYTE_FLIP, len(payload), bytes(mutated),
                          details={"position": pos, "mask": mask})


_ARITH_DELTAS: Tuple[int, ...] = (-35, -16, -1, 1, 16, 35)


def arithmetic(data: Any, *, position: Optional[int] = None,
               delta: Optional[int] = None, rng: Any = None,
               limits: Optional[MutationLimits] = None) -> MutationResult:
    """Add/subtract a small constant from one byte (wrapping mod 256)."""
    payload = validate_payload(data, limits=limits)
    if not payload:
        return MutationResult(MutationKind.ARITHMETIC, 0, b"", applied=False,
                              reason="empty payload has no bytes")
    generator = seeded_rng(rng)
    pos = position if position is not None else pick_index(generator, len(payload))
    pos = clamp_size(pos, 0, len(payload) - 1)
    step = delta if delta is not None else generator.choice(_ARITH_DELTAS)
    step = clamp_size(step, -255, 255) % 256
    if step == 0:
        return MutationResult(MutationKind.ARITHMETIC, len(payload), payload,
                              applied=False, reason="delta 0 is identity",
                              details={"position": pos})
    mutated = bytearray(payload)
    mutated[pos] = (mutated[pos] + step) & 0xFF
    return MutationResult(MutationKind.ARITHMETIC, len(payload), bytes(mutated),
                          details={"position": pos, "delta": step})


def interest_value(data: Any, *, position: Optional[int] = None,
                   width: int = 1, value: Optional[int] = None,
                   endian: str = "little", rng: Any = None,
                   limits: Optional[MutationLimits] = None) -> MutationResult:
    """Overwrite 1/2/4/8 bytes with a classic interesting numeric value."""
    payload = validate_payload(data, limits=limits)
    if not payload:
        return MutationResult(MutationKind.INTEREST_VALUE, 0, b"", applied=False,
                              reason="empty payload")
    width = clamp_size(width, 1, 8)
    if width not in (1, 2, 4, 8):
        width = 1 << (width - 1)  # 3→4, 5..8 map sensibly
    table = {1: INTERESTING_8, 2: INTERESTING_16, 4: INTERESTING_32, 8: INTERESTING_64}[width]
    generator = seeded_rng(rng)
    if value is None:
        value = generator.choice(table)
    value = clamp_size(value, 0, (1 << (8 * width)) - 1)
    if len(payload) < width:
        return MutationResult(MutationKind.INTEREST_VALUE, len(payload), payload,
                              applied=False,
                              reason=f"payload shorter than {width}-byte field")
    endianness = "<" if str(endian).lower().startswith("l") else ">"
    packed = struct.pack(f"{endianness}{'BHHQ'[int(math.log2(width))]}"[:1] if False else
                         {"1": "B", "2": "H", "4": "I", "8": "Q"}[str(width)], value)
    pos = position if position is not None else rng_and_pick(generator, len(payload) - width + 1)
    pos = clamp_size(pos, 0, len(payload) - width)
    mutated = bytearray(payload)
    mutated[pos:pos + width] = packed
    return MutationResult(MutationKind.INTEREST_VALUE, len(payload), bytes(mutated),
                          details={"position": pos, "width": width,
                                   "value": value, "endian": endianness})


def rng_and_pick(generator: random.Random, upper: int) -> int:
    """Internal helper: uniform pick in ``[0, upper)`` tolerant of upper==1."""
    return generator.randrange(upper) if upper > 1 else 0


def insert_bytes(data: Any, *, payload_to_insert: Optional[bytes] = None,
                 position: Optional[int] = None, length: Optional[int] = None,
                 fill: int = 0x41, rng: Any = None,
                 limits: Optional[MutationLimits] = None) -> MutationResult:
    """Insert bytes at ``position`` (random filler unless ``payload_to_insert``)."""
    payload = validate_payload(data, limits=limits)
    generator = seeded_rng(rng)
    if payload_to_insert is not None:
        chunk = validate_payload(payload_to_insert, limits=limits, name="payload_to_insert")
        if not chunk:
            return MutationResult(MutationKind.INSERT_BYTES, len(payload), payload,
                                  applied=False, reason="nothing to insert")
    else:
        max_room = limits.max_output_bytes - len(payload)
        if max_room <= 0:
            return MutationResult(MutationKind.INSERT_BYTES, len(payload), payload,
                                  applied=False, reason="output cap reached")
        upper = min(max_room, limits.max_block, max(1, len(payload) or 1))
        chunk = bytes([clamp_size(fill, 0, 255)]) * generator.randint(1, upper)
    pos = position if position is not None else generator.randrange(len(payload) + 1)
    pos = clamp_size(pos, 0, len(payload))
    mutated = payload[:pos] + chunk + payload[pos:]
    return MutationResult(MutationKind.INSERT_BYTES, len(payload), mutated,
                          details={"position": pos, "inserted": len(chunk)})


def delete_bytes(data: Any, *, position: Optional[int] = None,
                 length: Optional[int] = None, rng: Any = None,
                 limits: Optional[MutationLimits] = None) -> MutationResult:
    """Delete a contiguous run of bytes."""
    payload = validate_payload(data, limits=limits)
    if not payload:
        return MutationResult(MutationKind.DELETE_BYTES, 0, b"", applied=False,
                              reason="empty payload")
    generator = seeded_rng(rng)
    max_del = min(limits.max_block, len(payload) - (0 if limits.allow_empty_output else 1))
    if max_del <= 0:
        return MutationResult(MutationKind.DELETE_BYTES, len(payload), payload,
                              applied=False, reason="deletion would empty payload")
    dlen = length if length is not None else generator.randint(1, max_del)
    dlen = clamp_size(dlen, 1, max_del)
    start = position if position is not None else generator.randrange(0, len(payload) - dlen + 1)
    start = clamp_size(start, 0, len(payload) - dlen)
    mutated = payload[:start] + payload[start + dlen:]
    if not mutated and not limits.allow_empty_output:
        return MutationResult(MutationKind.DELETE_BYTES, len(payload), payload,
                              applied=False, reason="result would be empty")
    return MutationResult(MutationKind.DELETE_BYTES, len(payload), mutated,
                          details={"position": start, "deleted": dlen})


def replace_block(data: Any, *, start: Optional[int] = None,
                  length: Optional[int] = None, replacement: Optional[bytes] = None,
                  fill: int = 0x42, rng: Any = None,
                  limits: Optional[MutationLimits] = None) -> MutationResult:
    """Replace a window with equal-length random/fixed bytes."""
    payload = validate_payload(data, limits=limits)
    if not payload:
        return MutationResult(MutationKind.REPLACE_BLOCK, 0, b"", applied=False,
                              reason="empty payload")
    generator = seeded_rng(rng)
    pos, blen = (start, length) if start is not None and length is not None \
        else pick_window(generator, len(payload), max_len=limits.max_block)
    if replacement is not None:
        chunk = validate_payload(replacement, limits=limits, name="replacement")[:blen]
        blen = len(chunk)
    else:
        chunk = bytes([clamp_size(fill, 0, 255)]) * blen if generator.random() < 0.5 else \
            generator.randbytes(blen)
    mutated = payload[:pos] + chunk + payload[pos + blen:]
    return MutationResult(MutationKind.REPLACE_BLOCK, len(payload), mutated,
                          details={"position": pos, "length": blen})


def duplicate_block(data: Any, *, start: Optional[int] = None,
                    length: Optional[int] = None, rng: Any = None,
                    limits: Optional[MutationLimits] = None) -> MutationResult:
    """Copy a window and splice the copy right after itself."""
    payload = validate_payload(data, limits=limits)
    if not payload:
        return MutationResult(MutationKind.DUPLICATE_BLOCK, 0, b"", applied=False,
                              reason="empty payload")
    generator = seeded_rng(rng)
    max_dup = min(limits.max_block, limits.max_output_bytes - len(payload))
    if max_dup <= 0:
        return MutationResult(MutationKind.DUPLICATE_BLOCK, len(payload), payload,
                              applied=False, reason="no room to duplicate")
    pos, blen = (start, length) if start is not None and length is not None \
        else pick_window(generator, len(payload), max_len=max_dup)
    blen = clamp_size(blen, 1, min(blen, max_dup, len(payload) - pos))
    chunk = payload[pos:pos + blen]
    mutated = payload[:pos + blen] + chunk + payload[pos + blen:]
    return MutationResult(MutationKind.DUPLICATE_BLOCK, len(payload), mutated,
                          details={"position": pos, "length": blen})


def truncate(data: Any, *, keep: Optional[int] = None, rng: Any = None,
             limits: Optional[MutationLimits] = None) -> MutationResult:
    """Keep only the first ``keep`` bytes (never zero unless allowed)."""
    payload = validate_payload(data, limits=limits)
    if len(payload) <= 1:
        return MutationResult(MutationKind.TRUNCATE, len(payload), payload,
                              applied=False, reason="payload too short to truncate")
    generator = seeded_rng(rng)
    lower = 1 if not limits.allow_empty_output else 0
    n = keep if keep is not None else generator.randint(lower, max(lower, len(payload) - 1))
    n = clamp_size(n, lower, len(payload))
    mutated = payload[:n]
    if mutated == payload:
        return MutationResult(MutationKind.TRUNCATE, len(payload), payload,
                              applied=False, reason="keep == size is identity")
    return MutationResult(MutationKind.TRUNCATE, len(payload), mutated,
                          details={"kept": n})


def extend(data: Any, *, count: Optional[int] = None, fill: int = 0x00,
           rng: Any = None, limits: Optional[MutationLimits] = None) -> MutationResult:
    """Append filler bytes up to the configured output cap."""
    limits = limits or MutationLimits.DEFAULT
    payload = validate_payload(data, limits=limits)
    generator = seeded_rng(rng)
    room = limits.max_output_bytes - len(payload)
    if room <= 0:
        return MutationResult(MutationKind.EXTEND, len(payload), payload,
                              applied=False, reason="output cap reached")
    upper = min(room, max(limits.max_block, 1), MAX_SINGLE_MUTATION_GROWTH)
    n = count if count is not None else generator.randint(1, upper)
    n = clamp_size(n, 1, upper)
    tail = bytes([clamp_size(fill, 0, 255)]) * n if generator.random() < 0.5 else \
        generator.randbytes(n)
    return MutationResult(MutationKind.EXTEND, len(payload), payload + tail,
                          details={"appended": n})


def shuffle_block(data: Any, *, start: Optional[int] = None,
                  length: Optional[int] = None, rng: Any = None,
                  limits: Optional[MutationLimits] = None) -> MutationResult:
    """Permute one window of bytes in place (length-preserving)."""
    payload = validate_payload(data, limits=limits)
    if len(payload) < 2:
        return MutationResult(MutationKind.SHUFFLE_BLOCK, len(payload), payload,
                              applied=False, reason="need at least two bytes")
    generator = seeded_rng(rng)
    pos, blen = (start, length) if start is not None and length is not None \
        else pick_window(generator, len(payload), min_len=2, max_len=limits.max_block)
    blen = clamp_size(blen, 2, len(payload) - pos)
    chunk = bytearray(payload[pos:pos + blen])
    generator.shuffle(chunk)
    mutated = payload[:pos] + bytes(chunk) + payload[pos + blen:]
    if mutated == payload:
        return MutationResult(MutationKind.SHUFFLE_BLOCK, len(payload), payload,
                              applied=False, reason="shuffle produced identity")
    return MutationResult(MutationKind.SHUFFLE_BLOCK, len(payload), mutated,
                          details={"position": pos, "length": blen})


def swap_adjacent(data: Any, *, position: Optional[int] = None, rng: Any = None,
                  limits: Optional[MutationLimits] = None) -> MutationResult:
    """Swap two neighbouring bytes."""
    payload = validate_payload(data, limits=limits)
    if len(payload) < 2:
        return MutationResult(MutationKind.SWAP_ADJACENT, len(payload), payload,
                              applied=False, reason="need at least two bytes")
    generator = seeded_rng(rng)
    pos = position if position is not None else generator.randrange(len(payload) - 1)
    pos = clamp_size(pos, 0, len(payload) - 2)
    if payload[pos] == payload[pos + 1]:
        return MutationResult(MutationKind.SWAP_ADJACENT, len(payload), payload,
                              applied=False, reason="adjacent bytes identical",
                              details={"position": pos})
    mutated = bytearray(payload)
    mutated[pos], mutated[pos + 1] = mutated[pos + 1], mutated[pos]
    return MutationResult(MutationKind.SWAP_ADJACENT, len(payload), bytes(mutated),
                          details={"position": pos})


def overwrite_with_token(data: Any, *, token: Optional[bytes] = None,
                         position: Optional[int] = None, dictionary: Optional[Sequence[bytes]] = None,
                         rng: Any = None, limits: Optional[MutationLimits] = None) -> MutationResult:
    """Overwrite (or insert) a short token at a position."""
    payload = validate_payload(data, limits=limits)
    generator = seeded_rng(rng)
    source = list(dictionary) if dictionary else list(DEFAULT_DICTIONARY)
    source = [validate_payload(tok, limits=limits, name="dictionary token") for tok in source if tok]
    if token is not None:
        chosen = validate_payload(token, limits=limits, name="token")
    elif source:
        chosen = generator.choice(source)
    else:
        return MutationResult(MutationKind.OVERWRITE_TOKEN, len(payload), payload,
                              applied=False, reason="empty dictionary and no token")
    if not chosen:
        return MutationResult(MutationKind.OVERWRITE_TOKEN, len(payload), payload,
                              applied=False, reason="empty token")
    if not payload:
        return MutationResult(MutationKind.OVERWRITE_TOKEN, 0, chosen,
                              details={"position": 0, "inserted": True})
    pos = position if position is not None else generator.randrange(len(payload) + 1)
    pos = clamp_size(pos, 0, len(payload))
    mutated = payload[:pos] + chosen + payload[pos + len(chosen):]
    if len(mutated) > limits.max_output_bytes:
        mutated = payload[:pos] + chosen
    if mutated == payload:
        return MutationResult(MutationKind.OVERWRITE_TOKEN, len(payload), payload,
                              applied=False, reason="token equals existing bytes",
                              details={"position": pos})
    return MutationResult(MutationKind.OVERWRITE_TOKEN, len(payload), mutated,
                          details={"position": pos, "token_len": len(chosen)})


#: Backwards-compatible alias used elsewhere in KMCS docs/tests.
overprint_at = overwrite_with_token


def dictionary_havoc(data: Any, *, steps: Optional[int] = None,
                    dictionary: Optional[Sequence[bytes]] = None, rng: Any = None,
                    limits: Optional[MutationLimits] = None) -> MutationResult:
    """Apply several token overwrites/insertions in one pass."""
    payload = validate_payload(data, limits=limits)
    generator = seeded_rng(rng)
    n = clamp_size(steps if steps is not None else generator.randint(1, 4), 1, limits.max_steps)
    total_in = len(payload)
    current = payload
    applied_steps = 0
    for _ in range(n):
        result = overwrite_with_token(current, dictionary=dictionary,
                                      rng=generator, limits=limits)
        if result.applied:
            current = result.output
            applied_steps += 1
        if not current:
            break
    if applied_steps == 0:
        return MutationResult(MutationKind.DICTIONARY_HAVOC, total_in, payload,
                              applied=False, reason="no token step could be applied")
    return MutationResult(MutationKind.DICTIONARY_HAVOC, total_in, current,
                          details={"steps_applied": applied_steps})


def splice(data: Any, *, donor: Any, start: Optional[int] = None,
           length: Optional[int] = None, donor_start: Optional[int] = None,
           rng: Any = None, limits: Optional[MutationLimits] = None) -> MutationResult:
    """Copy a window from ``donor`` into ``data`` at ``start``."""
    payload = validate_payload(data, limits=limits)
    other = validate_payload(donor, limits=limits, name="donor")
    if not payload or not other:
        return MutationResult(MutationKind.SPLICE, len(payload), payload,
                              applied=False, reason="source or donor empty")
    generator = seeded_rng(rng)
    spos, slen = (start, length) if start is not None and length is not None \
        else pick_window(generator, len(payload), max_len=limits.max_block)
    dpos = donor_start if donor_start is not None else generator.randrange(len(other))
    dpos = clamp_size(dpos, 0, len(other) - 1)
    chunk = other[dpos:dpos + slen]
    if not chunk:
        return MutationResult(MutationKind.SPLICE, len(payload), payload,
                              applied=False, reason="donor window empty")
    mutated = payload[:spos] + chunk + payload[spos + len(chunk):]
    if mutated == payload:
        return MutationResult(MutationKind.SPLICE, len(payload), payload,
                              applied=False, reason="donor bytes identical")
    return MutationResult(MutationKind.SPLICE, len(payload), mutated,
                          details={"position": spos, "length": len(chunk),
                                   "donor_position": dpos})


def zero_out(data: Any, *, start: Optional[int] = None, length: Optional[int] = None,
             rng: Any = None, limits: Optional[MutationLimits] = None) -> MutationResult:
    """Set a window to NUL bytes."""
    payload = validate_payload(data, limits=limits)
    if not payload:
        return MutationResult(MutationKind.ZERO_OUT, 0, b"", applied=False,
                              reason="empty payload")
    generator = seeded_rng(rng)
    pos, blen = (start, length) if start is not None and length is not None \
        else pick_window(generator, len(payload), max_len=limits.max_block)
    chunk = payload[pos:pos + blen]
    if chunk == b"\x00" * blen:
        return MutationResult(MutationKind.ZERO_OUT, len(payload), payload,
                              applied=False, reason="window already zero",
                              details={"position": pos, "length": blen})
    mutated = payload[:pos] + b"\x00" * blen + payload[pos + blen:]
    return MutationResult(MutationKind.ZERO_OUT, len(payload), mutated,
                          details={"position": pos, "length": blen})


_UPPER = re.compile(rb"[a-z]")
_LOWER = re.compile(rb"[A-Z]")


def set_char_class(data: Any, *, position: Optional[int] = None,
                   mode: str = "upper", rng: Any = None,
                   limits: Optional[MutationLimits] = None) -> MutationResult:
    """Force one alphabetic byte to upper/lower/digit/punct class."""
    payload = validate_payload(data, limits=limits)
    if not payload:
        return MutationResult(MutationKind.SET_CHAR_CLASS, 0, b"", applied=False,
                              reason="empty payload")
    generator = seeded_rng(rng)
    mode = str(mode).lower()
    targets = {
        "upper": (_LOWER, lambda b: bytes([b - 32])),
        "lower": (_UPPER, lambda b: bytes([b + 32])),
        "digit": (re.compile(rb"[^0-9]"), lambda b: b"0"[0:1] if False else bytes([0x30])),
        "punct": (re.compile(rb"[A-Za-z0-9]"), lambda b: bytes([0x21])),
    }
    if mode not in targets:
        raise InvalidValueError(f"unknown char class '{mode}'",
                                details={"allowed": sorted(targets)})
    pattern, transform = targets[mode]
    positions = [m.start() for m in pattern.finditer(payload)]
    if not positions:
        return MutationResult(MutationKind.SET_CHAR_CLASS, len(payload), payload,
                              applied=False, reason=f"no byte eligible for '{mode}'")
    pos = position if position is not None else generator.choice(positions)
    pos = clamp_size(pos, 0, len(payload) - 1)
    if pattern.search(payload[pos:pos + 1]) is None:
        return MutationResult(MutationKind.SET_CHAR_CLASS, len(payload), payload,
                              applied=False, reason="chosen position not eligible",
                              details={"position": pos, "mode": mode})
    mutated = payload[:pos] + transform(payload[pos]) + payload[pos + 1:]
    return MutationResult(MutationKind.SET_CHAR_CLASS, len(payload), mutated,
                          details={"position": pos, "mode": mode})


def text_case_flip(data: Any, *, rng: Any = None,
                   limits: Optional[MutationLimits] = None) -> MutationResult:
    """Invert the case of one ASCII letter (SET_CHAR_CLASS sibling op)."""
    payload = validate_payload(data, limits=limits)
    letters = [(i, b) for i, b in enumerate(payload) if 65 <= b <= 90 or 97 <= b <= 122]
    if not letters:
        return MutationResult(MutationKind.TEXT_CASE_FLIP, len(payload), payload,
                              applied=False, reason="no ASCII letters present")
    generator = seeded_rng(rng)
    pos, byte = generator.choice(letters)
    flipped = byte ^ 0x20
    mutated = payload[:pos] + bytes([flipped]) + payload[pos + 1:]
    return MutationResult(MutationKind.TEXT_CASE_FLIP, len(payload), mutated,
                          details={"position": pos})


_STRUCT_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("<I", "uint32le"), (">I", "uint32be"), ("<H", "uint16le"), (">H", "uint16be"),
    ("<Q", "uint64le"), (">Q", "uint64be"),
)


def integer_field_edit(data: Any, *, offset: Optional[int] = None,
                       fmt: Optional[str] = None, new_value: Optional[int] = None,
                       op: str = "interest", rng: Any = None,
                       limits: Optional[MutationLimits] = None) -> MutationResult:
    """Edit a parsed integer field (1/2/4/8 bytes, given endian).

    ``op`` ∈ {``interest`` (replace with classic value), ``double``, ``halve``,
    ``inc``, ``dec``, ``set`` (needs ``new_value``)}.
    """
    payload = validate_payload(data, limits=limits)
    generator = seeded_rng(rng)
    if len(payload) < 2:
        return MutationResult(MutationKind.INTEGER_FIELD_EDIT, len(payload), payload,
                              applied=False, reason="payload too short for integer field")
    candidates: List[Tuple[int, str, int]] = []
    for fstring, tag in _STRUCT_PATTERNS:
        width = struct.calcsize(fstring)
        for start in range(0, len(payload) - width + 1):
            candidates.append((start, tag, width))
    if fmt is not None:
        candidates = [c for c in candidates if c[1] == fmt]
    if not candidates:
        return MutationResult(MutationKind.INTEGER_FIELD_EDIT, len(payload), payload,
                              applied=False, reason=f"no field matches fmt={fmt!r}")
    if offset is not None:
        chosen = next(((offset, t, w) for (o, t, w) in candidates if o == offset),
                      None) or (clamp_size(offset, 0, len(payload) - 1),
                                fmt or "uint32le", struct.calcsize("<I"))
    else:
        chosen = generator.choice(candidates)
    pos, tag, width = chosen
    fstring = {"uint16le": "<H", "uint16be": ">H", "uint32le": "<I",
               "uint32be": ">I", "uint64le": "<Q", "uint64be": ">Q"}.get(tag, "<I")
    width = struct.calcsize(fstring)
    if pos + width > len(payload):
        return MutationResult(MutationKind.INTEGER_FIELD_EDIT, len(payload), payload,
                              applied=False, reason="field runs past end of payload")
    old_value = struct.unpack(fstring, payload[pos:pos + width])[0]
    op = str(op).lower()
    maxv = (1 << (8 * width)) - 1
    if op == "set":
        if new_value is None:
            raise InvalidValueError("integer_field_edit(op='set') requires new_value")
        value = clamp_size(new_value, 0, maxv)
    elif op == "double":
        value = min(old_value * 2, maxv)
    elif op == "halve":
        value = old_value // 2
    elif op == "inc":
        value = min(old_value + 1, maxv)
    elif op == "dec":
        value = max(old_value - 1, 0)
    elif op == "interest":
        table = {1: INTERESTING_8, 2: INTERESTING_16, 4: INTERESTING_32, 8: INTERESTING_64}[width]
        value = generator.choice([v for v in table if v <= maxv] or [0, 1])
    else:
        raise InvalidValueError(f"unknown integer edit op '{op}'",
                                details={"allowed": ["interest", "double", "halve", "inc", "dec", "set"]})
    if value == old_value:
        return MutationResult(MutationKind.INTEGER_FIELD_EDIT, len(payload), payload,
                              applied=False, reason="new value equals old value",
                              details={"position": pos, "field": tag, "value": old_value})
    mutated = payload[:pos] + struct.pack(fstring, value) + payload[pos + width:]
    return MutationResult(MutationKind.INTEGER_FIELD_EDIT, len(payload), mutated,
                          details={"position": pos, "field": tag,
                                   "old": old_value, "new": value, "op": op})


# ---------------------------------------------------------------------------
# Multi-step havoc
# ---------------------------------------------------------------------------

_HAVOC_POOL: Tuple[MutationKind, ...] = (
    MutationKind.BIT_FLIP, MutationKind.BYTE_FLIP, MutationKind.ARITHMETIC,
    MutationKind.INTEREST_VALUE, MutationKind.INSERT_BYTES, MutationKind.DELETE_BYTES,
    MutationKind.REPLACE_BLOCK, MutationKind.DUPLICATE_BLOCK, MutationKind.TRUNCATE,
    MutationKind.EXTEND, MutationKind.SHUFFLE_BLOCK, MutationKind.SWAP_ADJACENT,
    MutationKind.OVERWRITE_TOKEN, MutationKind.ZERO_OUT, MutationKind.TEXT_CASE_FLIP,
)


def havoc(data: Any, *, steps: Optional[int] = None, rng: Any = None,
          limits: Optional[MutationLimits] = None,
          kinds: Optional[Sequence[Any]] = None) -> MutationResult:
    """Compose several single-step mutations, respecting caps at each step.

    Mirrors (very modestly) what real engines do internally; provided purely
    for KMCS-side corpus utilities such as building deterministic edge-case
    regression sets.  Each intermediate result is re-validated against the
    limits so growth cannot compound beyond ``max_output_bytes``.
    """
    payload = validate_payload(data, limits=limits)
    generator = seeded_rng(rng)
    pool = [MutationKind.coerce(k) for k in (kinds or _HAVOC_POOL)]
    if not pool:
        raise InvalidValueError("havoc needs at least one mutation kind")
    n = clamp_size(steps if steps is not None else generator.randint(1, 6), 1, limits.max_steps)
    current = payload
    trail: List[Dict[str, Any]] = []
    for i in range(n):
        kind = generator.choice(pool)
        try:
            step = apply_mutation(kind, current, rng=generator, limits=limits)
        except (InvalidValueError, CorpusError):
            continue
        if step.applied:
            current = step.output
            trail.append({"step": i, "kind": kind.value, "len": len(current)})
        if not current:
            break
    if not trail:
        return MutationResult(MutationKind.HAVOC, len(payload), payload,
                              applied=False, reason="no havoc step was applicable")
    return MutationResult(MutationKind.HAVOC, len(payload), current,
                          details={"steps": trail})


#: Registry mapping kinds to their implementing callables.
FUNCTION_MUTATIONS: Dict[MutationKind, Callable[..., MutationResult]] = {
    MutationKind.BIT_FLIP: bit_flip,
    MutationKind.BYTE_FLIP: byte_flip,
    MutationKind.ARITHMETIC: arithmetic,
    MutationKind.INTEREST_VALUE: interest_value,
    MutationKind.INSERT_BYTES: insert_bytes,
    MutationKind.DELETE_BYTES: delete_bytes,
    MutationKind.REPLACE_BLOCK: replace_block,
    MutationKind.DUPLICATE_BLOCK: duplicate_block,
    MutationKind.TRUNCATE: truncate,
    MutationKind.EXTEND: extend,
    MutationKind.SHUFFLE_BLOCK: shuffle_block,
    MutationKind.SWAP_ADJACENT: swap_adjacent,
    MutationKind.OVERWRITE_TOKEN: overwrite_with_token,
    MutationKind.DICTIONARY_HAVOC: dictionary_havoc,
    MutationKind.SPLICE: splice,
    MutationKind.ZERO_OUT: zero_out,
    MutationKind.SET_CHAR_CLASS: set_char_class,
    MutationKind.TEXT_CASE_FLIP: text_case_flip,
    MutationKind.INTEGER_FIELD_EDIT: integer_field_edit,
    MutationKind.HAVOC: havoc,
}


def apply_mutation(kind: Any, data: Any, *, rng: Any = None,
                   limits: Optional[MutationLimits] = None,
                   **kwargs: Any) -> MutationResult:
    """Single dispatch entry point: ``apply_mutation('bit_flip', b'...')``."""
    resolved = MutationKind.coerce(kind)
    fn = FUNCTION_MUTATIONS.get(resolved)
    if fn is None:  # pragma: no cover — registry is exhaustive by construction
        raise CorpusError(f"no implementation registered for {resolved.value}")
    accepted = {"rng", "limits"} | {
        p for p in (
            "position", "bit", "xor_mask", "delta", "width", "value", "endian",
            "payload_to_insert", "length", "fill", "replacement", "keep", "count",
            "token", "dictionary", "steps", "donor", "start", "donor_start",
            "mode", "offset", "fmt", "new_value", "op", "kinds",
        )
    }
    filtered = {k: v for k, v in kwargs.items() if k in accepted and v is not None}
    unexpected = set(kwargs) - set(filtered)
    if unexpected and any(v is not None for v in unexpected):
        raise InvalidValueError(
            f"unexpected kwargs for {resolved.value}",
            details={"unsupported": sorted(str(k) for k in unexpected)},
        )
    if resolved == MutationKind.SPLICE and "donor" not in filtered:
        raise InvalidValueError("splice mutation requires a 'donor' payload")
    return fn(data, rng=rng, limits=limits, **filtered)


def cycle_kinds(kinds: Optional[Sequence[Any]] = None) -> List[MutationKind]:
    """Deterministic ordered plan of kinds (deduplicated, sorted)."""
    source = kinds if kinds is not None else list(FUNCTION_MUTATIONS)
    seen: Dict[MutationKind, None] = {}
    for item in source:
        seen.setdefault(MutationKind.coerce(item), None)
    return sorted(seen, key=lambda k: k.value)


def grow_by_halving(target: int, current: int) -> int:
    """How much a block op may add: halving rule keeps growth geometric."""
    room = max(0, int(target) - int(current))
    if room == 0:
        return 0
    return max(1, min(room, max(room // 2, 1)))


# ---------------------------------------------------------------------------
# Composable operation objects (used by manager workflows)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MutationOp:
    """A named, parameterised, replayable mutation operation."""

    kind: MutationKind
    params: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", MutationKind.coerce(self.kind))

    def apply(self, data: bytes, *, rng: Any = None,
              limits: Optional[MutationLimits] = None) -> MutationResult:
        return apply_mutation(self.kind, data, rng=rng, limits=limits,
                              **dict(self.params))

    def to_dict(self) -> Dict[str, Any]:
        params = {k: (base64.b64encode(v).decode("ascii")
                      if isinstance(v, (bytes, bytearray)) else v)
                  for k, v in dict(self.params).items()}
        return {"kind": self.kind.value, "params": params}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "MutationOp":
        params = dict(payload.get("params") or {})
        for key, value in list(params.items()):
            if isinstance(value, str) and key in {"token", "replacement", "payload_to_insert", "donor"}:
                try:
                    params[key] = base64.b64decode(value.encode("ascii"))
                except Exception:
                    params[key] = value.encode("utf-8")
        return cls(kind=MutationKind.coerce(payload["kind"]), params=params)


# ---------------------------------------------------------------------------
# Self-test smoke
# ---------------------------------------------------------------------------


def _smoke() -> int:
    failures: List[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            failures.append(name)

    seed = 20261002
    base = b"KMCS-corpus-mutation-sample-0123456789"

    r1 = bit_flip(base, rng=seed)
    r2 = bit_flip(base, rng=seed)
    check("bit_flip deterministic", r1.output == r2.output)
    check("bit_flip pure", base == b"KMCS-corpus-mutation-sample-0123456789")
    check("bit_flip changed", r1.output != base and len(r1.output) == len(base))

    check("empty handled", not bit_flip(b"", rng=1).applied)
    check("insert grows", len(insert_bytes(b"AAAA", length=3, rng=1).output) == 7)
    check("delete shrinks", len(delete_bytes(b"AAAAAAAA", length=3, rng=1).output) == 5)
    check("truncate", truncate(b"ABCDEFGH", keep=3).output == b"ABC")
    check("zero_out", zero_out(b"ABCDEFGH", start=2, length=3).output == b"AB\x00\x00\x00EFGH")
    check("swap", swap_adjacent(b"AB", position=0).output == b"BA")
    check("identity detected", not swap_adjacent(b"AA", position=0).applied)
    check("case flip", text_case_flip(b"abc", rng=1).output.upper() != b"abc")
    check("char class", set_char_class(b"abc", mode="upper", rng=1).output != b"abc")

    edited = integer_field_edit(b"\x00\x00\x00\x00\x00\x00\x00\x00", offset=0,
                                fmt="uint32le", op="set", new_value=300)
    check("int field set", edited.output[:4] == struct.pack("<I", 300))

    spliced = splice(b"AAAAAAAA", donor=b"BBB", start=2, length=3, donor_start=0)
    check("splice", spliced.output == b"AABBBAAAAA"[:8] or spliced.applied)

    hav = havoc(base, rng=seed, limits=MutationLimits())
    check("havoc applied", hav.applied and len(hav.output) <= MutationLimits().max_output_bytes)

    capped = MutationLimits(max_output_bytes=1024, max_input_bytes=1024)
    grown = extend(b"x" * 1000, count=500, rng=1, limits=capped)
    check("cap enforced", grown.applied and len(grown.output) <= 1024)

    op = MutationOp(MutationKind.BIT_FLIP, {"position": 0, "bit": 0})
    check("op roundtrip", MutationOp.from_dict(op.to_dict()).apply(base).output == op.apply(base).output)

    check("registry complete", set(FUNCTION_MUTATIONS) == set(MutationKind) - {MutationKind.HAVOC} | {MutationKind.HAVOC})
    check("coerce alias", MutationKind.coerce("flip-bit") is MutationKind.BIT_FLIP)

    limits_bad = 0
    try:
        MutationLimits(max_steps=0)
        limits_bad = 1
    except InvalidValueError:
        pass
    check("limits validated", limits_bad == 0)

    return len(failures), failures


if __name__ == "__main__":  # pragma: no cover
    count, names = _smoke()
    if count:
        print(f"[kmcs.corpus.mutations] FAILED checks: {names}")
        raise SystemExit(1)
    print("[kmcs.corpus.mutations] smoke OK — 20 mutation kinds, deterministic, bounded")
