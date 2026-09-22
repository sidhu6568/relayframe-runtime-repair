"""Independent behavioral verifier for the RelayFrame repair benchmark.

This file intentionally does not import the candidate's helpers or the oracle solution.
It constructs protocol bytes from the written specification and observes only the public
StreamDecoder API through an unprivileged subprocess.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import random
import signal
import struct
import subprocess
import sys
import tempfile
import time
import zlib

try:
    import resource
except ImportError:  # pragma: no cover - local Windows inspection only
    resource = None


DELIMITER = b"\x7e"
HEADER = struct.Struct(">BBHHIIIH")
MAX_BODY = 2072
MAX_DECODED = 262144
ROOT = Path(__file__).resolve().parent
CANDIDATE_PATH = Path(os.environ.get("CANDIDATE_PATH", "/app/relayframe/decoder.py"))
HOST_PATH = Path(os.environ.get("CANDIDATE_HOST", "/opt/relay-runner/candidate_host.py"))
CONTRACT_ROOT = Path(os.environ.get("RELAYFRAME_CONTRACT_ROOT", "/opt/relay-contract"))
REPORT_PATH = Path(os.environ.get("METRICS_PATH", "/logs/verifier/metrics.json"))


class CandidateFailure(RuntimeError):
    """The candidate could not be evaluated as a valid implementation."""


def _drop_privileges() -> None:
    """Constrain the candidate process without requiring external sandbox packages."""

    os.setsid()
    if resource is not None:
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)


def run_candidate(chunks: list[bytes], timeout: float = 6.0) -> list[list[dict[str, object]]]:
    """Execute one fresh decoder and return its records grouped by feed call."""

    if not CANDIDATE_PATH.is_file():
        raise CandidateFailure(f"missing required artifact: {CANDIDATE_PATH}")
    if not HOST_PATH.is_file():
        raise CandidateFailure(f"candidate host is unavailable: {HOST_PATH}")

    request = {
        "candidate_path": str(CANDIDATE_PATH),
        "chunks_b64": [base64.b64encode(chunk).decode("ascii") for chunk in chunks],
    }
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "PYTHONPATH": str(CONTRACT_ROOT),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "RELAYFRAME_CONTRACT_ROOT": str(CONTRACT_ROOT),
    }
    preexec = _drop_privileges if os.name == "posix" else None
    payload = json.dumps(request).encode("utf-8")
    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                [sys.executable, "-E", "-s", str(HOST_PATH)],
                stdin=subprocess.PIPE,
                stdout=stdout_file,
                stderr=stderr_file,
                cwd="/tmp" if os.name == "posix" else None,
                env=environment,
                preexec_fn=preexec,
            )
            try:
                process.communicate(input=payload, timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:  # pragma: no cover - local Windows inspection only
                    process.kill()
                process.wait(timeout=2)
                raise CandidateFailure("candidate timed out") from exc
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout_bytes = stdout_file.read(1_000_001)
            stderr_bytes = stderr_file.read(1_000_001)
    except CandidateFailure:
        raise
    except OSError as exc:
        raise CandidateFailure(f"candidate process failed to start: {exc}") from exc

    if len(stdout_bytes) > 1_000_000 or len(stderr_bytes) > 1_000_000:
        raise CandidateFailure("candidate produced excessive output")
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    try:
        response = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CandidateFailure("candidate host returned malformed output") from exc
    if not response.get("ok"):
        raise CandidateFailure(
            f"{response.get('error', 'candidate error')}: {response.get('message', '')}"
        )
    calls = response.get("calls")
    if not isinstance(calls, list) or len(calls) != len(chunks):
        raise CandidateFailure("candidate host returned an invalid call transcript")
    return calls


def escape_body(body: bytes) -> bytes:
    """Literal verifier-owned RelayFrame escaping."""

    encoded = bytearray()
    for byte in body:
        if byte == 0x7E:
            encoded.extend((0x7D, 0x5E))
        elif byte == 0x7D:
            encoded.extend((0x7D, 0x5D))
        else:
            encoded.append(byte)
    return bytes(encoded)


def frame(
    channel: int,
    sequence: int,
    record_id: int,
    offset: int,
    total: int,
    payload: bytes,
    *,
    flags: int = 0,
    version: int = 1,
    declared_length: int | None = None,
    corrupt_crc: bool = False,
) -> bytes:
    """Build a wire frame without using any code supplied to the candidate."""

    length = len(payload) if declared_length is None else declared_length
    header = HEADER.pack(
        version,
        flags,
        channel,
        sequence,
        record_id,
        offset,
        total,
        length,
    )
    checked = header + payload
    checksum = zlib.crc32(checked) & 0xFFFFFFFF
    if corrupt_crc:
        checksum ^= 0x01020304
    body = checked + struct.pack(">I", checksum)
    return DELIMITER + escape_body(body) + DELIMITER


def expected_record(channel: int, record_id: int, payload: bytes) -> dict[str, object]:
    return {
        "channel_id": channel,
        "record_id": record_id,
        "payload_b64": base64.b64encode(payload).decode("ascii"),
    }


def flatten(calls: list[list[dict[str, object]]]) -> list[dict[str, object]]:
    return [record for call in calls for record in call]


def assert_records(chunks: list[bytes], expected: list[dict[str, object]]) -> None:
    actual = flatten(run_candidate(chunks))
    assert actual == expected, f"records differ: expected={expected!r}, actual={actual!r}"


def cut_at(data: bytes, positions: list[int]) -> list[bytes]:
    cuts = [0] + sorted({value for value in positions if 0 < value < len(data)}) + [len(data)]
    return [data[start:end] for start, end in zip(cuts, cuts[1:])]


def clean_singleton() -> None:
    """Decode one ordinary complete frame delivered in one call."""

    assert_records([frame(1, 1, 1001, 0, 5, b"hello")], [expected_record(1, 1001, b"hello")])


def every_byte_boundary() -> None:
    """Retain parser state across a feed boundary after every wire byte."""

    wire = frame(2, 1, 1002, 0, 8, b"bytewise")
    calls = run_candidate([bytes([byte]) for byte in wire])
    assert flatten(calls) == [expected_record(2, 1002, b"bytewise")]
    assert all(not call for call in calls[:-1]), "record was emitted before the closing delimiter"


def split_escape_pair() -> None:
    """Preserve an escape introducer at the end of a transport read."""

    payload = b"left~middle}right"
    wire = frame(3, 7, 1003, 0, len(payload), payload)
    marker = wire.index(b"\x7d") + 1
    assert_records(cut_at(wire, [marker]), [expected_record(3, 1003, payload)])


def randomized_partitions() -> None:
    """Produce invariant output under seeded chunking of several adjacent frames."""

    stream = b"".join(
        [
            frame(4, 20, 1100, 0, 3, b"one"),
            frame(4, 21, 1101, 0, 7, b"two~two"),
            frame(4, 22, 1102, 0, 5, b"three"),
        ]
    )
    expected = [
        expected_record(4, 1100, b"one"),
        expected_record(4, 1101, b"two~two"),
        expected_record(4, 1102, b"three"),
    ]
    rng = random.Random(4102)
    positions = rng.sample(range(1, len(stream)), min(23, len(stream) - 1))
    assert_records(cut_at(stream, positions), expected)


def noise_empty_and_shared_delimiter() -> None:
    """Ignore preamble/empty frames and support one delimiter shared by adjacent frames."""

    first = frame(5, 1, 1200, 0, 1, b"A")
    second = frame(5, 2, 1201, 0, 1, b"B")
    stream = b"unframed-noise" + b"\x7e\x7e" + first + second[1:]
    assert_records(
        [stream],
        [expected_record(5, 1200, b"A"), expected_record(5, 1201, b"B")],
    )


def invalid_and_dangling_escape_resync() -> None:
    """Drop bad escape candidates and resume at their closing delimiters."""

    invalid = b"\x7eabc\x7d\x00ignored\x7e"
    dangling = b"\x7edef\x7d\x7e"
    good = frame(6, 1, 1300, 0, 2, b"ok")
    assert_records([invalid[:6], invalid[6:] + dangling + good], [expected_record(6, 1300, b"ok")])


def oversized_candidate_resync() -> None:
    """Discard an over-limit decoded body through the next delimiter, then recover."""

    oversized = b"\x7e" + b"Q" * (MAX_BODY + 1) + b"\x7e"
    good = frame(7, 1, 1400, 0, 4, b"next")
    assert_records([oversized + good], [expected_record(7, 1400, b"next")])


def exact_body_length() -> None:
    """Reject bodies with bytes beyond the header-declared segment length."""

    wrong = frame(8, 1, 1500, 0, 3, b"abc", declared_length=2)
    good = frame(8, 1, 1501, 0, 3, b"yes")
    assert_records([wrong + good], [expected_record(8, 1501, b"yes")])


def version_and_flag_validation() -> None:
    """Reject unsupported versions and flag bits without consuming their sequences."""

    bad_version = frame(9, 10, 1600, 0, 1, b"x", version=2)
    bad_flags = frame(9, 10, 1601, 0, 1, b"y", flags=2)
    good = frame(9, 10, 1602, 0, 1, b"z")
    assert_records([bad_version + bad_flags + good], [expected_record(9, 1602, b"z")])


def range_size_and_zero_rules() -> None:
    """Enforce range, empty-segment, total-size, and zero-record constraints."""

    invalid_range = frame(10, 1, 1700, 3, 3, b"x")
    range_probe = frame(10, 1, 1710, 0, 0, b"")
    empty_nonzero = frame(10, 2, 1701, 0, 1, b"")
    empty_probe = frame(10, 2, 1711, 0, 0, b"")
    compressed_zero = frame(10, 3, 1702, 0, 0, b"", flags=1)
    zero_probe = frame(10, 3, 1712, 0, 0, b"")
    over_total = frame(10, 4, 1703, 0, 65537, b"x")
    total_probe = frame(10, 4, 1713, 0, 0, b"")
    assert_records(
        [
            invalid_range
            + range_probe
            + empty_nonzero
            + empty_probe
            + compressed_zero
            + zero_probe
            + over_total
            + total_probe
        ],
        [
            expected_record(10, 1710, b""),
            expected_record(10, 1711, b""),
            expected_record(10, 1712, b""),
            expected_record(10, 1713, b""),
        ],
    )


def maximum_size_boundaries() -> None:
    """Accept 2048-byte segments and a record at the exact 65536-byte limit."""

    payload = bytes((0x7E, 0x7D)) * 32768
    pieces = []
    for index, offset in enumerate(range(0, len(payload), 2048)):
        pieces.append(
            frame(
                10,
                100 + index,
                1750,
                offset,
                len(payload),
                payload[offset : offset + 2048],
            )
        )
    assert_records([b"".join(pieces)], [expected_record(10, 1750, payload)])


def crc_failure_resync() -> None:
    """Drop a bad-CRC frame and decode the valid frame that follows it."""

    bad = frame(11, 1, 1800, 0, 3, b"bad", corrupt_crc=True)
    good = frame(11, 1, 1801, 0, 4, b"good")
    assert_records([bad + good], [expected_record(11, 1801, b"good")])


def duplicate_sequence() -> None:
    """Emit only the first frame carrying a channel's repeated serial number."""

    original = frame(12, 77, 1900, 0, 3, b"one")
    replay = frame(12, 77, 1901, 0, 3, b"two")
    assert_records([original + replay], [expected_record(12, 1900, b"one")])


def sequence_wraparound() -> None:
    """Treat 65535-to-zero as forward progress in serial-number space."""

    sequences = [65534, 65535, 0, 1]
    stream = b"".join(frame(13, seq, 2000 + index, 0, 0, b"") for index, seq in enumerate(sequences))
    expected = [expected_record(13, 2000 + index, b"") for index in range(4)]
    assert_records([stream], expected)


def unseen_out_of_order_sequence() -> None:
    """Accept unseen serials that arrive behind the high-water mark inside the window."""

    sequences = [100, 103, 101, 102]
    stream = b"".join(frame(14, seq, 2100 + index, 0, 0, b"") for index, seq in enumerate(sequences))
    expected = [expected_record(14, 2100 + index, b"") for index in range(4)]
    assert_records([stream], expected)


def replay_window_boundaries() -> None:
    """Accept unseen behind-63 and reject unseen behind-64, duplicates, and half range."""

    stream = b"".join(
        [
            frame(15, 1000, 2200, 0, 0, b""),
            frame(15, 1065, 2201, 0, 0, b""),
            frame(15, 1001, 2202, 0, 0, b""),
            frame(15, 1002, 2203, 0, 0, b""),
            frame(15, 1002, 2204, 0, 0, b""),
            frame(15, (1065 + 32768) & 0xFFFF, 2205, 0, 0, b""),
        ]
    )
    expected = [
        expected_record(15, 2200, b""),
        expected_record(15, 2201, b""),
        expected_record(15, 2203, b""),
    ]
    assert_records([stream], expected)


def bad_crc_does_not_poison_replay() -> None:
    """Keep a CRC-invalid future serial from advancing the replay high-water mark."""

    stream = b"".join(
        [
            frame(16, 10, 2300, 0, 0, b""),
            frame(16, 500, 2301, 0, 0, b"", corrupt_crc=True),
            frame(16, 11, 2302, 0, 0, b""),
        ]
    )
    assert_records(
        [stream],
        [expected_record(16, 2300, b""), expected_record(16, 2302, b"")],
    )


def bad_crc_does_not_poison_assembly() -> None:
    """Prevent a CRC-invalid completing segment from mutating an existing assembly."""

    stream = b"".join(
        [
            frame(16, 30, 2350, 0, 4, b"ab"),
            frame(16, 31, 2350, 2, 4, b"XX", corrupt_crc=True),
            frame(16, 31, 2350, 2, 4, b"cd"),
        ]
    )
    assert_records([stream], [expected_record(16, 2350, b"abcd")])


def reversed_absolute_segments() -> None:
    """Reassemble two segments delivered in reverse absolute-offset order."""

    stream = frame(17, 1, 2400, 5, 10, b"fghij") + frame(17, 2, 2400, 0, 10, b"abcde")
    assert_records([stream], [expected_record(17, 2400, b"abcdefghij")])


def gap_delays_completion() -> None:
    """Withhold output until a missing middle range arrives."""

    chunks = [
        frame(18, 1, 2500, 0, 8, b"ab") + frame(18, 2, 2500, 5, 8, b"fgh"),
        frame(18, 3, 2500, 2, 8, b"cde"),
    ]
    calls = run_candidate(chunks)
    assert calls[0] == [], f"gapped record emitted early: {calls[0]!r}"
    assert calls[1] == [expected_record(18, 2500, b"abcdefgh")]


def identical_overlap() -> None:
    """Allow matching overlapping ranges while counting only new byte positions."""

    stream = frame(19, 1, 2600, 0, 7, b"abcde") + frame(19, 2, 2600, 2, 7, b"cdefg")
    assert_records([stream], [expected_record(19, 2600, b"abcdefg")])


def conflicting_overlap_recovery() -> None:
    """Delete a conflicted assembly and accept a later clean reconstruction."""

    calls = run_candidate(
        [
            frame(20, 1, 2700, 0, 8, b"abcde") + frame(20, 2, 2700, 2, 8, b"cdX"),
            frame(20, 3, 2700, 5, 8, b"fgh"),
            frame(20, 4, 2700, 0, 8, b"abcdefgh"),
        ]
    )
    assert calls[:2] == [[], []], f"conflicted bytes survived: {calls[:2]!r}"
    assert calls[2] == [expected_record(20, 2700, b"abcdefgh")]


def metadata_mismatch_recovery() -> None:
    """Clear assemblies after total or flag disagreement before clean reconstruction."""

    calls = run_candidate(
        [
            frame(21, 1, 2800, 0, 6, b"abc") + frame(21, 2, 2800, 3, 7, b"defg"),
            frame(21, 3, 2800, 3, 6, b"def"),
            frame(21, 4, 2800, 0, 6, b"abcdef"),
            frame(21, 5, 2801, 0, 6, b"abc")
            + frame(21, 6, 2801, 3, 6, b"def", flags=1),
            frame(21, 7, 2801, 3, 6, b"def"),
            frame(21, 8, 2801, 0, 6, b"abcdef"),
        ]
    )
    assert calls[0:2] == [[], []], f"total mismatch did not clear state: {calls[0:2]!r}"
    assert calls[2] == [expected_record(21, 2800, b"abcdef")]
    assert calls[3:5] == [[], []], f"flag mismatch did not clear state: {calls[3:5]!r}"
    assert calls[5] == [expected_record(21, 2801, b"abcdef")]


def channel_scoped_record_identity() -> None:
    """Keep equal record identifiers on different channels completely independent."""

    stream = b"".join(
        [
            frame(22, 1, 42, 0, 4, b"ab"),
            frame(23, 1, 42, 0, 4, b"wx"),
            frame(23, 2, 42, 2, 4, b"yz"),
            frame(22, 2, 42, 2, 4, b"cd"),
        ]
    )
    expected = [expected_record(23, 42, b"wxyz"), expected_record(22, 42, b"abcd")]
    assert_records([stream], expected)


def whole_record_compression() -> None:
    """Reassemble compressed bytes first and inflate exactly once after completion."""

    payload = (b"sensor=alpha;value=17;" * 300) + b"~}"
    encoded = zlib.compress(payload, level=9)
    midpoint = len(encoded) // 2
    stream = frame(24, 1, 2900, midpoint, len(encoded), encoded[midpoint:], flags=1)
    stream += frame(24, 2, 2900, 0, len(encoded), encoded[:midpoint], flags=1)
    assert_records([stream], [expected_record(24, 2900, payload)])


def invalid_compression_is_bounded_and_recovers() -> None:
    """Reject malformed, trailing, and over-limit zlib data while preserving later traffic."""

    malformed = b"this is not a zlib stream"
    trailing = zlib.compress(b"valid prefix") + b"trailing"
    exact_payload = b"A" * MAX_DECODED
    exact_limit = zlib.compress(exact_payload, level=9)
    bomb = zlib.compress(b"B" * (MAX_DECODED + 1), level=9)
    stream = b"".join(
        [
            frame(25, 1, 3000, 0, len(malformed), malformed, flags=1),
            frame(25, 1, 3999, 0, 1, b"x"),
            frame(25, 2, 3000, 0, 7, b"recover"),
            frame(25, 3, 3001, 0, len(trailing), trailing, flags=1),
            frame(25, 4, 3002, 0, len(bomb), bomb, flags=1),
            frame(25, 5, 3003, 0, len(exact_limit), exact_limit, flags=1),
            frame(25, 6, 3004, 0, 4, b"safe"),
        ]
    )
    assert_records(
        [stream],
        [
            expected_record(25, 3000, b"recover"),
            expected_record(25, 3003, exact_payload),
            expected_record(25, 3004, b"safe"),
        ],
    )


def deterministic_lru_eviction() -> None:
    """Apply the incomplete cap globally, refresh LRU, and avoid evicting for instant completion."""

    phase_one = [frame(40 + index, 1, 3100 + index, 0, 2, b"A") for index in range(8)]
    phase_one.append(frame(48, 1, 3199, 0, 1, b"Z"))
    phase_one.extend(frame(40 + index, 2, 3100 + index, 1, 2, b"B") for index in range(8))

    phase_two = [frame(50 + index, 1, 3200 + index, 0, 2, b"A") for index in range(8)]
    phase_two.append(frame(50, 2, 3200, 0, 2, b"A"))
    phase_two.append(frame(58, 1, 3208, 0, 2, b"A"))
    for index in range(9):
        sequence = 3 if index == 0 else 2
        phase_two.append(frame(50 + index, sequence, 3200 + index, 1, 2, b"B"))

    expected = [expected_record(48, 3199, b"Z")]
    expected.extend(expected_record(40 + index, 3100 + index, b"AB") for index in range(8))
    expected.extend(
        expected_record(50 + index, 3200 + index, b"AB")
        for index in [0, 2, 3, 4, 5, 6, 7, 8]
    )
    assert_records([b"".join(phase_one + phase_two)], expected)


def one_call_can_emit_multiple_records() -> None:
    """Return every record completed by a call in wire-completion order."""

    stream = b"".join(frame(27, seq, 3200 + seq, 0, 1, bytes([64 + seq])) for seq in range(1, 5))
    calls = run_candidate([stream])
    expected = [expected_record(27, 3200 + seq, bytes([64 + seq])) for seq in range(1, 5)]
    assert calls == [expected]


def replay_is_channel_local() -> None:
    """Use independent replay windows when channels carry the same serial values."""

    stream = b"".join(
        [
            frame(28, 400, 3300, 0, 1, b"a"),
            frame(29, 1, 3301, 0, 1, b"b"),
            frame(28, 401, 3302, 0, 1, b"c"),
            frame(29, 2, 3303, 0, 1, b"d"),
        ]
    )
    expected = [
        expected_record(28, 3300, b"a"),
        expected_record(29, 3301, b"b"),
        expected_record(28, 3302, b"c"),
        expected_record(29, 3303, b"d"),
    ]
    assert_records([stream], expected)


def structurally_valid_conflict_consumes_sequence() -> None:
    """Consume replay state for CRC-correct frames rejected by assembly conflict."""

    stream = b"".join(
        [
            frame(30, 10, 3400, 0, 4, b"ab"),
            frame(30, 11, 3400, 1, 4, b"X"),
            frame(30, 11, 3401, 0, 1, b"q"),
            frame(30, 12, 3402, 0, 1, b"r"),
        ]
    )
    assert_records([stream], [expected_record(30, 3402, b"r")])


def seeded_metamorphic_corpus() -> None:
    """Decode a generated corpus under many chunkings and interleaved fragment orders."""

    rng = random.Random(918273)
    next_sequence = {31: 65520, 32: 91, 33: 700}
    all_frames: list[bytes] = []
    expected: list[dict[str, object]] = []

    for batch in range(4):
        pending: list[tuple[int, int, int, int, bytes, int]] = []
        for within in range(5):
            ordinal = batch * 5 + within
            channel = 31 + (ordinal % 3)
            record_id = 4000 + ordinal
            size = rng.randint(80, 1800)
            raw = bytearray(rng.randbytes(size))
            raw[ordinal % size] = 0x7E
            raw[(ordinal * 7 + 3) % size] = 0x7D
            payload = bytes(raw)
            flags = ordinal % 2
            encoded = zlib.compress(payload, level=6) if flags else payload
            expected.append(expected_record(channel, record_id, payload))
            cursor = 0
            while cursor < len(encoded):
                width = rng.randint(1, min(700, len(encoded) - cursor))
                pending.append((channel, record_id, cursor, len(encoded), encoded[cursor : cursor + width], flags))
                cursor += width
        rng.shuffle(pending)
        for channel, record_id, offset, total, payload, flags in pending:
            sequence = next_sequence[channel]
            next_sequence[channel] = (sequence + 1) & 0xFFFF
            all_frames.append(frame(channel, sequence, record_id, offset, total, payload, flags=flags))

    stream = b"".join(all_frames)
    expected_sorted = sorted(expected, key=lambda item: (item["channel_id"], item["record_id"]))
    for trial in range(10):
        partition_rng = random.Random(7000 + trial)
        cut_count = min(90, len(stream) - 1)
        positions = partition_rng.sample(range(1, len(stream)), cut_count)
        actual = flatten(run_candidate(cut_at(stream, positions), timeout=10.0))
        actual_sorted = sorted(actual, key=lambda item: (item["channel_id"], item["record_id"]))
        assert actual_sorted == expected_sorted, f"metamorphic partition {trial} differed"


CHECKS = [
    ("clean_singleton", clean_singleton),
    ("every_byte_boundary", every_byte_boundary),
    ("split_escape_pair", split_escape_pair),
    ("randomized_partitions", randomized_partitions),
    ("noise_empty_shared_delimiter", noise_empty_and_shared_delimiter),
    ("invalid_dangling_escape_resync", invalid_and_dangling_escape_resync),
    ("oversized_candidate_resync", oversized_candidate_resync),
    ("exact_body_length", exact_body_length),
    ("version_flag_validation", version_and_flag_validation),
    ("range_size_zero_rules", range_size_and_zero_rules),
    ("maximum_size_boundaries", maximum_size_boundaries),
    ("crc_failure_resync", crc_failure_resync),
    ("duplicate_sequence", duplicate_sequence),
    ("sequence_wraparound", sequence_wraparound),
    ("unseen_out_of_order_sequence", unseen_out_of_order_sequence),
    ("replay_window_boundaries", replay_window_boundaries),
    ("bad_crc_does_not_poison_replay", bad_crc_does_not_poison_replay),
    ("bad_crc_does_not_poison_assembly", bad_crc_does_not_poison_assembly),
    ("reversed_absolute_segments", reversed_absolute_segments),
    ("gap_delays_completion", gap_delays_completion),
    ("identical_overlap", identical_overlap),
    ("conflicting_overlap_recovery", conflicting_overlap_recovery),
    ("metadata_mismatch_recovery", metadata_mismatch_recovery),
    ("channel_scoped_record_identity", channel_scoped_record_identity),
    ("whole_record_compression", whole_record_compression),
    ("invalid_compression_bounded_recovery", invalid_compression_is_bounded_and_recovers),
    ("deterministic_lru_eviction", deterministic_lru_eviction),
    ("one_call_multiple_records", one_call_can_emit_multiple_records),
    ("replay_is_channel_local", replay_is_channel_local),
    ("conflict_consumes_sequence", structurally_valid_conflict_consumes_sequence),
    ("seeded_metamorphic_corpus", seeded_metamorphic_corpus),
]


def main() -> int:
    started = time.monotonic()
    results: list[dict[str, object]] = []
    for check_index, (name, check) in enumerate(CHECKS):
        check_started = time.monotonic()
        try:
            check()
        except CandidateFailure as exc:
            results.append(
                {
                    "name": name,
                    "passed": False,
                    "duration_ms": round((time.monotonic() - check_started) * 1000, 3),
                    "detail": f"CandidateFailure: {str(exc)[:700]}",
                }
            )
            for skipped_name, _ in CHECKS[check_index + 1 :]:
                results.append(
                    {
                        "name": skipped_name,
                        "passed": False,
                        "duration_ms": 0.0,
                        "detail": "not run after a fatal candidate failure",
                    }
                )
            break
        except BaseException as exc:
            results.append(
                {
                    "name": name,
                    "passed": False,
                    "duration_ms": round((time.monotonic() - check_started) * 1000, 3),
                    "detail": f"{type(exc).__name__}: {str(exc)[:700]}",
                }
            )
        else:
            results.append(
                {
                    "name": name,
                    "passed": True,
                    "duration_ms": round((time.monotonic() - check_started) * 1000, 3),
                    "detail": "",
                }
            )

    passed = sum(1 for result in results if result["passed"])
    report = {
        "schema_version": "1.0",
        "candidate": str(CANDIDATE_PATH),
        "passed": passed,
        "total": len(results),
        "all_passed": passed == len(results),
        "diagnostic_fraction": passed / len(results),
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
        "checks": results,
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"RelayFrame verification: {passed}/{len(results)} checks passed")
    for result in results:
        if not result["passed"]:
            print(f"FAIL {result['name']}: {result['detail']}")
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
