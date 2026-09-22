"""RelayFrame v1 decoder with known runtime bugs.

The public capture works because its reads happen to contain complete, ordered frames.
Real transports do not preserve those boundaries. Repair this implementation according
to the task instruction while keeping the public API unchanged.
"""

from __future__ import annotations

import struct
import zlib

from .model import DecodedRecord


DELIMITER = 0x7E
ESCAPE = 0x7D
HEADER = struct.Struct(">BBHHIIIH")


class StreamDecoder:
    """A deliberately flawed baseline that mistakes reads for logical records."""

    def __init__(self) -> None:
        self._last_sequence: dict[int, int] = {}
        self._pieces: dict[int, bytearray] = {}
        self._totals: dict[int, int] = {}
        self._flags: dict[int, int] = {}

    def feed(self, chunk: bytes) -> list[DecodedRecord]:
        completed: list[DecodedRecord] = []

        for encoded in chunk.split(bytes([DELIMITER])):
            if not encoded:
                continue

            body = encoded.replace(b"\x7d\x5e", b"\x7e").replace(b"\x7d\x5d", b"\x7d")
            if len(body) < HEADER.size + 4:
                continue

            try:
                version, flags, channel, sequence, record_id, offset, total, length = HEADER.unpack(
                    body[: HEADER.size]
                )
            except struct.error:
                continue
            payload = body[HEADER.size : HEADER.size + length]
            checksum = body[HEADER.size + length : HEADER.size + length + 4]
            if len(checksum) != 4:
                continue

            if sequence <= self._last_sequence.get(channel, -1):
                continue
            self._last_sequence[channel] = sequence
            expected_crc = struct.unpack(">I", checksum)[0]
            if zlib.crc32(body[: HEADER.size] + payload) & 0xFFFFFFFF != expected_crc:
                continue
            if version != 1 or flags not in (0, 1):
                continue

            piece = self._pieces.setdefault(record_id, bytearray())
            piece.extend(payload)
            self._totals[record_id] = total
            self._flags[record_id] = flags

            if len(piece) >= total:
                raw = bytes(piece[:total])
                del self._pieces[record_id]
                self._totals.pop(record_id, None)
                compressed = self._flags.pop(record_id, 0) == 1
                try:
                    decoded = zlib.decompress(raw) if compressed else raw
                except zlib.error:
                    continue
                completed.append(DecodedRecord(channel, record_id, decoded))

        return completed
