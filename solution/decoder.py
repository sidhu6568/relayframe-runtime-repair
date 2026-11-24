"""Correct RelayFrame v1 streaming decoder used by the Harbor oracle."""

from __future__ import annotations

from dataclasses import dataclass
import struct
import zlib

from .model import DecodedRecord


DELIMITER = 0x7E
ESCAPE = 0x7D
ESCAPED_DELIMITER = 0x5E
ESCAPED_ESCAPE = 0x5D
HEADER = struct.Struct(">BBHHIIIH")
MAX_SEGMENT = 2048
MAX_ENCODED_RECORD = 65536
MAX_DECODED_RECORD = 262144
MAX_FRAME_BODY = HEADER.size + MAX_SEGMENT + 4
MAX_INCOMPLETE = 8
WINDOW_BITS = 64
WINDOW_MASK = (1 << WINDOW_BITS) - 1


@dataclass(slots=True)
class _ReplayWindow:
    high: int
    bitmap: int


@dataclass(slots=True)
class _Assembly:
    flags: int
    total: int
    data: bytearray
    present: bytearray
    filled: int
    touched: int


class StreamDecoder:
    """Incrementally decode, validate, replay-filter, and reassemble RelayFrame."""

    def __init__(self) -> None:
        self._started = False
        self._candidate = bytearray()
        self._escape_pending = False
        self._dropping = False
        self._replay: dict[int, _ReplayWindow] = {}
        self._assemblies: dict[tuple[int, int], _Assembly] = {}
        self._touch_clock = 0

    def feed(self, chunk: bytes) -> list[DecodedRecord]:
        if not isinstance(chunk, bytes):
            raise TypeError("chunk must be bytes")

        emitted: list[DecodedRecord] = []
        for byte in chunk:
            if byte == DELIMITER:
                if (
                    self._started
                    and self._candidate
                    and not self._dropping
                    and not self._escape_pending
                ):
                    record = self._consume_body(bytes(self._candidate))
                    if record is not None:
                        emitted.append(record)
                self._started = True
                self._candidate.clear()
                self._escape_pending = False
                self._dropping = False
                continue

            if not self._started or self._dropping:
                continue

            if self._escape_pending:
                if byte == ESCAPED_DELIMITER:
                    self._candidate.append(DELIMITER)
                elif byte == ESCAPED_ESCAPE:
                    self._candidate.append(ESCAPE)
                else:
                    self._candidate.clear()
                    self._dropping = True
                self._escape_pending = False
            elif byte == ESCAPE:
                self._escape_pending = True
            else:
                self._candidate.append(byte)

            if len(self._candidate) > MAX_FRAME_BODY:
                self._candidate.clear()
                self._escape_pending = False
                self._dropping = True

        return emitted

    def _consume_body(self, body: bytes) -> DecodedRecord | None:
        if len(body) < HEADER.size + 4:
            return None

        try:
            version, flags, channel, sequence, record_id, offset, total, length = HEADER.unpack(
                body[: HEADER.size]
            )
        except struct.error:
            return None

        if len(body) != HEADER.size + length + 4:
            return None
        if version != 1 or flags & ~1:
            return None
        if length > MAX_SEGMENT or total > MAX_ENCODED_RECORD:
            return None
        if total == 0:
            if flags != 0 or offset != 0 or length != 0:
                return None
        elif length == 0 or offset > total or length > total - offset:
            return None

        payload = body[HEADER.size : HEADER.size + length]
        supplied_crc = struct.unpack(">I", body[-4:])[0]
        calculated_crc = zlib.crc32(body[:-4]) & 0xFFFFFFFF
        if supplied_crc != calculated_crc:
            return None

        replay = self._preview_replay(channel, sequence)
        if replay is None:
            return None
        self._replay[channel] = replay

        return self._merge_segment(channel, record_id, flags, offset, total, payload)

    def _preview_replay(self, channel: int, sequence: int) -> _ReplayWindow | None:
        current = self._replay.get(channel)
        if current is None:
            return _ReplayWindow(sequence, 1)

        forward = (sequence - current.high) & 0xFFFF
        if forward == 0:
            return None
        if forward < 0x8000:
            if forward >= WINDOW_BITS:
                return _ReplayWindow(sequence, 1)
            shifted = ((current.bitmap << forward) | 1) & WINDOW_MASK
            return _ReplayWindow(sequence, shifted)

        behind = (current.high - sequence) & 0xFFFF
        if behind >= WINDOW_BITS:
            return None
        bit = 1 << behind
        if current.bitmap & bit:
            return None
        return _ReplayWindow(current.high, current.bitmap | bit)

    def _merge_segment(
        self,
        channel: int,
        record_id: int,
        flags: int,
        offset: int,
        total: int,
        payload: bytes,
    ) -> DecodedRecord | None:
        key = (channel, record_id)
        assembly = self._assemblies.get(key)

        if assembly is not None and (assembly.flags != flags or assembly.total != total):
            del self._assemblies[key]
            return None

        if total == 0:
            return DecodedRecord(channel, record_id, b"")

        is_new = assembly is None
        if assembly is None:
            assembly = _Assembly(
                flags=flags,
                total=total,
                data=bytearray(total),
                present=bytearray(total),
                filled=0,
                touched=0,
            )

        for index, value in enumerate(payload, start=offset):
            if assembly.present[index] and assembly.data[index] != value:
                self._assemblies.pop(key, None)
                return None

        for index, value in enumerate(payload, start=offset):
            if not assembly.present[index]:
                assembly.data[index] = value
                assembly.present[index] = 1
                assembly.filled += 1

        self._touch_clock += 1
        assembly.touched = self._touch_clock

        if assembly.filled == total:
            self._assemblies.pop(key, None)
            decoded = self._decode_payload(flags, bytes(assembly.data))
            if decoded is None:
                return None
            return DecodedRecord(channel, record_id, decoded)

        if is_new:
            if len(self._assemblies) >= MAX_INCOMPLETE:
                victim = min(
                    self._assemblies,
                    key=lambda candidate: self._assemblies[candidate].touched,
                )
                del self._assemblies[victim]
            self._assemblies[key] = assembly

        return None

    @staticmethod
    def _decode_payload(flags: int, encoded: bytes) -> bytes | None:
        if flags == 0:
            return encoded

        decompressor = zlib.decompressobj()
        try:
            decoded = decompressor.decompress(encoded, MAX_DECODED_RECORD + 1)
            if (
                len(decoded) > MAX_DECODED_RECORD
                or decompressor.unconsumed_tail
                or not decompressor.eof
                or decompressor.unused_data
            ):
                return None
            decoded += decompressor.flush()
        except zlib.error:
            return None
        if len(decoded) > MAX_DECODED_RECORD:
            return None
        return decoded
