"""Stable public value types for the RelayFrame decoder."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DecodedRecord:
    """One completely reassembled and, when requested, decompressed record."""

    channel_id: int
    record_id: int
    payload: bytes
