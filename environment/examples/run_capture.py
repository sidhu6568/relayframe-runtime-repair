"""Run the public clean capture through the installed decoder."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from relayframe import StreamDecoder


def main() -> None:
    root = Path(__file__).resolve().parent
    decoder = StreamDecoder()
    records = []
    for line in (root / "capture_chunks.jsonl").read_text(encoding="utf-8").splitlines():
        chunk = base64.b64decode(json.loads(line)["chunk_b64"])
        records.extend(decoder.feed(chunk))
    rendered = [
        {
            "channel_id": item.channel_id,
            "record_id": item.record_id,
            "payload_b64": base64.b64encode(item.payload).decode("ascii"),
        }
        for item in records
    ]
    print(json.dumps(rendered, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
