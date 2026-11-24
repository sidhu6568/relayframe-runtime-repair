"""Minimal process boundary around an untrusted candidate decoder."""

from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import traceback


def _load_decoder(path: Path):
    contract_root = os.environ.get("RELAYFRAME_CONTRACT_ROOT", "/opt/relay-contract")
    sys.path.insert(0, contract_root)
    from relayframe.model import DecodedRecord

    spec = importlib.util.spec_from_file_location("relayframe.decoder", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("candidate module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules["relayframe.decoder"] = module
    spec.loader.exec_module(module)
    decoder_type = getattr(module, "StreamDecoder", None)
    if not isinstance(decoder_type, type):
        raise TypeError("candidate must define StreamDecoder")
    return decoder_type, DecodedRecord


def _record_json(record) -> dict[str, object]:
    return {
        "channel_id": record.channel_id,
        "record_id": record.record_id,
        "payload_b64": base64.b64encode(record.payload).decode("ascii"),
    }


def main() -> int:
    request = json.load(sys.stdin)
    candidate = Path(request["candidate_path"])
    chunks = [base64.b64decode(value, validate=True) for value in request["chunks_b64"]]

    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    with contextlib.redirect_stdout(captured_stdout), contextlib.redirect_stderr(captured_stderr):
        decoder_type, record_type = _load_decoder(candidate)
        decoder = decoder_type()
        calls: list[list[dict[str, object]]] = []
        for chunk in chunks:
            result = decoder.feed(chunk)
            if type(result) is not list:
                raise TypeError("feed must return a list")
            for record in result:
                if type(record) is not record_type:
                    raise TypeError("feed returned a non-canonical DecodedRecord")
                if type(record.channel_id) is not int or not 0 <= record.channel_id <= 0xFFFF:
                    raise TypeError("DecodedRecord.channel_id is invalid")
                if type(record.record_id) is not int or not 0 <= record.record_id <= 0xFFFFFFFF:
                    raise TypeError("DecodedRecord.record_id is invalid")
                if type(record.payload) is not bytes:
                    raise TypeError("DecodedRecord.payload must be bytes")
            calls.append([_record_json(record) for record in result])

    json.dump({"ok": True, "calls": calls}, sys.stdout, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    try:
        status = main()
    except BaseException as exc:
        json.dump(
            {
                "ok": False,
                "error": type(exc).__name__,
                "message": str(exc)[:500],
                "trace": "".join(traceback.format_exception_only(type(exc), exc))[:500],
            },
            sys.stdout,
            separators=(",", ":"),
        )
        raise SystemExit(0)
    raise SystemExit(status)
