# RelayFrame Runtime Repair Benchmark

RelayFrame is a self-contained Harbor 1.4 benchmark for evaluating runtime debugging and repair. The candidate receives a plausible Python telemetry decoder that succeeds on a clean public capture but fails when real transport and protocol behavior interact. The repair must coordinate incremental framing, replay protection, sparse record assembly, integrity checks, compression, and bounded state.

## What is included

- `instruction.md` — the complete agent-visible behavioral contract.
- `environment/` — a digest-pinned, offline Python image with the broken decoder and a clean example capture.
- `solution/` — an oracle-only reference repair used to prove solvability.
- `tests/` — an offline separate verifier with 31 deterministic behavioral checks.
- `task.toml` — Harbor schema 1.4 metadata, resource limits, artifact declaration, and isolated-verifier configuration.
- `VALIDATION.md`, `PROVENANCE.md`, `LICENSE.txt`, and `MARKETPLACE_LISTING.md` — release evidence, provenance, and listing notes.

The task has no runtime package dependencies outside Python's standard library. Neither the oracle nor verifier is copied into the agent image. During a Harbor run, only `/app/relayframe/decoder.py` is transferred to the separate verifier.

## Run with Harbor

From the directory containing this task:

```sh
harbor run -p relayframe-runtime-repair -a oracle
harbor run -p relayframe-runtime-repair -a nop
```

The oracle must produce reward `1`; the unmodified starter must produce reward `0`. Detailed check results are written to `/logs/verifier/metrics.json`, while Harbor reads the scalar `/logs/verifier/reward.txt`.

For a quick agent-visible demonstration inside the environment, run:

```sh
python /app/examples/run_capture.py
```

The intentionally clean capture is not a substitute for the verifier. It exists to make the initial runtime behavior reproducible without revealing the adversarial cases.

## Evaluation design

The verifier generates protocol frames independently and executes the candidate in a fresh unprivileged subprocess for each check. It covers individual byte boundaries, split escapes, shared delimiters, malformed-frame recovery, CRC ordering, modulo-16-bit replay boundaries, absolute-offset assembly, gaps and overlaps, cross-channel identity, exact size limits, bounded zlib handling, deterministic LRU eviction, and a generated metamorphic corpus under ten transport partitions.

All checks are binary requirements. Partial results are recorded only as diagnostics; the Harbor reward is `1` only when all 31 checks pass.
