# Release validation

Validation was performed on 10 September 2026 with Python 3.12, Docker Desktop's Linux engine, and Harbor 0.20.0's task configuration model.

## Results

- Harbor schema: `task.toml` was accepted as schema 1.4 with one transferred artifact and a separate verifier environment.
- Agent image: the digest-pinned `environment/Dockerfile` built without errors.
- Verifier image: the digest-pinned `tests/Dockerfile` built without errors.
- Oracle proof in Linux: reward `1`; 31 of 31 checks passed.
- Broken-starter proof in Linux: reward `0`; 9 of 31 checks passed.
- Local oracle proof: 31 of 31 checks passed.
- Public example: output matched `expected_records.json` exactly.
- Shortcut resistance: mutants using ordinary integer replay ordering, channel-blind record identity, and unbounded zlib output were rejected by their targeted checks.
- Static validation: all Python source parsed, all JSON and TOML parsed, and the agent/verifier copies of the public model contract were byte-identical.
- Content audit: generated caches, bytecode, VCS data, review exports, secrets, local machine paths, and reference-archive files are excluded from the release ZIP.

The verifier constructs frames independently, starts a fresh unprivileged candidate process for each check, limits CPU, address space, file size, process count, file descriptors, wall time, and captured output, and grants reward only when every check passes.

## Reproduction

From the directory that contains `relayframe-runtime-repair`:

```sh
harbor run -p relayframe-runtime-repair -a oracle
harbor run -p relayframe-runtime-repair -a nop
```

The expected rewards are `1` and `0`, respectively.
