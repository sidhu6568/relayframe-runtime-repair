# Marketplace listing draft

## Title

RelayFrame: Adversarial Binary Stream Decoder Repair Benchmark

## Suggested listing configuration

- Priced asset: one downloadable codebase/ZIP bundle
- Quantity: 1
- Unit price: **USD 2,500**
- Included components: one Harbor task, its evaluation environment, oracle, and verifier
- License posture: non-exclusive, subject to the marketplace agreement
- Domain tags: software engineering, agent evaluation, runtime debugging, binary protocols, cybersecurity infrastructure
- Runtime: Harbor schema 1.4, Docker, Python 3.12, CPU only, offline

Use one priced codebase row so the checkout total is USD 2,500. If the listing form also records the task and environment as descriptive asset types, keep them included in this bundle rather than pricing the same files again.

## Executive summary

RelayFrame evaluates whether a coding agent can repair a plausible telemetry decoder whose clean-path behavior hides coupled runtime failures. The candidate must reason across streaming escape state, frame validation, CRC ordering, modulo serial arithmetic, sparse range assembly, deterministic eviction, and strict decompressed-output limits. A separate verifier runs 31 deterministic checks, including generated metamorphic traffic, without trusting candidate-generated evidence.

The package includes the broken environment, public task instruction, synthetic example input, isolated behavioral verifier, oracle repair, validation documentation, and an independent-redesign provenance record. It contains no customer data, secrets, repository history, or external services.

## Buyer value

- Ready to run with Harbor's Oracle, Nop, and coding-agent workflows.
- Difficulties arise from coupled state and boundary reasoning rather than unavailable dependencies or ambiguous output rules.
- Independent verifier code does not import the oracle or candidate encoding helpers.
- Fixed seeds and offline execution make results reproducible.
- The compact task is suitable for repeated model comparisons and regression testing.

## Delivery contents

The ZIP extracts to one task-root directory. Buyers can inspect the redacted tree, run the clean example, execute the oracle proof, and evaluate agents without assembling additional data or services.
