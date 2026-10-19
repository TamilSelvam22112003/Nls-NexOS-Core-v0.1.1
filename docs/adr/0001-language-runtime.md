# ADR-0001: Language/runtime
- Status: Accepted
- Date: 2026-10-19
- Decision: Go 1.22+, static Linux binaries, Ubuntu 22.04/24.04.
- Rationale: mature networking/concurrency and reproducible deployment.
- Alternative rejected: Python daemon due deployment and privileged packet-path concerns.
- Consequence: CI pins toolchain and release targets tested OS versions.