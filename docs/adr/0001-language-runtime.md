# ADR-0001: Language/runtime
- Status: Proposed.
- Decision: Go 1.22+, static Linux binaries, Ubuntu 22.04/24.04.
- Rationale: mature networking/concurrency and reproducible deployment.
- Alternative rejected: Python daemon, for privileged packet path and deployment consistency.
- Consequence: CI pins toolchain; support only tested targets.