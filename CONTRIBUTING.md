# Contributing to PQLite

Thank you for your interest in contributing to **PQLite**, a product of **Dyber, Inc.**

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run the build: `cmake -B build -DPQLITE_PQC=ON && cmake --build build`
5. Submit a pull request

## Code Guidelines

### PQC Code (`src/pqc/`)
- All PQC code **must** be guarded by `#ifdef PQLITE_ENABLE_PQC`
- Use real liboqs calls — no stubs or placeholder implementations
- All key material must use `pqc_secure_alloc()` / `pqc_secure_free()`
- Wipe sensitive data with `pqc_secure_wipe()` before freeing
- Use constant-time comparisons (`pqc_secure_memcmp()`) for secrets

### General
- Follow existing SQLite coding style (2-space indentation in PQC files)
- Every new file must include the Dyber, Inc. copyright header
- Keep the build working with both `-DPQLITE_PQC=ON` and `-DPQLITE_PQC=OFF`

### Security
- Never commit secrets, keys, or credentials
- Crypto PRs require review by a maintainer with crypto background
- Report vulnerabilities privately: security@dyber.org

## Copyright

All contributions to PQLite's PQC code are licensed under the MIT License.
By submitting a pull request, you agree that your contributions will be
licensed under the project's MIT License.

Copyright (c) 2025-2026 Dyber, Inc.
