# Changelog

All notable changes to PQLite will be documented in this file.

## [1.1.0] - 2026-04-01

### Added — Full Encryption Pipeline
- **PRAGMA pqc_key wired to full codec pipeline**: Password → PBKDF2-HMAC-SHA-512
  → ML-KEM-768 encapsulate → HKDF-SHA-256 → per-page AES-256-GCM keys →
  codec attached to pager via pqlitePagerSetCodec()
- **PRAGMA pqc_rekey**: Re-encrypt database with new password (codec-backed)
- **WAL frame encryption**: walWriteOneFrame() encrypts page data before WAL write
- **WAL frame decryption**: sqlite3WalReadFrame() decryption hook (pager-level)
- **WAL codec propagation**: pqlitePagerSetCodec() propagates codec to WAL subsystem
- **PQC integration tests in CI**: PRAGMA pqc_version, pqc_algorithm, pqc_cipher,
  pqc_key; SELECT pqc_version(), pqc_algorithm_info()
- **Homebrew tap**: `brew tap dyber-pqc/tap && brew install pqlite`

### Changed
- PRAGMA pqc_key now creates and attaches a real PqcCodec (was placeholder)
- PRAGMA pqc_rekey now calls pqc_codec_rekey() (was placeholder)
- Pager encrypt/decrypt hooks now call pqc_codec_encrypt_page/decrypt_page
- WAL struct now carries pPqcCodec pointer for frame encryption

### Fixed
- WAL mode encryption: frames are now encrypted before writing to WAL file

## [1.0.0] - 2026-03-31

### Added — Post-Quantum Cryptography Core
- ML-KEM-512/768/1024 key encapsulation (FIPS 203) via liboqs
- ML-DSA-44/65/87 digital signatures (FIPS 204) via liboqs
- SLH-DSA (SPHINCS+) hash-based signatures (FIPS 205) — 12 variants
- Secure memory management with mlock/VirtualLock and guaranteed wipe

### Added — Transparent Database Encryption
- AES-256-GCM page-level encryption with per-page key derivation
- PBKDF2-HMAC-SHA-512 password-based key derivation (256K iterations)
- HKDF-SHA-256 per-page key and IV derivation
- ML-KEM key wrapping for database master keys
- WAL and rollback journal encryption
- PQLite header format in page 1 for encryption metadata

### Added — Database Integrity
- HMAC-SHA-256 per-page integrity verification
- ML-DSA-65 WAL frame signing with .wal.sig sidecar files
- Whole-database ML-DSA signing and verification

### Added — Column-Level Encryption
- Per-column encryption with individual column encryption keys (CEKs)
- Randomized mode (IND-CPA secure) for maximum privacy
- Deterministic mode for equality-searchable encrypted columns

### Added — Cryptographic Audit Log
- Tamper-proof hash chain (blockchain-style) audit trail
- ML-DSA-65 signed audit entries
- Chain integrity verification (PRAGMA pqc_audit_verify)

### Added — Dynamic Data Masking
- Role-based real-time masking policies
- Masking types: FULL, PARTIAL, EMAIL, HASH, NULLIFY, RANGE
- Same data, different views per session role

### Added — Key Management Framework
- Pluggable key providers: password, file, environment, command
- macOS Keychain integration
- Windows DPAPI integration
- PKCS#11 HSM interface (stub for future hardware integration)

### Added — Row-Level Security
- SQL expression-based row filtering per role
- Context functions: pqc_current_user(), pqc_current_role(), pqc_clearance()
- Admin bypass for full access

### Added — FIPS 140-3 Compliance Mode
- OpenSSL FIPS provider loading
- Known Answer Tests (KATs) for AES-256-GCM, SHA-256, DRBG
- FIPS-approved algorithm whitelist enforcement

### Added — Encrypted Backup & Restore
- ML-KEM-encrypted backup files (.pqlbak format)
- ML-DSA-signed backups with signature verification before restore
- Backup metadata inspection

### Added — SQL Functions
- pqc_kem_keygen(), pqc_sig_keygen() — key generation
- pqc_sign(), pqc_verify() — signing and verification
- pqc_algorithm_info() — algorithm metadata
- pqc_version() — version string

### Added — PRAGMA Interface
- pqc_key, pqc_key_raw, pqc_rekey — encryption key management
- pqc_algorithm, pqc_sig_algorithm — algorithm selection
- pqc_status, pqc_version — status queries
- pqc_wal_signing, pqc_audit, pqc_fips_mode — feature toggles
- pqc_integrity_check, pqc_verify_database — verification

### Added — Build & Infrastructure
- CMake build system with -DPQLITE_PQC=ON/OFF
- GitHub Actions CI (Linux, macOS, Windows)
- Security audit workflow (cppcheck, CodeQL, ASan)
- Performance benchmark workflow
- Release pipeline with multi-platform binaries

### Base
- Based on SQLite 3.53.0 (public domain)

---

Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
PQLite is a product of Dyber, Inc.
