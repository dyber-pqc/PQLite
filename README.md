<p align="center">
  <img src="art/PQLite_logo.png" alt="PQLite Logo" width="280"/>
</p>

<h1 align="center">PQLite</h1>

<p align="center">
  <strong>Post-Quantum Encrypted SQLite</strong><br>
  <em>A product of <a href="https://github.com/dyber-pqc">Dyber, Inc.</a></em>
</p>

<p align="center">
  <a href="https://github.com/dyber-pqc/PQLite/actions/workflows/ci.yml"><img src="https://github.com/dyber-pqc/PQLite/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/dyber-pqc/PQLite/actions/workflows/security-audit.yml"><img src="https://github.com/dyber-pqc/PQLite/actions/workflows/security-audit.yml/badge.svg" alt="Security"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://github.com/dyber-pqc/PQLite/releases"><img src="https://img.shields.io/badge/version-1.0.0-brightgreen.svg" alt="Version"></a>
  <a href="https://csrc.nist.gov/projects/post-quantum-cryptography"><img src="https://img.shields.io/badge/NIST-FIPS%20203%2F204%2F205-orange.svg" alt="NIST PQC"></a>
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#building">Building</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#algorithms">Algorithms</a> &bull;
  <a href="#license">License</a>
</p>

---

## What is PQLite?

**PQLite** is a fork of [SQLite 3.53.0](https://sqlite.org/) that adds **NIST-standardized post-quantum cryptographic (PQC) protection** to the world's most widely deployed database engine.

With quantum computers threatening to break classical encryption, databases are vulnerable to **"harvest now, decrypt later"** attacks. PQLite protects data today against tomorrow's quantum threats using the algorithms standardized by NIST in August 2024.

PQLite is the SQLite companion to [**fortressQL**](https://github.com/dyber-pqc/fortressQL), Dyber's PQC-hardened PostgreSQL fork.

### Why PQLite over SQLCipher or SEE?

| Feature | SQLCipher | SQLite SEE | **PQLite** |
|---------|-----------|-----------|-----------|
| Encryption | AES-256-CBC | AES-128/256 | **AES-256-GCM** |
| Key Exchange | Classical | Classical | **ML-KEM (quantum-safe)** |
| Integrity Signing | No | No | **ML-DSA (quantum-safe)** |
| WAL Signing | No | No | **Yes (ML-DSA-65)** |
| Post-Quantum | No | No | **Yes (FIPS 203/204/205)** |
| Column-Level Encryption | No | No | **Yes** |
| Audit Logging | No | No | **Yes (hash-chain + ML-DSA)** |
| Data Masking | No | No | **Yes (role-based)** |
| Row-Level Security | No | No | **Yes** |
| FIPS 140-3 Mode | No | No | **Yes** |
| Key Management | Password only | Password only | **File, env, command, keychain, PKCS#11** |
| Encrypted Backup | No | No | **Yes (ML-KEM + ML-DSA signed)** |
| Open Source | Yes (BSD) | No (commercial) | **Yes (MIT)** |
| CNSA 2.0 Ready | No | No | **Yes** |

---

## Features

### Core Encryption

| Feature | Description | Standard |
|---------|-------------|----------|
| **ML-KEM Key Encapsulation** | Quantum-resistant key wrapping for master keys | FIPS 203 |
| **AES-256-GCM Page Encryption** | Authenticated encryption of every database page | NIST SP 800-38D |
| **ML-DSA Digital Signatures** | Quantum-resistant WAL signing and database integrity | FIPS 204 |
| **SLH-DSA Signatures** | Conservative hash-based signature alternative | FIPS 205 |
| **PBKDF2-HMAC-SHA-512** | Password-based key derivation (256K iterations) | SP 800-132 |
| **HKDF-SHA-256** | Per-page key derivation with domain separation | RFC 5869 |
| **Page-level HMAC** | Tamper detection on every page read | FIPS 198-1 |

### Enterprise Security

| Feature | Description |
|---------|-------------|
| **Column-Level Encryption** | Encrypt individual columns with per-column keys; deterministic mode enables equality search |
| **Cryptographic Audit Log** | Tamper-proof hash chain with ML-DSA-65 signatures on every mutation |
| **Dynamic Data Masking** | Role-based real-time masking (FULL, PARTIAL, EMAIL, HASH, RANGE, NULLIFY) |
| **Row-Level Security** | SQL-expression row filters per role with session context functions |
| **FIPS 140-3 Mode** | OpenSSL FIPS provider + KAT self-tests + algorithm whitelist |
| **Key Management** | Pluggable backends: file, env, command (Vault/KMS), macOS Keychain, Windows DPAPI |
| **Encrypted Backup** | ML-KEM-encrypted and ML-DSA-signed `.pqlbak` backup files |

---

## Installation

### Ubuntu / Debian (PPA)
```bash
sudo add-apt-repository ppa:dyber/pqlite
sudo apt update
sudo apt install pqlite3
```

### Ubuntu / Debian (.deb download)
```bash
# Or download the .deb directly from the latest release
wget https://github.com/dyber-pqc/PQLite/releases/latest/download/pqlite3_1.0.0_amd64.deb
sudo dpkg -i pqlite3_1.0.0_amd64.deb
```

### macOS (Homebrew)
```bash
brew tap dyber-pqc/tap
brew install pqlite
```

### Docker
```bash
docker pull ghcr.io/dyber-pqc/pqlite:latest
docker run -it -v $(pwd):/data ghcr.io/dyber-pqc/pqlite /data/mydb.db
```

### Pre-built binaries
Download from [GitHub Releases](https://github.com/dyber-pqc/PQLite/releases):
- `pqlite3-linux-x86_64` -- Linux (x86_64)
- `pqlite3-macos-arm64` -- macOS (Apple Silicon)

### Build from source
```bash
git clone https://github.com/dyber-pqc/PQLite.git
cd PQLite
./configure && make sqlite3.c && make shell.c   # Generate amalgamation
cmake -B build -DPQLITE_PQC=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build

## Quick Start

```bash
# Create an encrypted database
./pqlite3 secure.db
pqlite> PRAGMA pqc_key='my-quantum-safe-password';
pqlite> CREATE TABLE secrets(id INTEGER PRIMARY KEY, data TEXT);
pqlite> INSERT INTO secrets VALUES(1, 'quantum-safe data');
pqlite> .quit
```

---

## Architecture

### Key Hierarchy

```
User Password
  | PBKDF2-HMAC-SHA-512 (256K iterations, 16-byte random salt)
  v
Master Key (32 bytes)
  | ML-KEM-768 encapsulate --> KEM ciphertext (stored in DB header)
  v
KEM Shared Secret (32 bytes)
  | HKDF-SHA-256("pqlite-page-key", page_number)
  v
Per-Page AES-256-GCM Key (32 bytes) + IV (12 bytes)
```

### Encryption Flow

```
Write Path:                          Read Path:

+----------+                         +----------+
| SQL Data |                         | Disk     |
+----+-----+                         +----+-----+
     |                                    |
+----v--------+                     +-----v---------+
| B-Tree Page |                     | Encrypted     |
+----+--------+                     | Page + GCM Tag|
     |                              +-----+---------+
+----v-----------+                        |
| AES-256-GCM   |                  +-----v-----------+
| Encrypt + Tag  |                  | AES-256-GCM    |
+----+-----------+                  | Decrypt + Verify|
     |                              +-----+-----------+
+----v----+                               |
| Disk    |                         +-----v-------+
+---------+                         | B-Tree Page |
                                    +-------------+
```

### Integration Points

| Component | Encryption | Signing |
|-----------|-----------|---------|
| Database pages | AES-256-GCM (key from ML-KEM) | HMAC-SHA-256 |
| WAL frames | AES-256-GCM (same key hierarchy) | ML-DSA-65 per-frame |
| Rollback journal | AES-256-GCM | -- |
| Database file (whole) | -- | ML-DSA-65 signature |
| Backup files | AES-256-GCM (independent key) | ML-DSA-65 signature |

---

## Language Bindings

PQLite provides official bindings for all major languages:

| Language | Package | Install |
|----------|---------|---------|
| **Python** | `pqlite3` | `pip install pqlite3` |
| **Rust** | `pqlite` | `cargo add pqlite` |
| **Node.js** | `pqlite3` | `npm install pqlite3` |
| **Go** | `pqlite` | `go get github.com/dyber-pqc/PQLite/bindings/go` |
| **Java** | `io.dyber.pqlite` | Maven/Gradle |
| **C#/.NET** | `PQLite` | NuGet |

See [`bindings/`](bindings/) for full documentation and examples.

---

## Building

### Prerequisites

- **C compiler**: GCC 9+, Clang 10+, or MSVC 2019+
- **CMake**: 3.16+
- **liboqs**: 0.9+ ([Open Quantum Safe](https://openquantumsafe.org/liboqs/))
- **OpenSSL**: 3.0+ (for AES-256-GCM, PBKDF2, HKDF)

### Build Options

```bash
# Full PQC build (recommended)
cmake -B build -DPQLITE_PQC=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Vanilla SQLite (no PQC, zero dependencies)
cmake -B build -DPQLITE_PQC=OFF
cmake --build build

# Debug build with AddressSanitizer
cmake -B build -DPQLITE_PQC=ON -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer"
cmake --build build
```

---

## Usage

### PRAGMA Interface

```sql
-- Encryption key management
PRAGMA pqc_key='my-password';
PRAGMA pqc_key_raw=X'0123456789abcdef...';
PRAGMA pqc_rekey='new-password';

-- Algorithm selection
PRAGMA pqc_algorithm='ml-kem-1024';   -- CNSA 2.0 level
PRAGMA pqc_sig_algorithm='ml-dsa-87'; -- CNSA 2.0 level

-- Status and verification
PRAGMA pqc_status;
PRAGMA pqc_version;
PRAGMA pqc_integrity_check;
PRAGMA pqc_verify_database;

-- Feature toggles
PRAGMA pqc_wal_signing=ON;
PRAGMA pqc_audit=ON;
PRAGMA pqc_fips_mode=ON;

-- Data masking
PRAGMA pqc_mask_role='analyst';
```

### SQL Functions

```sql
-- Key generation
SELECT pqc_kem_keygen('ml-kem-768');
SELECT pqc_sig_keygen('ml-dsa-65');

-- Digital signatures
SELECT pqc_sign(secret_key, CAST('message' AS BLOB));
SELECT pqc_verify(public_key, CAST('message' AS BLOB), signature);

-- Algorithm info
SELECT pqc_algorithm_info('ml-kem-768');
SELECT pqc_version();
```

### C API

```c
#include "pqlite3_api.h"

sqlite3 *db;
sqlite3_open("secure.db", &db);

/* Set encryption key */
pqlite3_key(db, "my-password", 11);

/* Use normally -- encryption is transparent */
sqlite3_exec(db, "CREATE TABLE t(x)", NULL, NULL, NULL);
sqlite3_exec(db, "INSERT INTO t VALUES('quantum safe')", NULL, NULL, NULL);

sqlite3_close(db);
```

---

## Algorithms

### KEM (Key Encapsulation) -- FIPS 203

| Algorithm | Security Level | Public Key | Ciphertext | Shared Secret |
|-----------|---------------|-----------|-----------|--------------|
| ML-KEM-512 | Level 1 (128-bit) | 800 B | 768 B | 32 B |
| **ML-KEM-768** | **Level 3 (192-bit)** | **1,184 B** | **1,088 B** | **32 B** |
| ML-KEM-1024 | Level 5 (256-bit) | 1,568 B | 1,568 B | 32 B |

### Signatures -- FIPS 204 & 205

| Algorithm | Security Level | Public Key | Signature |
|-----------|---------------|-----------|----------|
| ML-DSA-44 | Level 2 | 1,312 B | 2,420 B |
| **ML-DSA-65** | **Level 3** | **1,952 B** | **3,309 B** |
| ML-DSA-87 | Level 5 | 2,592 B | 4,627 B |
| SLH-DSA-* | Levels 1-5 | 32-64 B | 7-50 KB |

**Bold** = PQLite defaults

---

## Project Structure

```
PQLite/
├── src/pqc/                         # PQC core (Dyber, Inc.)
│   ├── pqc_common.c/.h             # Algorithm registry, liboqs wrapper
│   ├── pqc_kem.c/.h                # ML-KEM key encapsulation (FIPS 203)
│   ├── pqc_sig.c/.h                # ML-DSA/SLH-DSA signatures (FIPS 204/205)
│   ├── pqc_mem.c/.h                # Secure memory management
│   ├── pqc_codec.c/.h              # Page encryption (AES-256-GCM)
│   ├── pqc_integrity.c/.h          # Page HMAC + database signing
│   ├── pqc_wal_sign.c/.h           # WAL frame signing
│   ├── pqc_sql_funcs.c/.h          # SQL function extensions
│   ├── pqc_column_encrypt.c/.h     # Column-level encryption
│   ├── pqc_audit.c/.h              # Cryptographic audit log
│   ├── pqc_masking.c/.h            # Dynamic data masking
│   ├── pqc_rls.c/.h                # Row-level security
│   ├── pqc_keymanager.c/.h         # Key management framework
│   ├── pqc_fips.c/.h               # FIPS 140-3 mode
│   ├── pqc_backup.c/.h             # Encrypted backup/restore
│   └── pqlite3_api.h               # Public C API
├── .github/workflows/               # CI/CD pipelines
├── CMakeLists.txt                   # CMake build system
├── LICENSE                          # MIT (PQC) + SQLite public domain
├── SECURITY.md                      # Security policy & threat model
├── CHANGELOG.md                     # Release history
└── README.md                        # This file
```

---

## See Also

- [**fortressQL**](https://github.com/dyber-pqc/fortressQL) -- Dyber's PQC-hardened PostgreSQL fork
- [PQLite on Launchpad](https://launchpad.net/pqlite) -- Ubuntu PPA and project tracking
- [PQLite PPA](https://launchpad.net/~dyber/+archive/ubuntu/pqlite) -- `ppa:dyber/pqlite`
- [PQLite Docker Image](https://github.com/dyber-pqc/PQLite/pkgs/container/pqlite) -- `ghcr.io/dyber-pqc/pqlite`
- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography) -- FIPS 203, 204, 205
- [liboqs](https://github.com/open-quantum-safe/liboqs) -- Open Quantum Safe library
- [SQLite](https://sqlite.org/) -- The original SQLite project

---

## License

PQLite's post-quantum cryptographic additions are licensed under the **MIT License**.

The original SQLite source code is in the **public domain**.

Copyright (c) 2025-2026 **Dyber, Inc.** All rights reserved.

---

<p align="center">
  <img src="art/PQLite.png" alt="PQLite" width="120"/><br>
  <strong>PQLite</strong> -- Quantum-safe databases for the post-quantum era<br>
  <em>A product of <a href="https://github.com/dyber-pqc">Dyber, Inc.</a></em>
</p>
