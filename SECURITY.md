# PQLite Security Policy

**PQLite is a product of Dyber, Inc.**

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in PQLite, please report it
responsibly:

1. **Email**: security@dyber.org
2. **Subject**: `[PQLite Security] <brief description>`
3. **Do NOT** open a public GitHub issue for security vulnerabilities

We will acknowledge receipt within 48 hours and provide an initial
assessment within 7 business days.

## Cryptographic Standards

PQLite implements the following NIST-standardized algorithms:

| Standard | Algorithm | Purpose |
|----------|-----------|---------|
| FIPS 203 | ML-KEM-512/768/1024 | Key encapsulation |
| FIPS 204 | ML-DSA-44/65/87 | Digital signatures |
| FIPS 205 | SLH-DSA (12 variants) | Hash-based signatures |
| SP 800-132 | PBKDF2-HMAC-SHA-512 | Password-based key derivation |
| RFC 5869 | HKDF-SHA-256 | Key derivation |
| AES-256-GCM | — | Authenticated encryption |
| HMAC-SHA-256 | — | Page integrity |

## Threat Model

### Protected Against

- **Harvest Now, Decrypt Later (HNDL)**: ML-KEM provides quantum
  resistance for database master keys
- **Page tampering**: AES-256-GCM authenticated encryption detects
  any modification to encrypted pages
- **WAL tampering**: ML-DSA signatures over WAL frames detect
  unauthorized modifications
- **Cold-boot attacks**: Key material stored in mlock'd memory
  (defense-in-depth; not a complete mitigation)
- **Password brute-force**: PBKDF2 with 256,000 iterations

### Not Protected Against

- **Side-channel attacks on the host**: PQLite does not protect
  against a compromised host OS or hypervisor
- **Memory forensics on a running process**: While keys are in
  secure memory, a root-level attacker can still read process memory

## Dependencies

- **liboqs** (Open Quantum Safe): MIT License, actively maintained
- **OpenSSL**: Used for AES-256-GCM, PBKDF2, HKDF, HMAC

Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
