/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** FIPS 140-3 Compliance Mode
**
** When FIPS mode is enabled, PQLite:
**   - Uses ONLY FIPS-approved algorithms (AES-256-GCM, SHA-256/384/512)
**   - Loads the OpenSSL FIPS provider (if available)
**   - Runs power-on self-tests (KAT vectors) at initialization
**   - Rejects non-FIPS algorithms (ChaCha20, etc.)
**   - Enforces minimum key lengths
**   - Logs all crypto operations to the audit trail
**
** SQL Interface:
**   PRAGMA pqc_fips_mode = ON;
**   PRAGMA pqc_fips_status;     -- Returns FIPS validation status
**
** NOTE: FIPS 140-3 validation requires testing by an accredited lab.
** This mode ensures PQLite USES FIPS-validated crypto modules (OpenSSL)
** but PQLite itself is not FIPS-validated as a standalone module.
**
** NO other SQLite fork provides FIPS compliance infrastructure.
**
** PQLite is a product of Dyber, Inc.
*/
#ifndef PQLITE_PQC_FIPS_H
#define PQLITE_PQC_FIPS_H

#ifdef PQLITE_ENABLE_PQC

#include "pqc_common.h"

/*
** FIPS mode state
*/
typedef struct PqcFipsState {
  int enabled;                 /* Non-zero if FIPS mode is active */
  int openssl_fips_available;  /* Non-zero if OpenSSL FIPS provider loaded */
  int self_test_passed;        /* Non-zero if KAT self-tests passed */
  char status_msg[256];        /* Human-readable status */
} PqcFipsState;

/*
** Enable FIPS 140-3 mode.
** Attempts to load the OpenSSL FIPS provider and run self-tests.
*/
int pqc_fips_enable(PqcFipsState *state);

/*
** Disable FIPS mode (allows non-FIPS algorithms).
*/
int pqc_fips_disable(PqcFipsState *state);

/*
** Check if FIPS mode is currently active.
*/
int pqc_fips_is_enabled(const PqcFipsState *state);

/*
** Run Known Answer Tests (KATs) for all algorithms used by PQLite.
** Tests AES-256-GCM, HMAC-SHA-256, PBKDF2, SHA-256, SHA-512.
*/
int pqc_fips_run_self_tests(PqcFipsState *state);

/*
** Get FIPS status string (for PRAGMA pqc_fips_status).
*/
const char *pqc_fips_status_string(const PqcFipsState *state);

/*
** Validate that a given algorithm is FIPS-approved.
** Returns PQC_OK if approved, PQC_ERROR if not.
*/
int pqc_fips_check_algorithm(const PqcFipsState *state, const char *alg_name);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_FIPS_H */
