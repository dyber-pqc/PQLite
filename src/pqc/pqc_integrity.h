/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** PQLite Database Integrity Verification
**
** Provides page-level HMAC verification and whole-database
** ML-DSA signature support for tamper detection.
**
** PQLite is a product of Dyber, Inc.
*/
#ifndef PQLITE_PQC_INTEGRITY_H
#define PQLITE_PQC_INTEGRITY_H

#ifdef PQLITE_ENABLE_PQC

#include "pqc_common.h"
#include "pqc_sig.h"
#include "pqc_codec.h"
#include <stdint.h>

/*
** Verify the HMAC of a single page.
** Returns PQC_OK if intact, PQC_VERIFY_FAIL if tampered.
*/
int pqc_integrity_verify_page(PqcCodec *codec, uint32_t pgno,
                                const uint8_t *data, int data_len,
                                const uint8_t *expected_hmac);

/*
** Sign an entire database file with ML-DSA.
** Computes a hash over all pages, then signs with the provided key.
**
** @param db_path       Path to the database file
** @param kp            ML-DSA signing keypair
** @param signature     Output buffer for the signature
** @param sig_len       In: buffer size. Out: actual signature length.
** @return PQC_OK on success
*/
int pqc_integrity_sign_database(const char *db_path,
                                  const PqcSigKeypair *kp,
                                  uint8_t *signature, size_t *sig_len);

/*
** Verify an ML-DSA signature over an entire database.
*/
int pqc_integrity_verify_database(const char *db_path,
                                    const PqcSigKeypair *kp,
                                    const uint8_t *signature, size_t sig_len);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_INTEGRITY_H */
