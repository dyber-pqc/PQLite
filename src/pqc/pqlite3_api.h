/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** PQLite Public C API
**
** This header defines the public C API for PQLite's post-quantum
** cryptographic features. Include this alongside sqlite3.h to access
** PQC key management, algorithm selection, and integrity functions.
**
** PQLite is a product of Dyber, Inc.
*/
#ifndef PQLITE3_API_H
#define PQLITE3_API_H

#include "sqlite3.h"

#ifdef PQLITE_ENABLE_PQC

#include "pqc/pqc_common.h"
#include "pqc/pqc_kem.h"
#include "pqc/pqc_sig.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
** Set the encryption key for a PQLite database.
** Equivalent to: PRAGMA pqc_key='...'
**
** For a new database: creates encryption metadata, generates KEM
** keypair, and begins encrypting all pages.
**
** For an existing encrypted database: derives the master key and
** decapsulates the KEM ciphertext to unlock the database.
**
** @param db      Database connection
** @param pKey    Password (UTF-8 string)
** @param nKey    Password length in bytes
** @return SQLITE_OK on success, SQLITE_ERROR on failure
*/
int pqlite3_key(sqlite3 *db, const void *pKey, int nKey);

/*
** Set the encryption key for a specific attached database.
*/
int pqlite3_key_v2(sqlite3 *db, const char *zDbName,
                    const void *pKey, int nKey);

/*
** Change the encryption key (re-key the database).
** Equivalent to: PRAGMA pqc_rekey='...'
**
** All pages are re-encrypted with the new key. This is a
** potentially expensive operation for large databases.
*/
int pqlite3_rekey(sqlite3 *db, const void *pKey, int nKey);
int pqlite3_rekey_v2(sqlite3 *db, const char *zDbName,
                      const void *pKey, int nKey);

/*
** Set the KEM algorithm for encryption.
** Must be called BEFORE pqlite3_key() for a new database.
** Has no effect on an already-encrypted database (algorithm
** is stored in the database header).
**
** @param db   Database connection
** @param alg  KEM algorithm (PQC_KEM_ML_KEM_512/768/1024)
** @return SQLITE_OK on success
*/
int pqlite3_set_kem_algorithm(sqlite3 *db, PqcKemAlgorithm alg);

/*
** Set the signature algorithm for WAL signing and database signing.
**
** @param db   Database connection
** @param alg  Signature algorithm
** @return SQLITE_OK on success
*/
int pqlite3_set_sig_algorithm(sqlite3 *db, PqcSigAlgorithm alg);

/*
** Query the current encryption status.
**
** @param db   Database connection
** @return 1 if encrypted, 0 if not encrypted
*/
int pqlite3_is_encrypted(sqlite3 *db);

/*
** Export the KEM public key from the database.
** Useful for creating additional encrypted copies or
** for key escrow.
**
** @param db      Database connection
** @param buf     Output buffer (NULL to query required size)
** @param buf_len In: buffer size. Out: bytes written.
** @return SQLITE_OK on success
*/
int pqlite3_export_public_key(sqlite3 *db, uint8_t *buf, size_t *buf_len);

/*
** Sign the entire database with ML-DSA.
** Computes a hash over all pages and produces a digital signature.
**
** @param db          Database connection
** @param kp          ML-DSA signing keypair
** @param signature   Output buffer
** @param sig_len     In: buffer size. Out: actual signature length.
** @return SQLITE_OK on success
*/
int pqlite3_sign_database(sqlite3 *db, const PqcSigKeypair *kp,
                           uint8_t *signature, size_t *sig_len);

/*
** Verify an ML-DSA signature over the entire database.
**
** @param db          Database connection
** @param kp          ML-DSA keypair (public key used)
** @param signature   Signature to verify
** @param sig_len     Signature length
** @return SQLITE_OK if valid, SQLITE_ERROR if invalid
*/
int pqlite3_verify_database(sqlite3 *db, const PqcSigKeypair *kp,
                              const uint8_t *signature, size_t sig_len);

/*
** Get the PQLite version string.
** Returns something like:
**   "PQLite 1.0.0 (based on SQLite 3.53.0, liboqs 0.12.0)"
*/
const char *pqlite3_version(void);

#ifdef __cplusplus
}
#endif

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE3_API_H */
