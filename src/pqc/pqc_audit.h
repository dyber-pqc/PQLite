/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Cryptographic Audit Log
**
** Tamper-proof audit trail using a hash chain (blockchain-like)
** with ML-DSA digital signatures. Every database mutation
** (INSERT, UPDATE, DELETE) is logged with:
**   - Timestamp
**   - Operation type and table name
**   - SHA-256 hash of the affected data
**   - Previous log entry's hash (chain)
**   - ML-DSA-65 signature over the entry
**
** Any modification to any log entry breaks the hash chain,
** making tampering immediately detectable.
**
** SQL Interface:
**   PRAGMA pqc_audit = ON;               -- Enable audit logging
**   PRAGMA pqc_audit_verify;             -- Verify chain integrity
**   SELECT * FROM _pqlite_audit_log;     -- Query the audit trail
**
** NO other SQLite fork provides cryptographic audit logging.
**
** PQLite is a product of Dyber, Inc.
*/
#ifndef PQLITE_PQC_AUDIT_H
#define PQLITE_PQC_AUDIT_H

#ifdef PQLITE_ENABLE_PQC

#include "pqc_common.h"
#include "pqc_sig.h"
#include "sqlite3.h"

/*
** Audit operation types
*/
typedef enum {
  PQC_AUDIT_INSERT   = 1,
  PQC_AUDIT_UPDATE   = 2,
  PQC_AUDIT_DELETE   = 3,
  PQC_AUDIT_CREATE   = 4,  /* CREATE TABLE */
  PQC_AUDIT_DROP     = 5,  /* DROP TABLE */
  PQC_AUDIT_ALTER    = 6,  /* ALTER TABLE */
  PQC_AUDIT_PRAGMA   = 7,  /* Security-relevant PRAGMA */
} PqcAuditOp;

/*
** Audit log context — attached to the database connection.
*/
typedef struct PqcAuditLog {
  int enabled;                  /* Non-zero if auditing is active */
  sqlite3 *db;                  /* Database connection */
  PqcSigKeypair signing_key;   /* ML-DSA keypair for signing entries */
  uint8_t prev_hash[32];       /* SHA-256 hash of previous entry (chain) */
  uint64_t sequence;            /* Monotonic sequence number */
} PqcAuditLog;

/*
** Initialize the audit log for a database.
** Creates _pqlite_audit_log table and generates signing key.
*/
int pqc_audit_init(PqcAuditLog *log, sqlite3 *db);

/*
** Log a database mutation.
** Called from SQLite's update hook for INSERT/UPDATE/DELETE.
**
** @param log        Audit log context
** @param op         Operation type
** @param db_name    Database name ("main", etc.)
** @param table_name Table that was modified
** @param rowid      Rowid of the affected row
*/
int pqc_audit_log_mutation(PqcAuditLog *log, PqcAuditOp op,
                             const char *db_name,
                             const char *table_name,
                             sqlite3_int64 rowid);

/*
** Log a DDL operation (CREATE, DROP, ALTER).
*/
int pqc_audit_log_ddl(PqcAuditLog *log, PqcAuditOp op,
                        const char *sql_statement);

/*
** Verify the entire audit chain.
** Walks through all entries and verifies:
** 1. Each entry's hash matches its content
** 2. Each entry's prev_hash matches the previous entry
** 3. Each entry's ML-DSA signature is valid
**
** @param log          Audit log context
** @param n_verified   Output: number of entries verified
** @param n_errors     Output: number of verification failures
** @return PQC_OK if chain is intact, PQC_VERIFY_FAIL if tampered
*/
int pqc_audit_verify_chain(PqcAuditLog *log,
                             int *n_verified, int *n_errors);

/*
** Export the audit signing public key (for external verification).
*/
int pqc_audit_export_pubkey(const PqcAuditLog *log,
                              uint8_t *buf, size_t *buf_len);

/*
** Free audit log resources.
*/
void pqc_audit_free(PqcAuditLog *log);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_AUDIT_H */
