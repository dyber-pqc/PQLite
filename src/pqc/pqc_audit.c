/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Cryptographic Audit Log — Implementation
**
** Hash chain structure (each entry):
**   entry_hash = SHA-256(sequence || timestamp || op || table || rowid || prev_hash)
**   signature  = ML-DSA-65.sign(signing_key, entry_hash)
**
** The chain is append-only. Modifying any entry changes its hash,
** which breaks the prev_hash link in the next entry, which breaks
** its signature, cascading through the entire chain.
**
** Storage: _pqlite_audit_log table with columns:
**   sequence, timestamp, operation, db_name, table_name, rowid,
**   prev_hash (BLOB), entry_hash (BLOB), signature (BLOB)
**
** PQLite is a product of Dyber, Inc.
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_audit.h"
#include "pqc_mem.h"
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static const char *AUDIT_CREATE_SQL =
  "CREATE TABLE IF NOT EXISTS _pqlite_audit_log("
  "  sequence INTEGER PRIMARY KEY,"
  "  timestamp TEXT NOT NULL,"
  "  operation INTEGER NOT NULL,"
  "  db_name TEXT,"
  "  table_name TEXT,"
  "  rowid INTEGER,"
  "  sql_text TEXT,"
  "  prev_hash BLOB NOT NULL,"
  "  entry_hash BLOB NOT NULL,"
  "  signature BLOB NOT NULL"
  ")";

/*
** Compute the hash of an audit entry.
** SHA-256(sequence || timestamp || op || table || rowid || prev_hash)
*/
static int compute_entry_hash(uint64_t sequence, const char *timestamp,
                                int op, const char *table_name,
                                sqlite3_int64 rowid,
                                const uint8_t *prev_hash,
                                uint8_t *out_hash){
  EVP_MD_CTX *ctx;
  unsigned int hash_len = 32;
  uint8_t seq_buf[8];
  uint8_t op_buf[4];
  uint8_t rowid_buf[8];
  int i;

  ctx = EVP_MD_CTX_new();
  if( !ctx ) return PQC_ERROR;

  if( EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ){
    EVP_MD_CTX_free(ctx);
    return PQC_ERROR;
  }

  /* Sequence number (big-endian) */
  for(i = 7; i >= 0; i--){
    seq_buf[7-i] = (uint8_t)((sequence >> (i*8)) & 0xFF);
  }
  EVP_DigestUpdate(ctx, seq_buf, 8);

  /* Timestamp */
  if( timestamp ){
    EVP_DigestUpdate(ctx, timestamp, strlen(timestamp));
  }

  /* Operation */
  op_buf[0] = (uint8_t)((op >> 24) & 0xFF);
  op_buf[1] = (uint8_t)((op >> 16) & 0xFF);
  op_buf[2] = (uint8_t)((op >> 8) & 0xFF);
  op_buf[3] = (uint8_t)(op & 0xFF);
  EVP_DigestUpdate(ctx, op_buf, 4);

  /* Table name */
  if( table_name ){
    EVP_DigestUpdate(ctx, table_name, strlen(table_name));
  }

  /* Rowid */
  for(i = 7; i >= 0; i--){
    rowid_buf[7-i] = (uint8_t)((rowid >> (i*8)) & 0xFF);
  }
  EVP_DigestUpdate(ctx, rowid_buf, 8);

  /* Previous hash (chain link) */
  EVP_DigestUpdate(ctx, prev_hash, 32);

  if( EVP_DigestFinal_ex(ctx, out_hash, &hash_len) != 1 ){
    EVP_MD_CTX_free(ctx);
    return PQC_ERROR;
  }

  EVP_MD_CTX_free(ctx);
  return PQC_OK;
}

/*
** Initialize the audit log.
*/
int pqc_audit_init(PqcAuditLog *log, sqlite3 *db){
  char *err = NULL;
  sqlite3_stmt *stmt = NULL;
  int rc;

  if( !log || !db ) return PQC_ERROR;
  memset(log, 0, sizeof(*log));
  log->db = db;

  /* Create audit table */
  rc = sqlite3_exec(db, AUDIT_CREATE_SQL, NULL, NULL, &err);
  if( rc != SQLITE_OK ){
    sqlite3_free(err);
    return PQC_ERROR;
  }

  /* Generate ML-DSA-65 signing keypair for this session */
  rc = pqc_sig_keygen(PQC_SIG_ML_DSA_65, &log->signing_key);
  if( rc != PQC_OK ) return rc;

  /* Load the last entry's hash to continue the chain */
  rc = sqlite3_prepare_v2(db,
    "SELECT sequence, entry_hash FROM _pqlite_audit_log "
    "ORDER BY sequence DESC LIMIT 1",
    -1, &stmt, NULL);
  if( rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW ){
    log->sequence = (uint64_t)sqlite3_column_int64(stmt, 0);
    const uint8_t *hash = (const uint8_t *)sqlite3_column_blob(stmt, 1);
    if( hash && sqlite3_column_bytes(stmt, 1) == 32 ){
      memcpy(log->prev_hash, hash, 32);
    }
  }else{
    /* First entry — genesis hash is all zeros */
    memset(log->prev_hash, 0, 32);
    log->sequence = 0;
  }
  if( stmt ) sqlite3_finalize(stmt);

  log->enabled = 1;
  return PQC_OK;
}

/*
** Log a DML mutation (INSERT, UPDATE, DELETE).
*/
int pqc_audit_log_mutation(PqcAuditLog *log, PqcAuditOp op,
                             const char *db_name,
                             const char *table_name,
                             sqlite3_int64 rowid){
  sqlite3_stmt *stmt = NULL;
  uint8_t entry_hash[32];
  uint8_t *signature = NULL;
  size_t sig_len;
  const PqcSigInfo *info;
  char timestamp[32];
  time_t now;
  struct tm *tm_info;
  int rc;

  if( !log || !log->enabled ) return PQC_OK;

  /* Skip our own audit table to prevent infinite recursion */
  if( table_name && strcmp(table_name, "_pqlite_audit_log") == 0 ){
    return PQC_OK;
  }

  log->sequence++;

  /* Generate timestamp */
  now = time(NULL);
  tm_info = gmtime(&now);
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);

  /* Compute entry hash (includes prev_hash for chaining) */
  rc = compute_entry_hash(log->sequence, timestamp, (int)op,
                            table_name, rowid,
                            log->prev_hash, entry_hash);
  if( rc != PQC_OK ) return rc;

  /* Sign the entry hash with ML-DSA-65 */
  info = pqc_sig_get_info(PQC_SIG_ML_DSA_65);
  if( !info ) return PQC_ERROR;

  sig_len = info->sig_len;
  signature = (uint8_t *)malloc(sig_len);
  if( !signature ) return PQC_NOMEM;

  rc = pqc_sig_sign(&log->signing_key, entry_hash, 32, signature, &sig_len);
  if( rc != PQC_OK ){
    free(signature);
    return rc;
  }

  /* Insert into audit table */
  rc = sqlite3_prepare_v2(log->db,
    "INSERT INTO _pqlite_audit_log"
    "(sequence, timestamp, operation, db_name, table_name, rowid,"
    " prev_hash, entry_hash, signature)"
    " VALUES(?,?,?,?,?,?,?,?,?)",
    -1, &stmt, NULL);

  if( rc == SQLITE_OK ){
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)log->sequence);
    sqlite3_bind_text(stmt, 2, timestamp, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, (int)op);
    sqlite3_bind_text(stmt, 4, db_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, table_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, rowid);
    sqlite3_bind_blob(stmt, 7, log->prev_hash, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 8, entry_hash, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 9, signature, (int)sig_len, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
  }

  /* Update chain: this entry's hash becomes the next entry's prev_hash */
  memcpy(log->prev_hash, entry_hash, 32);

  free(signature);
  return PQC_OK;
}

/*
** Log a DDL operation.
*/
int pqc_audit_log_ddl(PqcAuditLog *log, PqcAuditOp op,
                        const char *sql_statement){
  /* DDL operations are logged similarly but with sql_text instead of rowid */
  return pqc_audit_log_mutation(log, op, "main", sql_statement, 0);
}

/*
** Verify the entire audit chain.
** Walks through every entry and checks hash chain + ML-DSA signatures.
*/
int pqc_audit_verify_chain(PqcAuditLog *log,
                             int *n_verified, int *n_errors){
  sqlite3_stmt *stmt = NULL;
  uint8_t prev_hash[32];
  uint8_t computed_hash[32];
  int verified = 0, errors = 0;
  int rc;

  if( !log || !log->db ) return PQC_ERROR;
  *n_verified = 0;
  *n_errors = 0;

  memset(prev_hash, 0, 32); /* Genesis hash */

  rc = sqlite3_prepare_v2(log->db,
    "SELECT sequence, timestamp, operation, table_name, rowid,"
    " prev_hash, entry_hash, signature"
    " FROM _pqlite_audit_log ORDER BY sequence ASC",
    -1, &stmt, NULL);
  if( rc != SQLITE_OK ) return PQC_ERROR;

  while( sqlite3_step(stmt) == SQLITE_ROW ){
    uint64_t seq = (uint64_t)sqlite3_column_int64(stmt, 0);
    const char *ts = (const char *)sqlite3_column_text(stmt, 1);
    int op = sqlite3_column_int(stmt, 2);
    const char *tbl = (const char *)sqlite3_column_text(stmt, 3);
    sqlite3_int64 rowid = sqlite3_column_int64(stmt, 4);
    const uint8_t *stored_prev = (const uint8_t *)sqlite3_column_blob(stmt, 5);
    const uint8_t *stored_hash = (const uint8_t *)sqlite3_column_blob(stmt, 6);
    const uint8_t *sig = (const uint8_t *)sqlite3_column_blob(stmt, 7);
    int sig_len = sqlite3_column_bytes(stmt, 7);

    /* 1. Verify prev_hash chain link */
    if( stored_prev && pqc_secure_memcmp(stored_prev, prev_hash, 32) != 0 ){
      errors++;
      continue;
    }

    /* 2. Recompute entry hash and verify */
    compute_entry_hash(seq, ts, op, tbl, rowid, prev_hash, computed_hash);
    if( stored_hash && pqc_secure_memcmp(stored_hash, computed_hash, 32) != 0 ){
      errors++;
      continue;
    }

    /* 3. Verify ML-DSA signature */
    if( sig && sig_len > 0 ){
      rc = pqc_sig_verify(&log->signing_key, stored_hash, 32,
                            sig, (size_t)sig_len);
      if( rc != PQC_OK ){
        errors++;
        continue;
      }
    }

    memcpy(prev_hash, computed_hash, 32);
    verified++;
  }

  sqlite3_finalize(stmt);
  *n_verified = verified;
  *n_errors = errors;

  return (errors == 0) ? PQC_OK : PQC_VERIFY_FAIL;
}

/*
** Export audit signing public key.
*/
int pqc_audit_export_pubkey(const PqcAuditLog *log,
                              uint8_t *buf, size_t *buf_len){
  if( !log || !buf_len ) return PQC_ERROR;
  if( !log->enabled ) return PQC_ERROR;

  if( !buf ){
    *buf_len = log->signing_key.pk_len;
    return PQC_OK;
  }
  if( *buf_len < log->signing_key.pk_len ) return PQC_ERROR;

  memcpy(buf, log->signing_key.public_key, log->signing_key.pk_len);
  *buf_len = log->signing_key.pk_len;
  return PQC_OK;
}

/*
** Free audit log resources.
*/
void pqc_audit_free(PqcAuditLog *log){
  if( !log ) return;
  pqc_sig_keypair_free(&log->signing_key);
  memset(log, 0, sizeof(*log));
}

#endif /* PQLITE_ENABLE_PQC */
