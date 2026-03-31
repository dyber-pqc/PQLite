/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Encrypted Backup & Restore with PQC Signing
**
** Creates ML-KEM-encrypted and ML-DSA-signed backup files.
** Backup format:
**   [Header: magic, version, KEM algorithm, SIG algorithm]
**   [KEM ciphertext (wraps the backup encryption key)]
**   [ML-DSA public key (for verification)]
**   [AES-256-GCM encrypted database pages]
**   [ML-DSA signature over entire backup]
**
** Supports:
**   - Full database backup with encryption
**   - Incremental backup of changed pages
**   - Signature verification before restore
**   - Key-independent backup (recipient's public key)
**
** SQL Interface:
**   SELECT pqc_backup('encrypted_backup.pqlbak', 'password');
**   SELECT pqc_restore('encrypted_backup.pqlbak', 'password');
**   SELECT pqc_backup_verify('encrypted_backup.pqlbak');
**
** PQLite is a product of Dyber, Inc.
*/
#ifndef PQLITE_PQC_BACKUP_H
#define PQLITE_PQC_BACKUP_H

#ifdef PQLITE_ENABLE_PQC

#include "pqc_common.h"
#include "pqc_kem.h"
#include "pqc_sig.h"
#include "sqlite3.h"

#define PQLITE_BACKUP_MAGIC "PQLBAK01"
#define PQLITE_BACKUP_MAGIC_LEN 8

/*
** Backup options
*/
typedef struct PqcBackupOptions {
  PqcKemAlgorithm kem_alg;       /* KEM for key wrapping (default: ML-KEM-768) */
  PqcSigAlgorithm sig_alg;       /* Signature algorithm (default: ML-DSA-65) */
  const char *password;           /* Password for key derivation */
  int password_len;
  const uint8_t *recipient_pk;   /* Optional: recipient's ML-KEM public key */
  size_t recipient_pk_len;
  int compress;                   /* Enable compression before encryption */
} PqcBackupOptions;

/*
** Create an encrypted, signed backup of the database.
**
** @param db          Source database
** @param backup_path Output backup file path
** @param opts        Backup options
** @return PQC_OK on success
*/
int pqc_backup_create(sqlite3 *db, const char *backup_path,
                        const PqcBackupOptions *opts);

/*
** Restore a database from an encrypted backup.
** Verifies the ML-DSA signature before restoring.
**
** @param db           Target database
** @param backup_path  Backup file path
** @param password     Decryption password
** @param pw_len       Password length
** @return PQC_OK on success, PQC_VERIFY_FAIL if signature invalid
*/
int pqc_backup_restore(sqlite3 *db, const char *backup_path,
                          const char *password, int pw_len);

/*
** Verify a backup file's ML-DSA signature without restoring.
**
** @param backup_path  Path to the backup file
** @return PQC_OK if signature valid, PQC_VERIFY_FAIL if not
*/
int pqc_backup_verify(const char *backup_path);

/*
** Get backup file metadata (algorithm, creation time, page count).
** Returns JSON string. Caller must sqlite3_free().
*/
char *pqc_backup_info(const char *backup_path);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_BACKUP_H */
