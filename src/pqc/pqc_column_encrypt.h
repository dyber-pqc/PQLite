/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Column-Level Encryption (CLE)
**
** Provides selective encryption of individual columns while leaving
** other columns queryable. This is an enterprise feature that NO
** other SQLite fork offers.
**
** Architecture:
**   - Each encrypted column gets its own column encryption key (CEK)
**   - CEKs are wrapped with the database master key via ML-KEM
**   - Encrypted values stored as BLOBs with format prefix
**   - Deterministic mode available for equality searches on encrypted data
**   - Supports both randomized (IND-CPA secure) and deterministic modes
**
** SQL Interface:
**   CREATE TABLE t(
**     id INTEGER PRIMARY KEY,
**     name TEXT,
**     ssn TEXT ENCRYPTED,                    -- Randomized (default)
**     email TEXT ENCRYPTED DETERMINISTIC,    -- Allows equality search
**     salary REAL ENCRYPTED
**   );
**
** PQLite is a product of Dyber, Inc.
*/
#ifndef PQLITE_PQC_COLUMN_ENCRYPT_H
#define PQLITE_PQC_COLUMN_ENCRYPT_H

#ifdef PQLITE_ENABLE_PQC

#include "pqc_common.h"
#include "pqc_codec.h"
#include <stdint.h>
#include <stddef.h>

/*
** Column encryption modes
*/
typedef enum {
  PQC_CLE_RANDOMIZED    = 0,  /* IND-CPA secure; each encrypt produces unique ciphertext */
  PQC_CLE_DETERMINISTIC = 1,  /* Same plaintext → same ciphertext (enables equality search) */
} PqcCleMode;

/*
** Column Encryption Key (CEK) — one per encrypted column.
*/
typedef struct PqcColumnKey {
  char *table_name;            /* Table this key belongs to */
  char *column_name;           /* Column this key belongs to */
  PqcCleMode mode;             /* Randomized or deterministic */
  uint8_t key[32];             /* AES-256 key material */
  uint8_t hmac_key[32];        /* For deterministic mode: HMAC-based encryption */
  int column_type;             /* SQLITE_INTEGER, SQLITE_FLOAT, SQLITE_TEXT, SQLITE_BLOB */
} PqcColumnKey;

/*
** Column Encryption Catalog — stored in _pqlite_column_keys table.
*/
typedef struct PqcColumnCatalog {
  PqcColumnKey *keys;          /* Array of column keys */
  int n_keys;                  /* Number of keys */
  int n_alloc;                 /* Allocated slots */
} PqcColumnCatalog;

/*
** Encrypted value format (stored as BLOB):
**   [1 byte: version (0x01)]
**   [1 byte: mode (0=randomized, 1=deterministic)]
**   [1 byte: original type (INTEGER/FLOAT/TEXT/BLOB)]
**   [1 byte: reserved]
**   [12 bytes: IV (randomized) or 0 (deterministic)]
**   [N bytes: AES-256-GCM ciphertext]
**   [16 bytes: GCM authentication tag]
*/
#define PQC_CLE_HEADER_SIZE  16  /* version + mode + type + reserved + IV */
#define PQC_CLE_TAG_SIZE     16  /* GCM auth tag */
#define PQC_CLE_VERSION      0x01

/*
** Initialize the column encryption catalog for a database.
** Creates the _pqlite_column_keys metadata table if not present.
*/
int pqc_cle_init(sqlite3 *db, PqcCodec *codec, PqcColumnCatalog *catalog);

/*
** Register a column for encryption.
** Generates a new CEK and stores it (wrapped) in the catalog table.
*/
int pqc_cle_register_column(PqcColumnCatalog *catalog, PqcCodec *codec,
                              const char *table_name,
                              const char *column_name,
                              PqcCleMode mode, int column_type);

/*
** Look up the encryption key for a specific column.
** Returns NULL if column is not encrypted.
*/
const PqcColumnKey *pqc_cle_get_key(const PqcColumnCatalog *catalog,
                                      const char *table_name,
                                      const char *column_name);

/*
** Encrypt a value for storage.
** Input: plaintext value (any SQLite type)
** Output: encrypted BLOB with PQC_CLE format header
*/
int pqc_cle_encrypt_value(const PqcColumnKey *ck,
                            const void *plaintext, int pt_len,
                            void **ciphertext, int *ct_len);

/*
** Decrypt a stored encrypted BLOB back to its original type.
*/
int pqc_cle_decrypt_value(const PqcColumnKey *ck,
                            const void *ciphertext, int ct_len,
                            void **plaintext, int *pt_len,
                            int *original_type);

/*
** Compute a searchable token for deterministic mode.
** For WHERE col = 'value' queries on deterministic columns,
** the query planner calls this to produce the search token.
*/
int pqc_cle_compute_search_token(const PqcColumnKey *ck,
                                   const void *plaintext, int pt_len,
                                   void **token, int *token_len);

/*
** Free the column encryption catalog.
*/
void pqc_cle_catalog_free(PqcColumnCatalog *catalog);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_COLUMN_ENCRYPT_H */
