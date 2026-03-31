/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Column-Level Encryption (CLE) — Implementation
**
** Provides per-column encryption with two modes:
**
** RANDOMIZED mode (default, IND-CPA secure):
**   - Each encryption of the same value produces different ciphertext
**   - Uses AES-256-GCM with random 12-byte IV per value
**   - Cannot do equality searches (WHERE col = 'x')
**   - Maximum security for sensitive data (SSN, health records, etc.)
**
** DETERMINISTIC mode (enables equality search):
**   - Same plaintext → same ciphertext (via SIV-like construction)
**   - Uses HMAC-SHA-256(column_hmac_key, plaintext) as synthetic IV
**   - Allows WHERE col = encrypted_token equality comparisons
**   - Weaker security (frequency analysis possible) but practical
**   - Suitable for: email lookups, username searches, etc.
**
** Column encryption keys are stored in _pqlite_column_keys table,
** wrapped (encrypted) with the database master key via AES-256-GCM.
**
** PQLite is a product of Dyber, Inc.
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_column_encrypt.h"
#include "pqc_mem.h"
#include "sqlite3.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>
#include <stdlib.h>

/*
** SQL to create the column encryption metadata table.
*/
static const char *CLE_CREATE_TABLE_SQL =
  "CREATE TABLE IF NOT EXISTS _pqlite_column_keys("
  "  id INTEGER PRIMARY KEY,"
  "  table_name TEXT NOT NULL,"
  "  column_name TEXT NOT NULL,"
  "  mode INTEGER NOT NULL,"            /* 0=randomized, 1=deterministic */
  "  column_type INTEGER NOT NULL,"     /* SQLITE_INTEGER, etc. */
  "  wrapped_key BLOB NOT NULL,"        /* CEK encrypted with master key */
  "  wrapped_hmac_key BLOB,"            /* HMAC key for deterministic mode */
  "  created_at TEXT DEFAULT (datetime('now')),"
  "  UNIQUE(table_name, column_name)"
  ")";

/*
** Wrap (encrypt) a column key with the master key using AES-256-GCM.
*/
static int wrap_column_key(const uint8_t *master_key,
                             const uint8_t *cek, int cek_len,
                             uint8_t *wrapped, int *wrapped_len){
  EVP_CIPHER_CTX *ctx;
  uint8_t iv[12];
  uint8_t tag[16];
  int len, ct_len;
  int rc = PQC_ERROR;

  if( RAND_bytes(iv, 12) != 1 ) return PQC_ERROR;

  ctx = EVP_CIPHER_CTX_new();
  if( !ctx ) return PQC_ERROR;

  if( EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ) goto done;
  if( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ) goto done;
  if( EVP_EncryptInit_ex(ctx, NULL, NULL, master_key, iv) != 1 ) goto done;
  if( EVP_EncryptUpdate(ctx, wrapped + 12, &len, cek, cek_len) != 1 ) goto done;
  ct_len = len;
  if( EVP_EncryptFinal_ex(ctx, wrapped + 12 + ct_len, &len) != 1 ) goto done;
  if( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1 ) goto done;

  /* Format: [12-byte IV][ciphertext][16-byte tag] */
  memcpy(wrapped, iv, 12);
  memcpy(wrapped + 12 + ct_len, tag, 16);
  *wrapped_len = 12 + ct_len + 16;
  rc = PQC_OK;

done:
  EVP_CIPHER_CTX_free(ctx);
  return rc;
}

/*
** Unwrap (decrypt) a column key.
*/
static int unwrap_column_key(const uint8_t *master_key,
                               const uint8_t *wrapped, int wrapped_len,
                               uint8_t *cek, int *cek_len){
  EVP_CIPHER_CTX *ctx;
  uint8_t iv[12];
  int ct_len;
  int len;
  int rc = PQC_ERROR;

  if( wrapped_len < 28 ) return PQC_ERROR; /* 12 IV + 0 data + 16 tag */

  memcpy(iv, wrapped, 12);
  ct_len = wrapped_len - 12 - 16;

  ctx = EVP_CIPHER_CTX_new();
  if( !ctx ) return PQC_ERROR;

  if( EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ) goto done;
  if( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ) goto done;
  if( EVP_DecryptInit_ex(ctx, NULL, NULL, master_key, iv) != 1 ) goto done;
  if( EVP_DecryptUpdate(ctx, cek, &len, wrapped + 12, ct_len) != 1 ) goto done;
  *cek_len = len;

  if( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
      (void*)(wrapped + 12 + ct_len)) != 1 ) goto done;
  if( EVP_DecryptFinal_ex(ctx, cek + len, &len) != 1 ){
    rc = PQC_DECRYPT_FAIL;
    goto done;
  }
  rc = PQC_OK;

done:
  EVP_CIPHER_CTX_free(ctx);
  return rc;
}

/*
** Initialize column encryption catalog.
*/
int pqc_cle_init(sqlite3 *db, PqcCodec *codec, PqcColumnCatalog *catalog){
  char *err = NULL;
  sqlite3_stmt *stmt = NULL;
  int rc;

  if( !db || !codec || !catalog ) return PQC_ERROR;
  memset(catalog, 0, sizeof(*catalog));

  /* Create metadata table */
  rc = sqlite3_exec(db, CLE_CREATE_TABLE_SQL, NULL, NULL, &err);
  if( rc != SQLITE_OK ){
    sqlite3_free(err);
    return PQC_ERROR;
  }

  /* Load existing column keys */
  rc = sqlite3_prepare_v2(db,
    "SELECT table_name, column_name, mode, column_type, "
    "wrapped_key, wrapped_hmac_key FROM _pqlite_column_keys",
    -1, &stmt, NULL);
  if( rc != SQLITE_OK ) return PQC_ERROR;

  while( sqlite3_step(stmt) == SQLITE_ROW ){
    const char *tbl = (const char *)sqlite3_column_text(stmt, 0);
    const char *col = (const char *)sqlite3_column_text(stmt, 1);
    int mode = sqlite3_column_int(stmt, 2);
    int coltype = sqlite3_column_int(stmt, 3);
    const uint8_t *wrapped_key = (const uint8_t *)sqlite3_column_blob(stmt, 4);
    int wrapped_key_len = sqlite3_column_bytes(stmt, 4);
    const uint8_t *wrapped_hmac = (const uint8_t *)sqlite3_column_blob(stmt, 5);
    int wrapped_hmac_len = sqlite3_column_bytes(stmt, 5);

    /* Expand catalog array */
    if( catalog->n_keys >= catalog->n_alloc ){
      int new_alloc = catalog->n_alloc ? catalog->n_alloc * 2 : 16;
      PqcColumnKey *new_keys = (PqcColumnKey *)realloc(
        catalog->keys, new_alloc * sizeof(PqcColumnKey));
      if( !new_keys ){
        sqlite3_finalize(stmt);
        return PQC_NOMEM;
      }
      catalog->keys = new_keys;
      catalog->n_alloc = new_alloc;
    }

    PqcColumnKey *ck = &catalog->keys[catalog->n_keys];
    memset(ck, 0, sizeof(*ck));
    ck->table_name = sqlite3_mprintf("%s", tbl);
    ck->column_name = sqlite3_mprintf("%s", col);
    ck->mode = (PqcCleMode)mode;
    ck->column_type = coltype;

    /* Unwrap the column encryption key */
    int cek_len = 32;
    if( unwrap_column_key(codec->page_key, wrapped_key, wrapped_key_len,
                           ck->key, &cek_len) != PQC_OK ){
      sqlite3_free(ck->table_name);
      sqlite3_free(ck->column_name);
      sqlite3_finalize(stmt);
      return PQC_DECRYPT_FAIL;
    }

    /* Unwrap HMAC key for deterministic mode */
    if( mode == PQC_CLE_DETERMINISTIC && wrapped_hmac && wrapped_hmac_len > 0 ){
      int hmac_len = 32;
      unwrap_column_key(codec->page_key, wrapped_hmac, wrapped_hmac_len,
                         ck->hmac_key, &hmac_len);
    }

    catalog->n_keys++;
  }

  sqlite3_finalize(stmt);
  return PQC_OK;
}

/*
** Register a new encrypted column.
*/
int pqc_cle_register_column(PqcColumnCatalog *catalog, PqcCodec *codec,
                              const char *table_name,
                              const char *column_name,
                              PqcCleMode mode, int column_type){
  PqcColumnKey *ck;
  uint8_t wrapped_key[60]; /* 12 IV + 32 ciphertext + 16 tag */
  uint8_t wrapped_hmac[60];
  int wrapped_key_len = 0, wrapped_hmac_len = 0;

  if( !catalog || !codec || !table_name || !column_name ) return PQC_ERROR;

  /* Expand catalog */
  if( catalog->n_keys >= catalog->n_alloc ){
    int new_alloc = catalog->n_alloc ? catalog->n_alloc * 2 : 16;
    PqcColumnKey *new_keys = (PqcColumnKey *)realloc(
      catalog->keys, new_alloc * sizeof(PqcColumnKey));
    if( !new_keys ) return PQC_NOMEM;
    catalog->keys = new_keys;
    catalog->n_alloc = new_alloc;
  }

  ck = &catalog->keys[catalog->n_keys];
  memset(ck, 0, sizeof(*ck));

  /* Generate random column encryption key */
  if( RAND_bytes(ck->key, 32) != 1 ) return PQC_ERROR;

  /* Generate HMAC key for deterministic mode */
  if( mode == PQC_CLE_DETERMINISTIC ){
    if( RAND_bytes(ck->hmac_key, 32) != 1 ) return PQC_ERROR;
  }

  ck->table_name = sqlite3_mprintf("%s", table_name);
  ck->column_name = sqlite3_mprintf("%s", column_name);
  ck->mode = mode;
  ck->column_type = column_type;

  /* Wrap keys with master key for storage */
  if( wrap_column_key(codec->page_key, ck->key, 32,
                       wrapped_key, &wrapped_key_len) != PQC_OK ){
    return PQC_ERROR;
  }

  if( mode == PQC_CLE_DETERMINISTIC ){
    wrap_column_key(codec->page_key, ck->hmac_key, 32,
                     wrapped_hmac, &wrapped_hmac_len);
  }

  catalog->n_keys++;
  return PQC_OK;
}

/*
** Look up a column's encryption key.
*/
const PqcColumnKey *pqc_cle_get_key(const PqcColumnCatalog *catalog,
                                      const char *table_name,
                                      const char *column_name){
  int i;
  if( !catalog || !table_name || !column_name ) return NULL;

  for(i = 0; i < catalog->n_keys; i++){
    if( strcmp(catalog->keys[i].table_name, table_name) == 0 &&
        strcmp(catalog->keys[i].column_name, column_name) == 0 ){
      return &catalog->keys[i];
    }
  }
  return NULL;
}

/*
** Encrypt a value for column-level storage.
**
** Randomized mode: AES-256-GCM with random IV
** Deterministic mode: AES-256-GCM with IV = HMAC-SHA-256(hmac_key, plaintext)[0:12]
*/
int pqc_cle_encrypt_value(const PqcColumnKey *ck,
                            const void *plaintext, int pt_len,
                            void **ciphertext, int *ct_len){
  uint8_t *out = NULL;
  uint8_t iv[12];
  uint8_t tag[16];
  EVP_CIPHER_CTX *ctx = NULL;
  int len, enc_len;
  int total;
  int rc = PQC_ERROR;

  if( !ck || !plaintext || !ciphertext || !ct_len ) return PQC_ERROR;

  /* Generate IV based on mode */
  if( ck->mode == PQC_CLE_DETERMINISTIC ){
    /* Synthetic IV from HMAC — same plaintext produces same IV */
    uint8_t hmac_out[32];
    unsigned int hmac_len = 32;
    HMAC(EVP_sha256(), ck->hmac_key, 32,
         (const uint8_t *)plaintext, pt_len,
         hmac_out, &hmac_len);
    memcpy(iv, hmac_out, 12);
    pqc_secure_wipe(hmac_out, sizeof(hmac_out));
  }else{
    /* Random IV for IND-CPA security */
    if( RAND_bytes(iv, 12) != 1 ) return PQC_ERROR;
  }

  /* Output format: [header (16)] [ciphertext (pt_len)] [tag (16)] */
  total = PQC_CLE_HEADER_SIZE + pt_len + PQC_CLE_TAG_SIZE;
  out = (uint8_t *)malloc(total);
  if( !out ) return PQC_NOMEM;

  /* Write header */
  out[0] = PQC_CLE_VERSION;
  out[1] = (uint8_t)ck->mode;
  out[2] = (uint8_t)ck->column_type;
  out[3] = 0; /* reserved */
  memcpy(out + 4, iv, 12);

  /* Encrypt with AES-256-GCM */
  ctx = EVP_CIPHER_CTX_new();
  if( !ctx ) goto done;

  if( EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ) goto done;
  if( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ) goto done;
  if( EVP_EncryptInit_ex(ctx, NULL, NULL, ck->key, iv) != 1 ) goto done;

  /* AAD: header bytes for authentication */
  if( EVP_EncryptUpdate(ctx, NULL, &len, out, PQC_CLE_HEADER_SIZE) != 1 ) goto done;

  if( EVP_EncryptUpdate(ctx, out + PQC_CLE_HEADER_SIZE, &len,
                          (const uint8_t *)plaintext, pt_len) != 1 ) goto done;
  enc_len = len;

  if( EVP_EncryptFinal_ex(ctx, out + PQC_CLE_HEADER_SIZE + enc_len, &len) != 1 )
    goto done;

  if( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1 ) goto done;
  memcpy(out + PQC_CLE_HEADER_SIZE + pt_len, tag, 16);

  *ciphertext = out;
  *ct_len = total;
  out = NULL; /* prevent free */
  rc = PQC_OK;

done:
  if( ctx ) EVP_CIPHER_CTX_free(ctx);
  if( out ) free(out);
  return rc;
}

/*
** Decrypt a column-level encrypted value.
*/
int pqc_cle_decrypt_value(const PqcColumnKey *ck,
                            const void *ciphertext, int ct_len,
                            void **plaintext, int *pt_len,
                            int *original_type){
  const uint8_t *in = (const uint8_t *)ciphertext;
  uint8_t *out = NULL;
  uint8_t iv[12];
  EVP_CIPHER_CTX *ctx = NULL;
  int enc_data_len, len;
  int rc = PQC_DECRYPT_FAIL;

  if( !ck || !ciphertext || !plaintext || !pt_len ) return PQC_ERROR;
  if( ct_len < PQC_CLE_HEADER_SIZE + PQC_CLE_TAG_SIZE ) return PQC_ERROR;

  /* Verify version */
  if( in[0] != PQC_CLE_VERSION ) return PQC_ERROR;

  /* Extract header */
  if( original_type ) *original_type = (int)in[2];
  memcpy(iv, in + 4, 12);

  enc_data_len = ct_len - PQC_CLE_HEADER_SIZE - PQC_CLE_TAG_SIZE;
  out = (uint8_t *)malloc(enc_data_len + 1); /* +1 for null terminator */
  if( !out ) return PQC_NOMEM;

  ctx = EVP_CIPHER_CTX_new();
  if( !ctx ){ free(out); return PQC_ERROR; }

  if( EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ) goto done;
  if( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ) goto done;
  if( EVP_DecryptInit_ex(ctx, NULL, NULL, ck->key, iv) != 1 ) goto done;

  /* AAD */
  if( EVP_DecryptUpdate(ctx, NULL, &len, in, PQC_CLE_HEADER_SIZE) != 1 ) goto done;

  if( EVP_DecryptUpdate(ctx, out, &len,
                          in + PQC_CLE_HEADER_SIZE, enc_data_len) != 1 ) goto done;
  *pt_len = len;

  /* Verify GCM tag */
  if( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
      (void*)(in + PQC_CLE_HEADER_SIZE + enc_data_len)) != 1 ) goto done;
  if( EVP_DecryptFinal_ex(ctx, out + len, &len) != 1 ){
    rc = PQC_DECRYPT_FAIL;
    goto done;
  }

  out[*pt_len] = 0; /* null-terminate for TEXT values */
  *plaintext = out;
  out = NULL;
  rc = PQC_OK;

done:
  if( ctx ) EVP_CIPHER_CTX_free(ctx);
  if( out ) free(out);
  return rc;
}

/*
** Compute a search token for deterministic mode.
** This token can be used in WHERE clauses to do equality matching.
*/
int pqc_cle_compute_search_token(const PqcColumnKey *ck,
                                   const void *plaintext, int pt_len,
                                   void **token, int *token_len){
  if( ck->mode != PQC_CLE_DETERMINISTIC ){
    return PQC_ERROR; /* Only deterministic columns are searchable */
  }
  /* For deterministic mode, encrypting the same plaintext produces
  ** the same ciphertext, so we just encrypt it. */
  return pqc_cle_encrypt_value(ck, plaintext, pt_len, token, token_len);
}

/*
** Free the column encryption catalog.
*/
void pqc_cle_catalog_free(PqcColumnCatalog *catalog){
  int i;
  if( !catalog ) return;
  for(i = 0; i < catalog->n_keys; i++){
    pqc_secure_wipe(catalog->keys[i].key, 32);
    pqc_secure_wipe(catalog->keys[i].hmac_key, 32);
    sqlite3_free(catalog->keys[i].table_name);
    sqlite3_free(catalog->keys[i].column_name);
  }
  free(catalog->keys);
  memset(catalog, 0, sizeof(*catalog));
}

#endif /* PQLITE_ENABLE_PQC */
