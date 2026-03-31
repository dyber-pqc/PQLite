/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** PQLite Encryption Codec
**
** Page-level Transparent Database Encryption (TDE) using a hybrid
** post-quantum + classical key hierarchy:
**
**   Password → PBKDF2-HMAC-SHA-512 → Master Key (32 bytes)
**            → ML-KEM encapsulate   → KEM Shared Secret
**            → HKDF-SHA-256         → Per-Page AES-256-GCM Keys
**
** Each page is encrypted independently with AES-256-GCM providing
** both confidentiality and authenticated encryption (tamper detection).
**
** PQLite is a product of Dyber, Inc.
*/
#ifndef PQLITE_PQC_CODEC_H
#define PQLITE_PQC_CODEC_H

#ifdef PQLITE_ENABLE_PQC

#include "pqc_common.h"
#include "pqc_kem.h"
#include <stdint.h>
#include <stddef.h>

/*
** PQLite database header magic bytes (stored at offset 24 of page 1)
*/
#define PQLITE_MAGIC        "PQLite\x01\x00"
#define PQLITE_MAGIC_LEN    8

/*
** Header layout within page 1 reserved area (after SQLite's 100-byte header).
** We use the "reserved space at end of each page" mechanism.
*/
#define PQLITE_HDR_OFFSET       100  /* Start after SQLite header */
#define PQLITE_HDR_MAGIC_OFF    0    /* 8 bytes: magic */
#define PQLITE_HDR_VERSION_OFF  8    /* 4 bytes: PQLite version */
#define PQLITE_HDR_FLAGS_OFF    12   /* 4 bytes: feature flags */
#define PQLITE_HDR_SALT_OFF     16   /* 16 bytes: PBKDF2 salt */
#define PQLITE_HDR_KEM_ALG_OFF  32   /* 4 bytes: KEM algorithm ID */
#define PQLITE_HDR_ITER_OFF     36   /* 4 bytes: PBKDF2 iterations */
#define PQLITE_HDR_CT_LEN_OFF   40   /* 4 bytes: KEM ciphertext length */
#define PQLITE_HDR_CT_OFF       44   /* Variable: KEM ciphertext */

/* Feature flags */
#define PQLITE_FLAG_ENCRYPTED      0x00000001
#define PQLITE_FLAG_HMAC_PAGES     0x00000002
#define PQLITE_FLAG_WAL_SIGNED     0x00000004

/* Default PBKDF2 iterations */
#define PQLITE_DEFAULT_PBKDF2_ITER 256000

/* Reserved bytes per page for HMAC (32 bytes for HMAC-SHA-256) + GCM tag (16) */
#define PQLITE_RESERVED_PER_PAGE   48

/*
** Encryption context — attached to each open database connection.
** Contains all derived key material needed for page encrypt/decrypt.
*/
typedef struct PqcCodec {
  /* State */
  int is_encrypted;              /* Non-zero if database is encrypted */
  int page_size;                 /* Database page size (e.g., 4096) */

  /* Algorithm selection */
  PqcKemAlgorithm kem_alg;      /* Which ML-KEM variant */

  /* Key material (all in secure memory) */
  uint8_t master_key[32];        /* PBKDF2-derived master key */
  uint8_t shared_secret[32];     /* KEM shared secret */
  uint8_t page_key[32];          /* HKDF-derived base page encryption key */
  uint8_t hmac_key[32];          /* HKDF-derived HMAC key */

  /* Header data */
  uint8_t salt[16];              /* PBKDF2 salt */
  uint32_t pbkdf2_iter;          /* PBKDF2 iteration count */
  uint8_t *kem_ciphertext;       /* KEM ciphertext (variable length) */
  size_t kem_ct_len;             /* KEM ciphertext length */

  /* KEM keypair (for rekey operations) */
  PqcKemKeypair kem_kp;

  /* Scratch buffer for encryption (one page) */
  uint8_t *scratch;
} PqcCodec;

/*
** Create a new codec context for an encrypted database.
** This is called when PRAGMA pqc_key is set.
**
** @param page_size   Database page size
** @param kem_alg     KEM algorithm to use
** @return New codec context, or NULL on failure
*/
PqcCodec *pqc_codec_new(int page_size, PqcKemAlgorithm kem_alg);

/*
** Initialize encryption for a new database (first-time setup).
** Generates salt, derives master key from password, generates KEM
** keypair, encapsulates to get shared secret, derives page keys.
**
** @param codec       Codec context
** @param password    User password (UTF-8)
** @param pw_len      Password length
** @return PQC_OK on success
*/
int pqc_codec_init_new(PqcCodec *codec,
                        const char *password, int pw_len);

/*
** Initialize encryption for an existing database.
** Reads header from page 1, derives master key from password,
** decapsulates KEM ciphertext to recover shared secret, derives page keys.
**
** @param codec       Codec context
** @param password    User password
** @param pw_len      Password length
** @param header      Database page 1 (contains PQLite header)
** @param header_len  Length of header data
** @return PQC_OK on success, PQC_DECRYPT_FAIL on wrong password
*/
int pqc_codec_init_existing(PqcCodec *codec,
                              const char *password, int pw_len,
                              const uint8_t *header, int header_len);

/*
** Initialize with a raw 32-byte key (skip PBKDF2).
*/
int pqc_codec_init_raw_key(PqcCodec *codec,
                             const uint8_t *raw_key, int key_len,
                             const uint8_t *header, int header_len);

/*
** Encrypt a database page in-place.
** Uses AES-256-GCM with a per-page IV derived from page number + salt.
**
** @param codec       Codec context
** @param pgno        Page number (1-based)
** @param data        Page data buffer (page_size bytes)
** @param n           Number of usable bytes in the page
** @return PQC_OK on success
*/
int pqc_codec_encrypt_page(PqcCodec *codec, uint32_t pgno,
                             uint8_t *data, int n);

/*
** Decrypt a database page in-place.
**
** @param codec       Codec context
** @param pgno        Page number
** @param data        Encrypted page data
** @param n           Number of bytes
** @return PQC_OK on success, PQC_DECRYPT_FAIL on authentication failure
*/
int pqc_codec_decrypt_page(PqcCodec *codec, uint32_t pgno,
                             uint8_t *data, int n);

/*
** Write the PQLite header into page 1.
** Must be called after pqc_codec_init_new to persist the
** encryption metadata (salt, KEM ciphertext, etc.).
**
** @param codec       Codec context
** @param page1       Page 1 buffer (at least page_size bytes)
** @return PQC_OK on success
*/
int pqc_codec_write_header(PqcCodec *codec, uint8_t *page1);

/*
** Re-encrypt the database with a new password (PRAGMA pqc_rekey).
** Derives a new master key, generates new KEM keypair, re-encapsulates.
**
** @param codec       Codec context
** @param new_password New password
** @param new_pw_len   New password length
** @return PQC_OK on success
*/
int pqc_codec_rekey(PqcCodec *codec,
                      const char *new_password, int new_pw_len);

/*
** Check if a database page 1 looks like a PQLite-encrypted database.
*/
int pqc_codec_is_pqlite(const uint8_t *page1, int page_size);

/*
** Free the codec context and wipe all key material.
*/
void pqc_codec_free(PqcCodec *codec);

/*
** Compute HMAC-SHA-256 over a page for integrity verification.
*/
int pqc_codec_compute_hmac(PqcCodec *codec, uint32_t pgno,
                             const uint8_t *data, int n,
                             uint8_t *hmac_out);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_CODEC_H */
