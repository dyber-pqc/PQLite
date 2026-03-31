/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** PQLite Database Integrity Verification — Implementation
**
** Page-level HMAC verification and whole-database ML-DSA signatures.
** Uses OpenSSL for SHA-256 hashing and the PQC signature module
** for post-quantum digital signatures.
**
** PQLite is a product of Dyber, Inc.
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_integrity.h"
#include "pqc_mem.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
** Verify a page's HMAC against an expected value.
** Uses constant-time comparison to prevent timing attacks.
*/
int pqc_integrity_verify_page(PqcCodec *codec, uint32_t pgno,
                                const uint8_t *data, int data_len,
                                const uint8_t *expected_hmac){
  uint8_t computed_hmac[32];
  int rc;

  if( codec == NULL || data == NULL || expected_hmac == NULL ){
    return PQC_ERROR;
  }

  rc = pqc_codec_compute_hmac(codec, pgno, data, data_len, computed_hmac);
  if( rc != PQC_OK ) return rc;

  /* Constant-time comparison to prevent timing side-channels */
  if( pqc_secure_memcmp(computed_hmac, expected_hmac, 32) != 0 ){
    pqc_secure_wipe(computed_hmac, sizeof(computed_hmac));
    return PQC_VERIFY_FAIL;
  }

  pqc_secure_wipe(computed_hmac, sizeof(computed_hmac));
  return PQC_OK;
}

/*
** Sign an entire database by computing SHA-256 over all pages,
** then applying ML-DSA signature to the hash.
**
** This provides a whole-database integrity guarantee that can be
** verified independently (e.g., for backup verification, distribution).
*/
int pqc_integrity_sign_database(const char *db_path,
                                  const PqcSigKeypair *kp,
                                  uint8_t *signature, size_t *sig_len){
  FILE *fp = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  uint8_t buf[4096];
  uint8_t hash[32];
  unsigned int hash_len = 32;
  size_t n;
  int rc = PQC_ERROR;

  if( db_path == NULL || kp == NULL || signature == NULL || sig_len == NULL ){
    return PQC_ERROR;
  }

  fp = fopen(db_path, "rb");
  if( fp == NULL ) return PQC_ERROR;

  md_ctx = EVP_MD_CTX_new();
  if( md_ctx == NULL ){ fclose(fp); return PQC_ERROR; }

  if( EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ) goto done;

  /* Hash the entire database file */
  while( (n = fread(buf, 1, sizeof(buf), fp)) > 0 ){
    if( EVP_DigestUpdate(md_ctx, buf, n) != 1 ) goto done;
  }

  if( EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1 ) goto done;

  /* Sign the hash with ML-DSA */
  rc = pqc_sig_sign(kp, hash, hash_len, signature, sig_len);

done:
  pqc_secure_wipe(hash, sizeof(hash));
  if( md_ctx ) EVP_MD_CTX_free(md_ctx);
  if( fp ) fclose(fp);
  return rc;
}

/*
** Verify an ML-DSA signature over an entire database.
*/
int pqc_integrity_verify_database(const char *db_path,
                                    const PqcSigKeypair *kp,
                                    const uint8_t *signature, size_t sig_len){
  FILE *fp = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  uint8_t buf[4096];
  uint8_t hash[32];
  unsigned int hash_len = 32;
  size_t n;
  int rc = PQC_ERROR;

  if( db_path == NULL || kp == NULL || signature == NULL ) return PQC_ERROR;

  fp = fopen(db_path, "rb");
  if( fp == NULL ) return PQC_ERROR;

  md_ctx = EVP_MD_CTX_new();
  if( md_ctx == NULL ){ fclose(fp); return PQC_ERROR; }

  if( EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ) goto done;

  while( (n = fread(buf, 1, sizeof(buf), fp)) > 0 ){
    if( EVP_DigestUpdate(md_ctx, buf, n) != 1 ) goto done;
  }

  if( EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1 ) goto done;

  /* Verify the ML-DSA signature */
  rc = pqc_sig_verify(kp, hash, hash_len, signature, sig_len);

done:
  pqc_secure_wipe(hash, sizeof(hash));
  if( md_ctx ) EVP_MD_CTX_free(md_ctx);
  if( fp ) fclose(fp);
  return rc;
}

#endif /* PQLITE_ENABLE_PQC */
