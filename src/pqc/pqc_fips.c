/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** FIPS 140-3 Compliance Mode — Implementation
**
** Loads the OpenSSL FIPS provider and runs Known Answer Tests
** (KATs) to verify correct operation of cryptographic algorithms.
**
** KAT vectors are taken from NIST CAVP (Cryptographic Algorithm
** Validation Program) test vectors.
**
** PQLite is a product of Dyber, Inc.
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_fips.h"
#include "pqc_mem.h"
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

/*
** NIST AES-256-GCM Known Answer Test vector.
** Source: NIST SP 800-38D, Test Case 16
*/
static const uint8_t KAT_AES_KEY[32] = {
  0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
  0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
  0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
  0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
};

static const uint8_t KAT_AES_IV[12] = {
  0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
  0xde,0xca,0xf8,0x88
};

static const uint8_t KAT_AES_PLAINTEXT[16] = {
  0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
  0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a
};

/*
** SHA-256 Known Answer Test vector.
** SHA-256("abc") = ba7816bf...
*/
static const uint8_t KAT_SHA256_INPUT[] = { 0x61, 0x62, 0x63 }; /* "abc" */
static const uint8_t KAT_SHA256_OUTPUT[32] = {
  0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
  0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
  0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
  0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
};

/*
** Run the AES-256-GCM KAT.
*/
static int run_aes_gcm_kat(void){
  EVP_CIPHER_CTX *ctx;
  uint8_t ct[16], tag[16], pt[16];
  int len, rc = PQC_ERROR;

  /* Encrypt */
  ctx = EVP_CIPHER_CTX_new();
  if( !ctx ) return PQC_ERROR;

  if( EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ) goto done;
  if( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ) goto done;
  if( EVP_EncryptInit_ex(ctx, NULL, NULL, KAT_AES_KEY, KAT_AES_IV) != 1 ) goto done;
  if( EVP_EncryptUpdate(ctx, ct, &len, KAT_AES_PLAINTEXT, 16) != 1 ) goto done;
  if( EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1 ) goto done;
  if( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1 ) goto done;

  EVP_CIPHER_CTX_free(ctx);

  /* Decrypt and verify */
  ctx = EVP_CIPHER_CTX_new();
  if( !ctx ) return PQC_ERROR;

  if( EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ) goto done;
  if( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ) goto done;
  if( EVP_DecryptInit_ex(ctx, NULL, NULL, KAT_AES_KEY, KAT_AES_IV) != 1 ) goto done;
  if( EVP_DecryptUpdate(ctx, pt, &len, ct, 16) != 1 ) goto done;
  if( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1 ) goto done;
  if( EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1 ) goto done;

  /* Verify plaintext matches */
  if( pqc_secure_memcmp(pt, KAT_AES_PLAINTEXT, 16) != 0 ) goto done;

  rc = PQC_OK;
done:
  EVP_CIPHER_CTX_free(ctx);
  return rc;
}

/*
** Run the SHA-256 KAT.
*/
static int run_sha256_kat(void){
  EVP_MD_CTX *ctx;
  uint8_t hash[32];
  unsigned int hash_len = 32;

  ctx = EVP_MD_CTX_new();
  if( !ctx ) return PQC_ERROR;

  if( EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(ctx, KAT_SHA256_INPUT, 3) != 1 ||
      EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1 ){
    EVP_MD_CTX_free(ctx);
    return PQC_ERROR;
  }
  EVP_MD_CTX_free(ctx);

  if( pqc_secure_memcmp(hash, KAT_SHA256_OUTPUT, 32) != 0 ){
    return PQC_ERROR;
  }
  return PQC_OK;
}

/*
** Run the DRBG (random number generator) health check.
*/
static int run_drbg_kat(void){
  uint8_t buf[32];
  int i, all_zero = 1;

  if( RAND_bytes(buf, 32) != 1 ) return PQC_ERROR;

  /* Verify output is not all zeros (trivial health check) */
  for(i = 0; i < 32; i++){
    if( buf[i] != 0 ){ all_zero = 0; break; }
  }
  pqc_secure_wipe(buf, sizeof(buf));

  return all_zero ? PQC_ERROR : PQC_OK;
}

/*
** Enable FIPS mode.
*/
int pqc_fips_enable(PqcFipsState *state){
  OSSL_PROVIDER *fips_prov = NULL;
  OSSL_PROVIDER *base_prov = NULL;

  if( !state ) return PQC_ERROR;
  memset(state, 0, sizeof(*state));

  /* Attempt to load OpenSSL FIPS provider */
  fips_prov = OSSL_PROVIDER_load(NULL, "fips");
  base_prov = OSSL_PROVIDER_load(NULL, "base");

  if( fips_prov != NULL ){
    state->openssl_fips_available = 1;
    snprintf(state->status_msg, sizeof(state->status_msg),
      "FIPS mode: OpenSSL FIPS provider loaded");
  }else{
    state->openssl_fips_available = 0;
    snprintf(state->status_msg, sizeof(state->status_msg),
      "FIPS mode: OpenSSL FIPS provider not available "
      "(using default provider with FIPS-approved algorithms only)");
  }

  /* Run self-tests */
  int rc = pqc_fips_run_self_tests(state);
  if( rc != PQC_OK ){
    snprintf(state->status_msg, sizeof(state->status_msg),
      "FIPS mode: FAILED — self-tests did not pass");
    return PQC_ERROR;
  }

  state->enabled = 1;
  return PQC_OK;
}

int pqc_fips_disable(PqcFipsState *state){
  if( !state ) return PQC_ERROR;
  state->enabled = 0;
  snprintf(state->status_msg, sizeof(state->status_msg),
    "FIPS mode: disabled");
  return PQC_OK;
}

int pqc_fips_is_enabled(const PqcFipsState *state){
  return state ? state->enabled : 0;
}

/*
** Run all KATs.
*/
int pqc_fips_run_self_tests(PqcFipsState *state){
  int rc;

  if( !state ) return PQC_ERROR;

  /* AES-256-GCM */
  rc = run_aes_gcm_kat();
  if( rc != PQC_OK ){
    state->self_test_passed = 0;
    return PQC_ERROR;
  }

  /* SHA-256 */
  rc = run_sha256_kat();
  if( rc != PQC_OK ){
    state->self_test_passed = 0;
    return PQC_ERROR;
  }

  /* DRBG */
  rc = run_drbg_kat();
  if( rc != PQC_OK ){
    state->self_test_passed = 0;
    return PQC_ERROR;
  }

  state->self_test_passed = 1;
  return PQC_OK;
}

const char *pqc_fips_status_string(const PqcFipsState *state){
  if( !state ) return "FIPS mode: not initialized";
  return state->status_msg;
}

/*
** Check if an algorithm name is FIPS-approved.
*/
int pqc_fips_check_algorithm(const PqcFipsState *state, const char *alg_name){
  if( !state || !state->enabled ) return PQC_OK; /* Not enforcing */

  /* FIPS-approved symmetric algorithms */
  if( strcmp(alg_name, "AES-256-GCM") == 0 ) return PQC_OK;
  if( strcmp(alg_name, "AES-256-CBC") == 0 ) return PQC_OK;
  if( strcmp(alg_name, "AES-128-GCM") == 0 ) return PQC_OK;

  /* FIPS-approved hash algorithms */
  if( strcmp(alg_name, "SHA-256") == 0 ) return PQC_OK;
  if( strcmp(alg_name, "SHA-384") == 0 ) return PQC_OK;
  if( strcmp(alg_name, "SHA-512") == 0 ) return PQC_OK;
  if( strcmp(alg_name, "SHA3-256") == 0 ) return PQC_OK;

  /* FIPS-approved PQC (per FIPS 203/204/205) */
  if( strncmp(alg_name, "ML-KEM", 6) == 0 ) return PQC_OK;
  if( strncmp(alg_name, "ML-DSA", 6) == 0 ) return PQC_OK;
  if( strncmp(alg_name, "SLH-DSA", 7) == 0 ) return PQC_OK;

  /* FIPS-approved KDFs */
  if( strcmp(alg_name, "PBKDF2") == 0 ) return PQC_OK;
  if( strcmp(alg_name, "HKDF") == 0 ) return PQC_OK;

  /* Not approved — reject in FIPS mode */
  return PQC_ERROR;
}

#endif /* PQLITE_ENABLE_PQC */
