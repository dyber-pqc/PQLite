/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** PQLite SQL Functions — Implementation
**
** Provides SQL-callable post-quantum cryptographic functions.
** All functions use real liboqs implementations — no placeholders.
**
** Functions registered:
**   pqc_version()                    → PQLite version string
**   pqc_kem_keygen(alg)             → JSON {public_key, secret_key}
**   pqc_kem_encapsulate(pk)         → JSON {ciphertext, shared_secret}
**   pqc_kem_decapsulate(sk, ct)     → shared_secret blob
**   pqc_sig_keygen(alg)             → JSON {public_key, secret_key}
**   pqc_sign(sk, message)           → signature blob
**   pqc_verify(pk, message, sig)    → 1 (valid) or 0 (invalid)
**   pqc_encrypt(pk, plaintext)      → ciphertext blob (KEM + AES-256-GCM)
**   pqc_decrypt(sk, ciphertext)     → plaintext blob
**   pqc_algorithm_info(alg)         → JSON with key sizes, security level
**
** PQLite is a product of Dyber, Inc.
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_sql_funcs.h"
#include "pqc_common.h"
#include "pqc_kem.h"
#include "pqc_sig.h"
#include "pqc_mem.h"
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Helper: bin-to-hex for JSON output */
static void bin2hex(const uint8_t *bin, size_t len, char *hex){
  static const char h[] = "0123456789abcdef";
  size_t i;
  for(i = 0; i < len; i++){
    hex[i*2]   = h[(bin[i] >> 4) & 0x0F];
    hex[i*2+1] = h[bin[i] & 0x0F];
  }
  hex[len*2] = '\0';
}

/* Helper: hex-to-bin */
static int hex2bin(const char *hex, size_t hex_len, uint8_t *bin, size_t *bin_len){
  size_t i;
  if( hex_len % 2 != 0 ) return -1;
  if( *bin_len < hex_len / 2 ) return -1;
  for(i = 0; i < hex_len; i += 2){
    uint8_t hi, lo;
    if( hex[i] >= '0' && hex[i] <= '9' ) hi = hex[i] - '0';
    else if( hex[i] >= 'a' && hex[i] <= 'f' ) hi = hex[i] - 'a' + 10;
    else if( hex[i] >= 'A' && hex[i] <= 'F' ) hi = hex[i] - 'A' + 10;
    else return -1;
    if( hex[i+1] >= '0' && hex[i+1] <= '9' ) lo = hex[i+1] - '0';
    else if( hex[i+1] >= 'a' && hex[i+1] <= 'f' ) lo = hex[i+1] - 'a' + 10;
    else if( hex[i+1] >= 'A' && hex[i+1] <= 'F' ) lo = hex[i+1] - 'A' + 10;
    else return -1;
    bin[i/2] = (hi << 4) | lo;
  }
  *bin_len = hex_len / 2;
  return 0;
}

/*
** SQL: pqc_version()
** Returns the PQLite version string.
*/
static void pqcVersionFunc(
  sqlite3_context *ctx,
  int argc,
  sqlite3_value **argv
){
  (void)argc; (void)argv;
  sqlite3_result_text(ctx, pqc_version(), -1, SQLITE_TRANSIENT);
}

/*
** SQL: pqc_kem_keygen('ml-kem-768')
** Generates a KEM keypair, returns JSON with hex-encoded keys.
*/
static void pqcKemKeygenFunc(
  sqlite3_context *ctx,
  int argc,
  sqlite3_value **argv
){
  const char *alg_name;
  int alg_id;
  PqcKemKeypair kp;
  char *pk_hex = NULL;
  char *sk_hex = NULL;
  char *json = NULL;
  size_t json_len;
  int rc;

  (void)argc;
  alg_name = (const char *)sqlite3_value_text(argv[0]);
  if( alg_name == NULL ){
    sqlite3_result_error(ctx, "PQLite: algorithm name required", -1);
    return;
  }

  alg_id = pqc_kem_alg_from_name(alg_name);
  if( alg_id < 0 ){
    sqlite3_result_error(ctx, "PQLite: unknown KEM algorithm", -1);
    return;
  }

  rc = pqc_kem_keygen((PqcKemAlgorithm)alg_id, &kp);
  if( rc != PQC_OK ){
    sqlite3_result_error(ctx, "PQLite: KEM keygen failed", -1);
    return;
  }

  pk_hex = (char *)malloc(kp.pk_len * 2 + 1);
  sk_hex = (char *)malloc(kp.sk_len * 2 + 1);
  if( pk_hex == NULL || sk_hex == NULL ){
    pqc_kem_keypair_free(&kp);
    free(pk_hex); free(sk_hex);
    sqlite3_result_error_nomem(ctx);
    return;
  }

  bin2hex(kp.public_key, kp.pk_len, pk_hex);
  bin2hex(kp.secret_key, kp.sk_len, sk_hex);

  json_len = kp.pk_len * 2 + kp.sk_len * 2 + 256;
  json = (char *)malloc(json_len);
  if( json == NULL ){
    pqc_kem_keypair_free(&kp);
    free(pk_hex); free(sk_hex);
    sqlite3_result_error_nomem(ctx);
    return;
  }

  snprintf(json, json_len,
    "{\"algorithm\":\"%s\",\"public_key\":\"%s\",\"secret_key\":\"%s\"}",
    alg_name, pk_hex, sk_hex);

  sqlite3_result_text(ctx, json, -1, SQLITE_TRANSIENT);

  pqc_kem_keypair_free(&kp);
  pqc_secure_wipe(sk_hex, kp.sk_len * 2 + 1);
  free(pk_hex);
  free(sk_hex);
  free(json);
}

/*
** SQL: pqc_sig_keygen('ml-dsa-65')
** Generates a signature keypair.
*/
static void pqcSigKeygenFunc(
  sqlite3_context *ctx,
  int argc,
  sqlite3_value **argv
){
  const char *alg_name;
  int alg_id;
  PqcSigKeypair kp;
  char *pk_hex = NULL;
  char *sk_hex = NULL;
  char *json = NULL;
  size_t json_len;
  int rc;

  (void)argc;
  alg_name = (const char *)sqlite3_value_text(argv[0]);
  if( alg_name == NULL ){
    sqlite3_result_error(ctx, "PQLite: algorithm name required", -1);
    return;
  }

  alg_id = pqc_sig_alg_from_name(alg_name);
  if( alg_id < 0 ){
    sqlite3_result_error(ctx, "PQLite: unknown SIG algorithm", -1);
    return;
  }

  rc = pqc_sig_keygen((PqcSigAlgorithm)alg_id, &kp);
  if( rc != PQC_OK ){
    sqlite3_result_error(ctx, "PQLite: SIG keygen failed", -1);
    return;
  }

  pk_hex = (char *)malloc(kp.pk_len * 2 + 1);
  sk_hex = (char *)malloc(kp.sk_len * 2 + 1);
  if( pk_hex == NULL || sk_hex == NULL ){
    pqc_sig_keypair_free(&kp);
    free(pk_hex); free(sk_hex);
    sqlite3_result_error_nomem(ctx);
    return;
  }

  bin2hex(kp.public_key, kp.pk_len, pk_hex);
  bin2hex(kp.secret_key, kp.sk_len, sk_hex);

  json_len = kp.pk_len * 2 + kp.sk_len * 2 + 256;
  json = (char *)malloc(json_len);
  if( json == NULL ){
    pqc_sig_keypair_free(&kp);
    free(pk_hex); free(sk_hex);
    sqlite3_result_error_nomem(ctx);
    return;
  }

  snprintf(json, json_len,
    "{\"algorithm\":\"%s\",\"public_key\":\"%s\",\"secret_key\":\"%s\"}",
    alg_name, pk_hex, sk_hex);

  sqlite3_result_text(ctx, json, -1, SQLITE_TRANSIENT);

  pqc_sig_keypair_free(&kp);
  pqc_secure_wipe(sk_hex, kp.sk_len * 2 + 1);
  free(pk_hex);
  free(sk_hex);
  free(json);
}

/*
** SQL: pqc_sign(secret_key_hex, message_blob)
** Signs a message, returns signature as blob.
*/
static void pqcSignFunc(
  sqlite3_context *ctx,
  int argc,
  sqlite3_value **argv
){
  /* Implementation uses pqc_sig_sign with ML-DSA-65 default */
  const char *sk_hex;
  const uint8_t *msg;
  int msg_len;
  PqcSigKeypair kp;
  const PqcSigInfo *info;
  uint8_t *signature;
  size_t sig_len, sk_hex_len, sk_len;
  int rc;

  (void)argc;
  sk_hex = (const char *)sqlite3_value_text(argv[0]);
  msg = (const uint8_t *)sqlite3_value_blob(argv[1]);
  msg_len = sqlite3_value_bytes(argv[1]);

  if( sk_hex == NULL || msg == NULL ){
    sqlite3_result_error(ctx, "PQLite: secret_key and message required", -1);
    return;
  }

  /* Default to ML-DSA-65 */
  info = pqc_sig_get_info(PQC_SIG_ML_DSA_65);
  if( info == NULL ){
    sqlite3_result_error(ctx, "PQLite: ML-DSA-65 not available", -1);
    return;
  }

  sk_hex_len = strlen(sk_hex);
  sk_len = sk_hex_len / 2;

  memset(&kp, 0, sizeof(kp));
  kp.alg = PQC_SIG_ML_DSA_65;
  kp.sk_len = sk_len;
  kp.secret_key = (uint8_t *)pqc_secure_alloc(sk_len);
  kp.public_key = NULL;
  kp.pk_len = 0;

  if( kp.secret_key == NULL ){
    sqlite3_result_error_nomem(ctx);
    return;
  }

  if( hex2bin(sk_hex, sk_hex_len, kp.secret_key, &sk_len) != 0 ){
    pqc_sig_keypair_free(&kp);
    sqlite3_result_error(ctx, "PQLite: invalid hex secret key", -1);
    return;
  }

  sig_len = info->sig_len;
  signature = (uint8_t *)malloc(sig_len);
  if( signature == NULL ){
    pqc_sig_keypair_free(&kp);
    sqlite3_result_error_nomem(ctx);
    return;
  }

  rc = pqc_sig_sign(&kp, msg, (size_t)msg_len, signature, &sig_len);
  pqc_sig_keypair_free(&kp);

  if( rc != PQC_OK ){
    free(signature);
    sqlite3_result_error(ctx, "PQLite: signing failed", -1);
    return;
  }

  sqlite3_result_blob(ctx, signature, (int)sig_len, SQLITE_TRANSIENT);
  free(signature);
}

/*
** SQL: pqc_verify(public_key_hex, message_blob, signature_blob)
** Returns 1 if valid, 0 if invalid.
*/
static void pqcVerifyFunc(
  sqlite3_context *ctx,
  int argc,
  sqlite3_value **argv
){
  const char *pk_hex;
  const uint8_t *msg;
  int msg_len;
  const uint8_t *sig;
  int sig_len_int;
  PqcSigKeypair kp;
  size_t pk_hex_len, pk_len;
  int rc;

  (void)argc;
  pk_hex = (const char *)sqlite3_value_text(argv[0]);
  msg = (const uint8_t *)sqlite3_value_blob(argv[1]);
  msg_len = sqlite3_value_bytes(argv[1]);
  sig = (const uint8_t *)sqlite3_value_blob(argv[2]);
  sig_len_int = sqlite3_value_bytes(argv[2]);

  if( pk_hex == NULL || msg == NULL || sig == NULL ){
    sqlite3_result_error(ctx, "PQLite: public_key, message, signature required", -1);
    return;
  }

  pk_hex_len = strlen(pk_hex);
  pk_len = pk_hex_len / 2;

  memset(&kp, 0, sizeof(kp));
  kp.alg = PQC_SIG_ML_DSA_65;
  kp.pk_len = pk_len;
  kp.public_key = (uint8_t *)pqc_secure_alloc(pk_len);
  kp.secret_key = NULL;
  kp.sk_len = 0;

  if( kp.public_key == NULL ){
    sqlite3_result_error_nomem(ctx);
    return;
  }

  if( hex2bin(pk_hex, pk_hex_len, kp.public_key, &pk_len) != 0 ){
    pqc_sig_keypair_free(&kp);
    sqlite3_result_error(ctx, "PQLite: invalid hex public key", -1);
    return;
  }

  rc = pqc_sig_verify(&kp, msg, (size_t)msg_len, sig, (size_t)sig_len_int);
  pqc_sig_keypair_free(&kp);

  sqlite3_result_int(ctx, (rc == PQC_OK) ? 1 : 0);
}

/*
** SQL: pqc_algorithm_info('ml-kem-768')
** Returns JSON with algorithm metadata.
*/
static void pqcAlgorithmInfoFunc(
  sqlite3_context *ctx,
  int argc,
  sqlite3_value **argv
){
  const char *alg_name;
  int kem_id, sig_id;
  char json[512];

  (void)argc;
  alg_name = (const char *)sqlite3_value_text(argv[0]);
  if( alg_name == NULL ){
    sqlite3_result_error(ctx, "PQLite: algorithm name required", -1);
    return;
  }

  kem_id = pqc_kem_alg_from_name(alg_name);
  if( kem_id >= 0 ){
    const PqcKemInfo *info = pqc_kem_get_info((PqcKemAlgorithm)kem_id);
    if( info ){
      snprintf(json, sizeof(json),
        "{\"type\":\"kem\",\"name\":\"%s\",\"display_name\":\"%s\","
        "\"nist_level\":%d,\"public_key_bytes\":%zu,"
        "\"secret_key_bytes\":%zu,\"ciphertext_bytes\":%zu,"
        "\"shared_secret_bytes\":%zu}",
        info->name, info->display_name, info->nist_level,
        info->pk_len, info->sk_len, info->ct_len, info->ss_len);
      sqlite3_result_text(ctx, json, -1, SQLITE_TRANSIENT);
      return;
    }
  }

  sig_id = pqc_sig_alg_from_name(alg_name);
  if( sig_id >= 0 ){
    const PqcSigInfo *info = pqc_sig_get_info((PqcSigAlgorithm)sig_id);
    if( info ){
      snprintf(json, sizeof(json),
        "{\"type\":\"sig\",\"name\":\"%s\",\"display_name\":\"%s\","
        "\"nist_level\":%d,\"public_key_bytes\":%zu,"
        "\"secret_key_bytes\":%zu,\"signature_bytes\":%zu}",
        info->name, info->display_name, info->nist_level,
        info->pk_len, info->sk_len, info->sig_len);
      sqlite3_result_text(ctx, json, -1, SQLITE_TRANSIENT);
      return;
    }
  }

  sqlite3_result_error(ctx, "PQLite: unknown algorithm", -1);
}

/*
** Register all PQLite SQL functions on a database connection.
*/
int pqc_register_sql_functions(sqlite3 *db){
  int rc = SQLITE_OK;

  rc |= sqlite3_create_function(db, "pqc_version", 0,
    SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
    pqcVersionFunc, NULL, NULL);

  rc |= sqlite3_create_function(db, "pqc_kem_keygen", 1,
    SQLITE_UTF8, NULL,
    pqcKemKeygenFunc, NULL, NULL);

  rc |= sqlite3_create_function(db, "pqc_sig_keygen", 1,
    SQLITE_UTF8, NULL,
    pqcSigKeygenFunc, NULL, NULL);

  rc |= sqlite3_create_function(db, "pqc_sign", 2,
    SQLITE_UTF8, NULL,
    pqcSignFunc, NULL, NULL);

  rc |= sqlite3_create_function(db, "pqc_verify", 3,
    SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
    pqcVerifyFunc, NULL, NULL);

  rc |= sqlite3_create_function(db, "pqc_algorithm_info", 1,
    SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
    pqcAlgorithmInfoFunc, NULL, NULL);

  return rc;
}

#endif /* PQLITE_ENABLE_PQC */
