/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** ML-DSA (FIPS 204) & SLH-DSA (FIPS 205) Digital Signatures — Implementation
**
** All operations call directly into liboqs with zero stubs.
** ML-DSA (Dilithium) is used for WAL signing and database integrity.
** SLH-DSA (SPHINCS+) is available as a conservative hash-based alternative.
**
** PQLite is a product of Dyber, Inc.
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_sig.h"
#include "pqc_mem.h"
#include "pqc_common.h"
#include <oqs/oqs.h>
#include <string.h>

/*
** Generate a new digital signature keypair using liboqs.
**
** For ML-DSA-65 (the default), this produces:
**   - Public key:  1952 bytes
**   - Secret key:  4032 bytes
**   - Signatures:  3309 bytes (max)
*/
int pqc_sig_keygen(PqcSigAlgorithm alg, PqcSigKeypair *kp){
  OQS_SIG *sig = NULL;
  const PqcSigInfo *info;
  OQS_STATUS rc;

  if( kp == NULL ) return PQC_ERROR;
  memset(kp, 0, sizeof(*kp));

  info = pqc_sig_get_info(alg);
  if( info == NULL ) return PQC_UNSUPPORTED;

  sig = OQS_SIG_new(info->name);
  if( sig == NULL ) return PQC_UNSUPPORTED;

  /* Allocate secure memory for key material */
  kp->public_key = (uint8_t *)pqc_secure_alloc(sig->length_public_key);
  kp->secret_key = (uint8_t *)pqc_secure_alloc(sig->length_secret_key);
  if( kp->public_key == NULL || kp->secret_key == NULL ){
    pqc_secure_free(kp->public_key, sig->length_public_key);
    pqc_secure_free(kp->secret_key, sig->length_secret_key);
    OQS_SIG_free(sig);
    memset(kp, 0, sizeof(*kp));
    return PQC_NOMEM;
  }

  /* Real ML-DSA / SLH-DSA keygen via liboqs */
  rc = OQS_SIG_keypair(sig, kp->public_key, kp->secret_key);
  if( rc != OQS_SUCCESS ){
    pqc_secure_free(kp->public_key, sig->length_public_key);
    pqc_secure_free(kp->secret_key, sig->length_secret_key);
    OQS_SIG_free(sig);
    memset(kp, 0, sizeof(*kp));
    return PQC_ERROR;
  }

  kp->alg = alg;
  kp->pk_len = sig->length_public_key;
  kp->sk_len = sig->length_secret_key;
  OQS_SIG_free(sig);
  return PQC_OK;
}

/*
** Sign a message using the secret key.
**
** For ML-DSA, signing:
** 1. Hashes the message
** 2. Samples a masking vector from the secret key
** 3. Computes the challenge polynomial
** 4. Produces the signature with rejection sampling
**
** This is a real FIPS 204 signature — not a placeholder.
*/
int pqc_sig_sign(const PqcSigKeypair *kp,
                  const uint8_t *msg, size_t msg_len,
                  uint8_t *signature, size_t *sig_len){
  OQS_SIG *sig_ctx = NULL;
  const PqcSigInfo *info;
  OQS_STATUS rc;

  if( kp == NULL || kp->secret_key == NULL ) return PQC_ERROR;
  if( msg == NULL && msg_len > 0 ) return PQC_ERROR;
  if( signature == NULL || sig_len == NULL ) return PQC_ERROR;

  info = pqc_sig_get_info(kp->alg);
  if( info == NULL ) return PQC_UNSUPPORTED;

  sig_ctx = OQS_SIG_new(info->name);
  if( sig_ctx == NULL ) return PQC_UNSUPPORTED;

  /* Real ML-DSA / SLH-DSA signing */
  rc = OQS_SIG_sign(sig_ctx, signature, sig_len,
                      msg, msg_len, kp->secret_key);
  OQS_SIG_free(sig_ctx);

  if( rc != OQS_SUCCESS ){
    return PQC_ERROR;
  }
  return PQC_OK;
}

/*
** Verify a signature using the public key.
**
** Returns PQC_OK if the signature is valid, PQC_VERIFY_FAIL otherwise.
** Verification is deterministic and typically faster than signing.
*/
int pqc_sig_verify(const PqcSigKeypair *kp,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *signature, size_t sig_len){
  OQS_SIG *sig_ctx = NULL;
  const PqcSigInfo *info;
  OQS_STATUS rc;

  if( kp == NULL || kp->public_key == NULL ) return PQC_ERROR;
  if( msg == NULL && msg_len > 0 ) return PQC_ERROR;
  if( signature == NULL ) return PQC_ERROR;

  info = pqc_sig_get_info(kp->alg);
  if( info == NULL ) return PQC_UNSUPPORTED;

  sig_ctx = OQS_SIG_new(info->name);
  if( sig_ctx == NULL ) return PQC_UNSUPPORTED;

  /* Real ML-DSA / SLH-DSA verification */
  rc = OQS_SIG_verify(sig_ctx, msg, msg_len,
                        signature, sig_len, kp->public_key);
  OQS_SIG_free(sig_ctx);

  if( rc != OQS_SUCCESS ){
    return PQC_VERIFY_FAIL;
  }
  return PQC_OK;
}

/*
** Securely free a signature keypair.
*/
void pqc_sig_keypair_free(PqcSigKeypair *kp){
  if( kp == NULL ) return;
  if( kp->public_key ){
    pqc_secure_free(kp->public_key, kp->pk_len);
  }
  if( kp->secret_key ){
    pqc_secure_free(kp->secret_key, kp->sk_len);
  }
  memset(kp, 0, sizeof(*kp));
}

/*
** Serialize a signature keypair.
** Format: [4-byte algorithm ID, big-endian][public key][secret key]
*/
int pqc_sig_keypair_serialize(const PqcSigKeypair *kp,
                               uint8_t *buf, size_t *buf_len){
  size_t total;
  if( kp == NULL || buf_len == NULL ) return PQC_ERROR;

  total = 4 + kp->pk_len + kp->sk_len;
  if( buf == NULL ){
    *buf_len = total;
    return PQC_OK;
  }
  if( *buf_len < total ) return PQC_ERROR;

  buf[0] = (uint8_t)((kp->alg >> 24) & 0xFF);
  buf[1] = (uint8_t)((kp->alg >> 16) & 0xFF);
  buf[2] = (uint8_t)((kp->alg >> 8) & 0xFF);
  buf[3] = (uint8_t)(kp->alg & 0xFF);

  memcpy(buf + 4, kp->public_key, kp->pk_len);
  memcpy(buf + 4 + kp->pk_len, kp->secret_key, kp->sk_len);
  *buf_len = total;
  return PQC_OK;
}

/*
** Deserialize a signature keypair.
*/
int pqc_sig_keypair_deserialize(PqcSigKeypair *kp,
                                 const uint8_t *buf, size_t buf_len){
  PqcSigAlgorithm alg;
  const PqcSigInfo *info;

  if( kp == NULL || buf == NULL || buf_len < 4 ) return PQC_ERROR;
  memset(kp, 0, sizeof(*kp));

  alg = (PqcSigAlgorithm)(
    ((uint32_t)buf[0] << 24) |
    ((uint32_t)buf[1] << 16) |
    ((uint32_t)buf[2] << 8) |
    (uint32_t)buf[3]
  );

  info = pqc_sig_get_info(alg);
  if( info == NULL ) return PQC_UNSUPPORTED;
  if( buf_len != 4 + info->pk_len + info->sk_len ) return PQC_ERROR;

  kp->alg = alg;
  kp->pk_len = info->pk_len;
  kp->sk_len = info->sk_len;
  kp->public_key = (uint8_t *)pqc_secure_alloc(kp->pk_len);
  kp->secret_key = (uint8_t *)pqc_secure_alloc(kp->sk_len);
  if( kp->public_key == NULL || kp->secret_key == NULL ){
    pqc_sig_keypair_free(kp);
    return PQC_NOMEM;
  }

  memcpy(kp->public_key, buf + 4, kp->pk_len);
  memcpy(kp->secret_key, buf + 4 + kp->pk_len, kp->sk_len);
  return PQC_OK;
}

/*
** Import just a public key for verification.
*/
int pqc_sig_import_public_key(PqcSigAlgorithm alg,
                               const uint8_t *pk, size_t pk_len,
                               PqcSigKeypair *kp){
  const PqcSigInfo *info;

  if( kp == NULL || pk == NULL ) return PQC_ERROR;
  memset(kp, 0, sizeof(*kp));

  info = pqc_sig_get_info(alg);
  if( info == NULL ) return PQC_UNSUPPORTED;
  if( pk_len != info->pk_len ) return PQC_ERROR;

  kp->alg = alg;
  kp->pk_len = info->pk_len;
  kp->sk_len = 0;
  kp->secret_key = NULL;
  kp->public_key = (uint8_t *)pqc_secure_alloc(pk_len);
  if( kp->public_key == NULL ) return PQC_NOMEM;

  memcpy(kp->public_key, pk, pk_len);
  return PQC_OK;
}

#endif /* PQLITE_ENABLE_PQC */
