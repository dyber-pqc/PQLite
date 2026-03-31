/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** ML-KEM (FIPS 203) Key Encapsulation Mechanism — Implementation
**
** This module provides real ML-KEM operations via the liboqs library.
** No stubs, no placeholders — all calls go directly to the NIST-standardized
** CRYSTALS-Kyber implementation in liboqs.
**
** PQLite is a product of Dyber, Inc.
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_kem.h"
#include "pqc_mem.h"
#include "pqc_common.h"
#include <oqs/oqs.h>
#include <string.h>

/*
** Generate a new ML-KEM keypair using liboqs.
**
** Calls OQS_KEM_keypair() which:
** 1. Generates a random seed from the OS CSPRNG
** 2. Expands the seed into a full keypair per FIPS 203
** 3. Stores public + secret keys in the output struct
**
** Key material is allocated in secure (mlock'd) memory.
*/
int pqc_kem_keygen(PqcKemAlgorithm alg, PqcKemKeypair *kp){
  OQS_KEM *kem = NULL;
  const PqcKemInfo *info;
  OQS_STATUS rc;

  if( kp == NULL ) return PQC_ERROR;
  memset(kp, 0, sizeof(*kp));

  info = pqc_kem_get_info(alg);
  if( info == NULL ) return PQC_UNSUPPORTED;

  /* Create liboqs KEM context */
  kem = OQS_KEM_new(info->name);
  if( kem == NULL ) return PQC_UNSUPPORTED;

  /* Allocate secure memory for keys */
  kp->public_key = (uint8_t *)pqc_secure_alloc(kem->length_public_key);
  kp->secret_key = (uint8_t *)pqc_secure_alloc(kem->length_secret_key);
  if( kp->public_key == NULL || kp->secret_key == NULL ){
    pqc_secure_free(kp->public_key, kem->length_public_key);
    pqc_secure_free(kp->secret_key, kem->length_secret_key);
    OQS_KEM_free(kem);
    memset(kp, 0, sizeof(*kp));
    return PQC_NOMEM;
  }

  /* Generate the keypair — this is the real ML-KEM keygen from liboqs */
  rc = OQS_KEM_keypair(kem, kp->public_key, kp->secret_key);
  if( rc != OQS_SUCCESS ){
    pqc_secure_free(kp->public_key, kem->length_public_key);
    pqc_secure_free(kp->secret_key, kem->length_secret_key);
    OQS_KEM_free(kem);
    memset(kp, 0, sizeof(*kp));
    return PQC_ERROR;
  }

  kp->alg = alg;
  kp->pk_len = kem->length_public_key;
  kp->sk_len = kem->length_secret_key;
  OQS_KEM_free(kem);
  return PQC_OK;
}

/*
** Encapsulate: produce a ciphertext and shared secret from a public key.
**
** This is the core of PQLite's key management:
** 1. Encapsulate using ML-KEM public key
** 2. Shared secret (32 bytes) is used as input to HKDF
** 3. Ciphertext is stored in the database header
**
** On database open, decapsulate recovers the shared secret.
*/
int pqc_kem_encapsulate(const PqcKemKeypair *kp,
                         uint8_t *ciphertext, size_t *ct_len,
                         uint8_t *shared_secret, size_t *ss_len){
  OQS_KEM *kem = NULL;
  const PqcKemInfo *info;
  OQS_STATUS rc;

  if( kp == NULL || kp->public_key == NULL ) return PQC_ERROR;
  if( ciphertext == NULL || shared_secret == NULL ) return PQC_ERROR;

  info = pqc_kem_get_info(kp->alg);
  if( info == NULL ) return PQC_UNSUPPORTED;

  kem = OQS_KEM_new(info->name);
  if( kem == NULL ) return PQC_UNSUPPORTED;

  /* Real ML-KEM encapsulation via liboqs.
  ** This generates a random shared secret and encrypts it
  ** under the public key using the Module-LWE problem. */
  rc = OQS_KEM_encaps(kem, ciphertext, shared_secret, kp->public_key);
  if( rc != OQS_SUCCESS ){
    OQS_KEM_free(kem);
    return PQC_ERROR;
  }

  if( ct_len ) *ct_len = kem->length_ciphertext;
  if( ss_len ) *ss_len = kem->length_shared_secret;
  OQS_KEM_free(kem);
  return PQC_OK;
}

/*
** Decapsulate: recover the shared secret from ciphertext + secret key.
**
** Called on database open after reading the KEM ciphertext from
** the database header. The recovered shared secret feeds into
** HKDF to derive the AES-256-GCM page encryption key.
*/
int pqc_kem_decapsulate(const PqcKemKeypair *kp,
                         const uint8_t *ciphertext, size_t ct_len,
                         uint8_t *shared_secret, size_t *ss_len){
  OQS_KEM *kem = NULL;
  const PqcKemInfo *info;
  OQS_STATUS rc;

  if( kp == NULL || kp->secret_key == NULL ) return PQC_ERROR;
  if( ciphertext == NULL || shared_secret == NULL ) return PQC_ERROR;

  info = pqc_kem_get_info(kp->alg);
  if( info == NULL ) return PQC_UNSUPPORTED;

  /* Verify ciphertext length matches expected */
  if( ct_len != info->ct_len ) return PQC_ERROR;

  kem = OQS_KEM_new(info->name);
  if( kem == NULL ) return PQC_UNSUPPORTED;

  /* Real ML-KEM decapsulation.
  ** If the ciphertext was tampered with, ML-KEM's implicit rejection
  ** mechanism returns a pseudorandom value (not the real shared secret),
  ** which will cause decryption to fail with garbled output. */
  rc = OQS_KEM_decaps(kem, shared_secret, ciphertext, kp->secret_key);
  if( rc != OQS_SUCCESS ){
    OQS_KEM_free(kem);
    pqc_secure_wipe(shared_secret, kem->length_shared_secret);
    return PQC_DECRYPT_FAIL;
  }

  if( ss_len ) *ss_len = kem->length_shared_secret;
  OQS_KEM_free(kem);
  return PQC_OK;
}

/*
** Securely free a keypair, wiping all key material.
*/
void pqc_kem_keypair_free(PqcKemKeypair *kp){
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
** Serialize a keypair to a byte buffer.
** Format: [4-byte algorithm ID, big-endian][public key][secret key]
*/
int pqc_kem_keypair_serialize(const PqcKemKeypair *kp,
                               uint8_t *buf, size_t *buf_len){
  size_t total;
  if( kp == NULL || buf_len == NULL ) return PQC_ERROR;

  total = 4 + kp->pk_len + kp->sk_len;
  if( buf == NULL ){
    *buf_len = total;
    return PQC_OK;
  }
  if( *buf_len < total ) return PQC_ERROR;

  /* Algorithm ID (big-endian) */
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
** Deserialize a keypair from a byte buffer.
*/
int pqc_kem_keypair_deserialize(PqcKemKeypair *kp,
                                 const uint8_t *buf, size_t buf_len){
  PqcKemAlgorithm alg;
  const PqcKemInfo *info;

  if( kp == NULL || buf == NULL || buf_len < 4 ) return PQC_ERROR;
  memset(kp, 0, sizeof(*kp));

  alg = (PqcKemAlgorithm)(
    ((uint32_t)buf[0] << 24) |
    ((uint32_t)buf[1] << 16) |
    ((uint32_t)buf[2] << 8) |
    (uint32_t)buf[3]
  );

  info = pqc_kem_get_info(alg);
  if( info == NULL ) return PQC_UNSUPPORTED;
  if( buf_len != 4 + info->pk_len + info->sk_len ) return PQC_ERROR;

  kp->alg = alg;
  kp->pk_len = info->pk_len;
  kp->sk_len = info->sk_len;
  kp->public_key = (uint8_t *)pqc_secure_alloc(kp->pk_len);
  kp->secret_key = (uint8_t *)pqc_secure_alloc(kp->sk_len);
  if( kp->public_key == NULL || kp->secret_key == NULL ){
    pqc_kem_keypair_free(kp);
    return PQC_NOMEM;
  }

  memcpy(kp->public_key, buf + 4, kp->pk_len);
  memcpy(kp->secret_key, buf + 4 + kp->pk_len, kp->sk_len);
  return PQC_OK;
}

/*
** Import a public key only (for encapsulation without the secret key).
*/
int pqc_kem_import_public_key(PqcKemAlgorithm alg,
                               const uint8_t *pk, size_t pk_len,
                               PqcKemKeypair *kp){
  const PqcKemInfo *info;

  if( kp == NULL || pk == NULL ) return PQC_ERROR;
  memset(kp, 0, sizeof(*kp));

  info = pqc_kem_get_info(alg);
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
