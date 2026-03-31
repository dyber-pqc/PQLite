/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** ML-KEM (FIPS 203) Key Encapsulation Mechanism
**
** Wraps the liboqs OQS_KEM API for key generation, encapsulation,
** and decapsulation using NIST-standardized ML-KEM (Kyber).
*/
#ifndef PQLITE_PQC_KEM_H
#define PQLITE_PQC_KEM_H

#ifdef PQLITE_ENABLE_PQC

#include "pqc_common.h"

/*
** KEM keypair — holds public and secret keys.
** All key material is stored in secure (mlock'd) memory
** and wiped on free.
*/
typedef struct PqcKemKeypair {
  PqcKemAlgorithm alg;     /* Which ML-KEM variant */
  uint8_t *public_key;     /* Encapsulation (public) key */
  uint8_t *secret_key;     /* Decapsulation (secret) key */
  size_t pk_len;            /* Public key length */
  size_t sk_len;            /* Secret key length */
} PqcKemKeypair;

/*
** Generate a new ML-KEM keypair.
**
** Uses liboqs OQS_KEM_keypair() which sources randomness from
** the OS CSPRNG (CryptGenRandom on Windows, /dev/urandom on POSIX).
**
** @param alg   Which ML-KEM variant (512, 768, or 1024)
** @param kp    Output keypair (caller must later call pqc_kem_keypair_free)
** @return PQC_OK on success, PQC_ERROR on failure
*/
int pqc_kem_keygen(PqcKemAlgorithm alg, PqcKemKeypair *kp);

/*
** Encapsulate: generate a shared secret and ciphertext from a public key.
**
** The ciphertext can be stored alongside the encrypted database and
** decapsulated later using the corresponding secret key to recover
** the shared secret (which derives the encryption key).
**
** @param kp              Keypair (only public_key is used)
** @param ciphertext      Output buffer (must be >= ct_len bytes)
** @param ct_len          Output: actual ciphertext length written
** @param shared_secret   Output buffer (must be >= ss_len bytes)
** @param ss_len          Output: actual shared secret length written
** @return PQC_OK on success
*/
int pqc_kem_encapsulate(const PqcKemKeypair *kp,
                         uint8_t *ciphertext, size_t *ct_len,
                         uint8_t *shared_secret, size_t *ss_len);

/*
** Decapsulate: recover the shared secret from ciphertext + secret key.
**
** @param kp              Keypair (secret_key must be present)
** @param ciphertext      The ciphertext produced by encapsulate
** @param ct_len          Length of ciphertext
** @param shared_secret   Output buffer for recovered shared secret
** @param ss_len          Output: shared secret length
** @return PQC_OK on success, PQC_DECRYPT_FAIL on decapsulation failure
*/
int pqc_kem_decapsulate(const PqcKemKeypair *kp,
                         const uint8_t *ciphertext, size_t ct_len,
                         uint8_t *shared_secret, size_t *ss_len);

/*
** Free a keypair and securely wipe all key material.
*/
void pqc_kem_keypair_free(PqcKemKeypair *kp);

/*
** Serialize/deserialize keypair for storage.
** Serialized format: [4-byte alg ID][pk_len bytes][sk_len bytes]
*/
int pqc_kem_keypair_serialize(const PqcKemKeypair *kp,
                               uint8_t *buf, size_t *buf_len);
int pqc_kem_keypair_deserialize(PqcKemKeypair *kp,
                                 const uint8_t *buf, size_t buf_len);

/*
** Import just a public key (for encapsulation only — no secret key).
*/
int pqc_kem_import_public_key(PqcKemAlgorithm alg,
                               const uint8_t *pk, size_t pk_len,
                               PqcKemKeypair *kp);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_KEM_H */
