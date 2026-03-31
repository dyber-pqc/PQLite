/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** ML-DSA (FIPS 204) & SLH-DSA (FIPS 205) Digital Signatures
**
** Wraps the liboqs OQS_SIG API for key generation, signing,
** and verification using NIST-standardized post-quantum
** signature schemes.
**
** PQLite is a product of Dyber, Inc.
*/
#ifndef PQLITE_PQC_SIG_H
#define PQLITE_PQC_SIG_H

#ifdef PQLITE_ENABLE_PQC

#include "pqc_common.h"

/*
** Signature keypair — holds public and secret signing keys.
** All key material stored in secure (mlock'd) memory.
*/
typedef struct PqcSigKeypair {
  PqcSigAlgorithm alg;     /* Which ML-DSA or SLH-DSA variant */
  uint8_t *public_key;     /* Verification (public) key */
  uint8_t *secret_key;     /* Signing (secret) key */
  size_t pk_len;            /* Public key length */
  size_t sk_len;            /* Secret key length */
} PqcSigKeypair;

/*
** Generate a new signature keypair.
**
** Uses liboqs OQS_SIG_keypair() backed by OS CSPRNG.
**
** @param alg   Which signature variant (ML-DSA-44/65/87, SLH-DSA-*)
** @param kp    Output keypair (caller must call pqc_sig_keypair_free)
** @return PQC_OK on success
*/
int pqc_sig_keygen(PqcSigAlgorithm alg, PqcSigKeypair *kp);

/*
** Sign a message.
**
** Produces a post-quantum digital signature over the given message
** using the secret key. For ML-DSA, signatures are ~2-4 KB.
** For SLH-DSA, signatures are ~8-50 KB depending on variant.
**
** @param kp          Keypair (secret_key must be present)
** @param msg         Message to sign
** @param msg_len     Message length in bytes
** @param signature   Output buffer (must be >= sig_len from PqcSigInfo)
** @param sig_len     In: buffer size. Out: actual signature length.
** @return PQC_OK on success
*/
int pqc_sig_sign(const PqcSigKeypair *kp,
                  const uint8_t *msg, size_t msg_len,
                  uint8_t *signature, size_t *sig_len);

/*
** Verify a signature.
**
** @param kp          Keypair (only public_key is used)
** @param msg         Original message
** @param msg_len     Message length
** @param signature   Signature to verify
** @param sig_len     Signature length
** @return PQC_OK if valid, PQC_VERIFY_FAIL if invalid
*/
int pqc_sig_verify(const PqcSigKeypair *kp,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *signature, size_t sig_len);

/*
** Free a signature keypair and securely wipe all key material.
*/
void pqc_sig_keypair_free(PqcSigKeypair *kp);

/*
** Serialize/deserialize for storage.
*/
int pqc_sig_keypair_serialize(const PqcSigKeypair *kp,
                               uint8_t *buf, size_t *buf_len);
int pqc_sig_keypair_deserialize(PqcSigKeypair *kp,
                                 const uint8_t *buf, size_t buf_len);

/*
** Import just a public key (for verification only).
*/
int pqc_sig_import_public_key(PqcSigAlgorithm alg,
                               const uint8_t *pk, size_t pk_len,
                               PqcSigKeypair *kp);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_SIG_H */
