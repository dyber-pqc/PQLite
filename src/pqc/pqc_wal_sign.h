/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** PQLite WAL (Write-Ahead Log) Signing
**
** Signs WAL segments using ML-DSA-65 to provide quantum-resistant
** integrity verification of the write-ahead log. Signatures are
** stored in a .wal.sig sidecar file.
**
** PQLite is a product of Dyber, Inc.
*/
#ifndef PQLITE_PQC_WAL_SIGN_H
#define PQLITE_PQC_WAL_SIGN_H

#ifdef PQLITE_ENABLE_PQC

#include "pqc_common.h"
#include "pqc_sig.h"
#include <stdint.h>

/*
** WAL signing context — attached to the WAL subsystem.
*/
typedef struct PqcWalSigner {
  int enabled;                 /* Non-zero if WAL signing is active */
  PqcSigAlgorithm sig_alg;    /* Signature algorithm (default: ML-DSA-65) */
  PqcSigKeypair signing_key;  /* Signing keypair */
  char *sig_path;              /* Path to the .wal.sig sidecar file */
} PqcWalSigner;

/*
** Initialize WAL signing for a database.
**
** @param signer    Output signer context
** @param sig_alg   Signature algorithm to use
** @param wal_path  Path to the WAL file (signer appends .sig)
** @return PQC_OK on success
*/
int pqc_wal_sign_init(PqcWalSigner *signer,
                        PqcSigAlgorithm sig_alg,
                        const char *wal_path);

/*
** Sign a WAL frame.
** Called after each WAL frame write to produce a signature
** over the frame header + page data.
**
** @param signer     WAL signer context
** @param frame_hdr  WAL frame header (24 bytes)
** @param page_data  Page data in the frame
** @param page_size  Size of page data
** @return PQC_OK on success
*/
int pqc_wal_sign_frame(PqcWalSigner *signer,
                         const uint8_t *frame_hdr,
                         const uint8_t *page_data,
                         int page_size);

/*
** Verify a WAL frame signature.
** Called during WAL recovery to verify frame integrity.
**
** @param signer     WAL signer context
** @param frame_hdr  WAL frame header
** @param page_data  Page data
** @param page_size  Size of page data
** @param sig_index  Index of the frame (for looking up signature)
** @return PQC_OK if valid, PQC_VERIFY_FAIL if tampered
*/
int pqc_wal_verify_frame(PqcWalSigner *signer,
                           const uint8_t *frame_hdr,
                           const uint8_t *page_data,
                           int page_size,
                           uint32_t sig_index);

/*
** Finalize WAL signing (write signature file, cleanup).
*/
int pqc_wal_sign_finalize(PqcWalSigner *signer);

/*
** Free the WAL signer and wipe key material.
*/
void pqc_wal_sign_free(PqcWalSigner *signer);

/*
** Export the WAL signing public key (for verification by other tools).
*/
int pqc_wal_sign_export_pubkey(const PqcWalSigner *signer,
                                 uint8_t *buf, size_t *buf_len);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_WAL_SIGN_H */
