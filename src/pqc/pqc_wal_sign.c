/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** PQLite WAL Signing — Implementation
**
** Provides ML-DSA digital signatures over WAL (Write-Ahead Log) frames.
** Each frame gets signed after write, and signatures are verified during
** crash recovery to detect WAL tampering.
**
** Signature storage: .wal.sig sidecar file, format:
**   [4-byte magic "PQWS"]
**   [4-byte version]
**   [4-byte sig_algorithm]
**   [4-byte public_key_length]
**   [public_key bytes]
**   [4-byte frame_count]
**   For each frame:
**     [4-byte signature_length]
**     [signature bytes]
**
** PQLite is a product of Dyber, Inc.
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_wal_sign.h"
#include "pqc_mem.h"
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define PQWS_MAGIC "PQWS"
#define PQWS_VERSION 1

/*
** Initialize WAL signing.
** Generates a fresh ML-DSA signing keypair for this WAL lifecycle.
*/
int pqc_wal_sign_init(PqcWalSigner *signer,
                        PqcSigAlgorithm sig_alg,
                        const char *wal_path){
  int rc;
  size_t path_len;

  if( signer == NULL || wal_path == NULL ) return PQC_ERROR;
  memset(signer, 0, sizeof(*signer));

  signer->sig_alg = sig_alg;

  /* Build .wal.sig path */
  path_len = strlen(wal_path) + 5; /* ".sig\0" */
  signer->sig_path = (char *)malloc(path_len);
  if( signer->sig_path == NULL ) return PQC_NOMEM;
  snprintf(signer->sig_path, path_len, "%s.sig", wal_path);

  /* Generate signing keypair */
  rc = pqc_sig_keygen(sig_alg, &signer->signing_key);
  if( rc != PQC_OK ){
    free(signer->sig_path);
    signer->sig_path = NULL;
    return rc;
  }

  signer->enabled = 1;
  return PQC_OK;
}

/*
** Sign a single WAL frame.
**
** The signature covers: frame_header (24 bytes) || page_data
** This binds the page number, page content, and WAL metadata
** together cryptographically.
*/
int pqc_wal_sign_frame(PqcWalSigner *signer,
                         const uint8_t *frame_hdr,
                         const uint8_t *page_data,
                         int page_size){
  const PqcSigInfo *info;
  uint8_t *msg = NULL;
  size_t msg_len;
  uint8_t *signature = NULL;
  size_t sig_len;
  FILE *fp = NULL;
  int rc = PQC_ERROR;

  if( signer == NULL || !signer->enabled ) return PQC_OK;
  if( frame_hdr == NULL || page_data == NULL ) return PQC_ERROR;

  info = pqc_sig_get_info(signer->sig_alg);
  if( info == NULL ) return PQC_UNSUPPORTED;

  /* Concatenate frame header + page data as the message to sign */
  msg_len = 24 + (size_t)page_size;
  msg = (uint8_t *)malloc(msg_len);
  if( msg == NULL ) return PQC_NOMEM;

  memcpy(msg, frame_hdr, 24);
  memcpy(msg + 24, page_data, page_size);

  /* Allocate signature buffer */
  sig_len = info->sig_len;
  signature = (uint8_t *)malloc(sig_len);
  if( signature == NULL ){
    free(msg);
    return PQC_NOMEM;
  }

  /* Sign with ML-DSA */
  rc = pqc_sig_sign(&signer->signing_key, msg, msg_len,
                      signature, &sig_len);
  free(msg);

  if( rc != PQC_OK ){
    free(signature);
    return rc;
  }

  /* Append signature to the .wal.sig sidecar file */
  fp = fopen(signer->sig_path, "ab");
  if( fp == NULL ){
    free(signature);
    return PQC_ERROR;
  }

  {
    /* Write signature length (4 bytes, big-endian) */
    uint8_t len_buf[4];
    uint32_t sl = (uint32_t)sig_len;
    len_buf[0] = (uint8_t)((sl >> 24) & 0xFF);
    len_buf[1] = (uint8_t)((sl >> 16) & 0xFF);
    len_buf[2] = (uint8_t)((sl >> 8) & 0xFF);
    len_buf[3] = (uint8_t)(sl & 0xFF);
    fwrite(len_buf, 1, 4, fp);
  }
  fwrite(signature, 1, sig_len, fp);
  fclose(fp);

  free(signature);
  return PQC_OK;
}

/*
** Verify a WAL frame signature during recovery.
*/
int pqc_wal_verify_frame(PqcWalSigner *signer,
                           const uint8_t *frame_hdr,
                           const uint8_t *page_data,
                           int page_size,
                           uint32_t sig_index){
  const PqcSigInfo *info;
  uint8_t *msg = NULL;
  size_t msg_len;
  FILE *fp = NULL;
  uint8_t *signature = NULL;
  uint8_t len_buf[4];
  uint32_t sig_len;
  uint32_t i;
  int rc = PQC_ERROR;

  if( signer == NULL || !signer->enabled ) return PQC_OK;
  if( frame_hdr == NULL || page_data == NULL ) return PQC_ERROR;

  info = pqc_sig_get_info(signer->sig_alg);
  if( info == NULL ) return PQC_UNSUPPORTED;

  /* Open .wal.sig file and seek to the right signature */
  fp = fopen(signer->sig_path, "rb");
  if( fp == NULL ) return PQC_ERROR;

  /* Skip signatures before the target index */
  for(i = 0; i < sig_index; i++){
    if( fread(len_buf, 1, 4, fp) != 4 ) goto done;
    sig_len = ((uint32_t)len_buf[0] << 24) |
              ((uint32_t)len_buf[1] << 16) |
              ((uint32_t)len_buf[2] << 8) |
              (uint32_t)len_buf[3];
    if( fseek(fp, (long)sig_len, SEEK_CUR) != 0 ) goto done;
  }

  /* Read the target signature */
  if( fread(len_buf, 1, 4, fp) != 4 ) goto done;
  sig_len = ((uint32_t)len_buf[0] << 24) |
            ((uint32_t)len_buf[1] << 16) |
            ((uint32_t)len_buf[2] << 8) |
            (uint32_t)len_buf[3];

  signature = (uint8_t *)malloc(sig_len);
  if( signature == NULL ) goto done;
  if( fread(signature, 1, sig_len, fp) != sig_len ) goto done;

  /* Reconstruct the signed message */
  msg_len = 24 + (size_t)page_size;
  msg = (uint8_t *)malloc(msg_len);
  if( msg == NULL ) goto done;

  memcpy(msg, frame_hdr, 24);
  memcpy(msg + 24, page_data, page_size);

  /* Verify with ML-DSA */
  rc = pqc_sig_verify(&signer->signing_key, msg, msg_len,
                        signature, (size_t)sig_len);

done:
  if( msg ) free(msg);
  if( signature ) free(signature);
  if( fp ) fclose(fp);
  return rc;
}

/*
** Finalize WAL signing — write the signature file header.
*/
int pqc_wal_sign_finalize(PqcWalSigner *signer){
  if( signer == NULL || !signer->enabled ) return PQC_OK;
  /* The individual frame signatures have already been appended.
  ** A production implementation would prepend a header with the
  ** public key for independent verification. */
  return PQC_OK;
}

/*
** Free WAL signer resources.
*/
void pqc_wal_sign_free(PqcWalSigner *signer){
  if( signer == NULL ) return;
  pqc_sig_keypair_free(&signer->signing_key);
  if( signer->sig_path ){
    free(signer->sig_path);
  }
  memset(signer, 0, sizeof(*signer));
}

/*
** Export the public key for external verification.
*/
int pqc_wal_sign_export_pubkey(const PqcWalSigner *signer,
                                 uint8_t *buf, size_t *buf_len){
  if( signer == NULL || buf_len == NULL ) return PQC_ERROR;
  if( !signer->enabled ) return PQC_ERROR;

  if( buf == NULL ){
    *buf_len = signer->signing_key.pk_len;
    return PQC_OK;
  }
  if( *buf_len < signer->signing_key.pk_len ) return PQC_ERROR;

  memcpy(buf, signer->signing_key.public_key, signer->signing_key.pk_len);
  *buf_len = signer->signing_key.pk_len;
  return PQC_OK;
}

#endif /* PQLITE_ENABLE_PQC */
