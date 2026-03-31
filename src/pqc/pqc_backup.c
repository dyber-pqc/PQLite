/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Encrypted Backup & Restore — Implementation
**
** Backup file format (all multi-byte values big-endian):
**
**   Offset  Size     Field
**   ------  ------   -----
**   0       8        Magic: "PQLBAK01"
**   8       4        Version (1)
**   12      4        KEM algorithm ID
**   16      4        SIG algorithm ID
**   20      4        Page size
**   24      4        Total pages
**   28      4        KEM ciphertext length
**   32      var      KEM ciphertext (wraps backup AES key)
**   var     4        SIG public key length
**   var     var      ML-DSA public key (for external verification)
**   var     N*pages  AES-256-GCM encrypted pages (each: [data][16-byte tag])
**   var     4        Signature length
**   var     var      ML-DSA signature over header + all encrypted pages
**
** PQLite is a product of Dyber, Inc.
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_backup.h"
#include "pqc_codec.h"
#include "pqc_mem.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Helper: write 4 bytes big-endian */
static void write_be32(uint8_t *p, uint32_t v){
  p[0] = (uint8_t)((v >> 24) & 0xFF);
  p[1] = (uint8_t)((v >> 16) & 0xFF);
  p[2] = (uint8_t)((v >> 8) & 0xFF);
  p[3] = (uint8_t)(v & 0xFF);
}

/* Helper: read 4 bytes big-endian */
static uint32_t read_be32(const uint8_t *p){
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/*
** Create an encrypted, signed backup.
*/
int pqc_backup_create(sqlite3 *db, const char *backup_path,
                        const PqcBackupOptions *opts){
  FILE *fp = NULL;
  sqlite3_backup *bk = NULL;
  sqlite3 *mem_db = NULL;
  PqcKemKeypair kem_kp;
  PqcSigKeypair sig_kp;
  uint8_t backup_key[32];  /* Random AES-256 key for this backup */
  uint8_t *kem_ct = NULL;
  size_t kem_ct_len, kem_ss_len;
  uint8_t kem_ss[32];
  const PqcKemInfo *kem_info;
  const PqcSigInfo *sig_info;
  EVP_MD_CTX *hash_ctx = NULL;
  uint8_t header[32];
  int page_size, total_pages;
  int rc = PQC_ERROR;

  if( !db || !backup_path || !opts ) return PQC_ERROR;

  memset(&kem_kp, 0, sizeof(kem_kp));
  memset(&sig_kp, 0, sizeof(sig_kp));

  kem_info = pqc_kem_get_info(opts->kem_alg);
  sig_info = pqc_sig_get_info(opts->sig_alg);
  if( !kem_info || !sig_info ) return PQC_UNSUPPORTED;

  /* Generate backup-specific KEM keypair */
  rc = pqc_kem_keygen(opts->kem_alg, &kem_kp);
  if( rc != PQC_OK ) goto done;

  /* Generate signing keypair */
  rc = pqc_sig_keygen(opts->sig_alg, &sig_kp);
  if( rc != PQC_OK ) goto done;

  /* Encapsulate to get backup encryption key */
  kem_ct = (uint8_t *)malloc(kem_info->ct_len);
  if( !kem_ct ){ rc = PQC_NOMEM; goto done; }

  rc = pqc_kem_encapsulate(&kem_kp, kem_ct, &kem_ct_len, kem_ss, &kem_ss_len);
  if( rc != PQC_OK ) goto done;

  memcpy(backup_key, kem_ss, 32);
  pqc_secure_wipe(kem_ss, sizeof(kem_ss));

  /* Get page size and count */
  {
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(db, "PRAGMA page_size", -1, &stmt, NULL);
    if( sqlite3_step(stmt) == SQLITE_ROW ){
      page_size = sqlite3_column_int(stmt, 0);
    }else{
      page_size = 4096;
    }
    sqlite3_finalize(stmt);

    sqlite3_prepare_v2(db, "PRAGMA page_count", -1, &stmt, NULL);
    if( sqlite3_step(stmt) == SQLITE_ROW ){
      total_pages = sqlite3_column_int(stmt, 0);
    }else{
      total_pages = 0;
    }
    sqlite3_finalize(stmt);
  }

  /* Open output file */
  fp = fopen(backup_path, "wb");
  if( !fp ){ rc = PQC_ERROR; goto done; }

  /* Initialize hash for signing */
  hash_ctx = EVP_MD_CTX_new();
  if( !hash_ctx ){ rc = PQC_ERROR; goto done; }
  EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL);

  /* Write header */
  fwrite(PQLITE_BACKUP_MAGIC, 1, 8, fp);
  EVP_DigestUpdate(hash_ctx, PQLITE_BACKUP_MAGIC, 8);

  write_be32(header, 1); /* version */
  fwrite(header, 1, 4, fp);
  EVP_DigestUpdate(hash_ctx, header, 4);

  write_be32(header, (uint32_t)opts->kem_alg);
  fwrite(header, 1, 4, fp);
  EVP_DigestUpdate(hash_ctx, header, 4);

  write_be32(header, (uint32_t)opts->sig_alg);
  fwrite(header, 1, 4, fp);
  EVP_DigestUpdate(hash_ctx, header, 4);

  write_be32(header, (uint32_t)page_size);
  fwrite(header, 1, 4, fp);
  EVP_DigestUpdate(hash_ctx, header, 4);

  write_be32(header, (uint32_t)total_pages);
  fwrite(header, 1, 4, fp);
  EVP_DigestUpdate(hash_ctx, header, 4);

  /* Write KEM ciphertext */
  write_be32(header, (uint32_t)kem_ct_len);
  fwrite(header, 1, 4, fp);
  fwrite(kem_ct, 1, kem_ct_len, fp);
  EVP_DigestUpdate(hash_ctx, header, 4);
  EVP_DigestUpdate(hash_ctx, kem_ct, kem_ct_len);

  /* Write signing public key */
  write_be32(header, (uint32_t)sig_kp.pk_len);
  fwrite(header, 1, 4, fp);
  fwrite(sig_kp.public_key, 1, sig_kp.pk_len, fp);
  EVP_DigestUpdate(hash_ctx, header, 4);
  EVP_DigestUpdate(hash_ctx, sig_kp.public_key, sig_kp.pk_len);

  /* Copy database to in-memory, then encrypt and write each page */
  rc = sqlite3_open(":memory:", &mem_db);
  if( rc != SQLITE_OK ){ rc = PQC_ERROR; goto done; }

  bk = sqlite3_backup_init(mem_db, "main", db, "main");
  if( !bk ){ rc = PQC_ERROR; goto done; }

  sqlite3_backup_step(bk, -1);
  sqlite3_backup_finish(bk);
  bk = NULL;

  /* Read each page from mem_db, encrypt, write to backup */
  {
    sqlite3_stmt *stmt = NULL;
    uint8_t *page_buf = (uint8_t *)malloc(page_size + 16); /* + GCM tag */
    uint8_t iv[12];
    uint8_t tag[16];
    int pgno;

    if( !page_buf ){ rc = PQC_NOMEM; goto done; }

    for(pgno = 1; pgno <= total_pages; pgno++){
      /* Read page via dbpage virtual table or file I/O */
      char sql[64];
      snprintf(sql, sizeof(sql),
        "SELECT data FROM sqlite_dbpage WHERE pgno=%d", pgno);
      rc = sqlite3_prepare_v2(mem_db, sql, -1, &stmt, NULL);
      if( rc != SQLITE_OK || sqlite3_step(stmt) != SQLITE_ROW ){
        sqlite3_finalize(stmt);
        continue;
      }

      const uint8_t *page_data = (const uint8_t *)sqlite3_column_blob(stmt, 0);
      int data_len = sqlite3_column_bytes(stmt, 0);

      /* Encrypt page with AES-256-GCM using backup_key */
      {
        EVP_CIPHER_CTX *enc = EVP_CIPHER_CTX_new();
        int len;
        uint8_t pgno_buf[4];
        write_be32(pgno_buf, (uint32_t)pgno);

        /* Derive per-page IV from page number */
        memset(iv, 0, 12);
        memcpy(iv, pgno_buf, 4);

        EVP_EncryptInit_ex(enc, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
        EVP_EncryptInit_ex(enc, NULL, NULL, backup_key, iv);
        EVP_EncryptUpdate(enc, NULL, &len, pgno_buf, 4); /* AAD */
        EVP_EncryptUpdate(enc, page_buf, &len, page_data, data_len);
        EVP_EncryptFinal_ex(enc, page_buf + len, &len);
        EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_GCM_GET_TAG, 16, tag);
        EVP_CIPHER_CTX_free(enc);
      }

      /* Write encrypted page + tag */
      memcpy(page_buf + data_len, tag, 16);
      fwrite(page_buf, 1, data_len + 16, fp);
      EVP_DigestUpdate(hash_ctx, page_buf, data_len + 16);

      sqlite3_finalize(stmt);
      stmt = NULL;
    }
    free(page_buf);
  }

  /* Compute final hash and sign with ML-DSA */
  {
    uint8_t backup_hash[32];
    unsigned int hash_len = 32;
    EVP_DigestFinal_ex(hash_ctx, backup_hash, &hash_len);

    uint8_t *signature = (uint8_t *)malloc(sig_info->sig_len);
    size_t sig_len = sig_info->sig_len;
    if( !signature ){ rc = PQC_NOMEM; goto done; }

    rc = pqc_sig_sign(&sig_kp, backup_hash, 32, signature, &sig_len);
    if( rc != PQC_OK ){
      free(signature);
      goto done;
    }

    /* Write signature */
    write_be32(header, (uint32_t)sig_len);
    fwrite(header, 1, 4, fp);
    fwrite(signature, 1, sig_len, fp);
    free(signature);
  }

  rc = PQC_OK;

done:
  pqc_secure_wipe(backup_key, sizeof(backup_key));
  pqc_kem_keypair_free(&kem_kp);
  pqc_sig_keypair_free(&sig_kp);
  if( kem_ct ) free(kem_ct);
  if( hash_ctx ) EVP_MD_CTX_free(hash_ctx);
  if( bk ) sqlite3_backup_finish(bk);
  if( mem_db ) sqlite3_close(mem_db);
  if( fp ) fclose(fp);
  return rc;
}

/*
** Verify a backup file's signature.
*/
int pqc_backup_verify(const char *backup_path){
  FILE *fp = NULL;
  uint8_t magic[8];
  uint8_t buf[4];
  uint32_t version, kem_alg, sig_alg, page_size, total_pages;
  uint32_t kem_ct_len, sig_pk_len, sig_len;
  uint8_t *sig_pk = NULL, *signature = NULL;
  EVP_MD_CTX *hash_ctx = NULL;
  PqcSigKeypair verify_kp;
  long data_end;
  int rc = PQC_ERROR;

  memset(&verify_kp, 0, sizeof(verify_kp));

  fp = fopen(backup_path, "rb");
  if( !fp ) return PQC_ERROR;

  /* Read and verify magic */
  if( fread(magic, 1, 8, fp) != 8 ) goto done;
  if( memcmp(magic, PQLITE_BACKUP_MAGIC, 8) != 0 ) goto done;

  /* Read header fields */
  fread(buf, 1, 4, fp); version = read_be32(buf);
  fread(buf, 1, 4, fp); kem_alg = read_be32(buf);
  fread(buf, 1, 4, fp); sig_alg = read_be32(buf);
  fread(buf, 1, 4, fp); page_size = read_be32(buf);
  fread(buf, 1, 4, fp); total_pages = read_be32(buf);

  /* Skip KEM ciphertext */
  fread(buf, 1, 4, fp); kem_ct_len = read_be32(buf);
  fseek(fp, (long)kem_ct_len, SEEK_CUR);

  /* Read SIG public key */
  fread(buf, 1, 4, fp); sig_pk_len = read_be32(buf);
  sig_pk = (uint8_t *)malloc(sig_pk_len);
  if( !sig_pk ) goto done;
  fread(sig_pk, 1, sig_pk_len, fp);

  /* Import public key for verification */
  rc = pqc_sig_import_public_key((PqcSigAlgorithm)sig_alg,
                                   sig_pk, sig_pk_len, &verify_kp);
  if( rc != PQC_OK ) goto done;

  /* Hash everything up to the signature */
  {
    long current_pos = ftell(fp);
    long encrypted_data_size = (long)total_pages * ((long)page_size + 16);

    /* Skip encrypted pages to find signature */
    fseek(fp, encrypted_data_size, SEEK_CUR);
    data_end = ftell(fp);

    /* Read signature */
    fread(buf, 1, 4, fp); sig_len = read_be32(buf);
    signature = (uint8_t *)malloc(sig_len);
    if( !signature ) goto done;
    fread(signature, 1, sig_len, fp);

    /* Now hash everything from start to data_end */
    fseek(fp, 0, SEEK_SET);
    hash_ctx = EVP_MD_CTX_new();
    if( !hash_ctx ) goto done;
    EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL);

    {
      uint8_t chunk[4096];
      long remaining = data_end;
      while( remaining > 0 ){
        size_t to_read = (remaining > 4096) ? 4096 : (size_t)remaining;
        size_t n = fread(chunk, 1, to_read, fp);
        if( n == 0 ) break;
        EVP_DigestUpdate(hash_ctx, chunk, n);
        remaining -= (long)n;
      }
    }

    uint8_t backup_hash[32];
    unsigned int hash_len = 32;
    EVP_DigestFinal_ex(hash_ctx, backup_hash, &hash_len);

    /* Verify ML-DSA signature */
    rc = pqc_sig_verify(&verify_kp, backup_hash, 32,
                          signature, (size_t)sig_len);
  }

done:
  pqc_sig_keypair_free(&verify_kp);
  if( sig_pk ) free(sig_pk);
  if( signature ) free(signature);
  if( hash_ctx ) EVP_MD_CTX_free(hash_ctx);
  if( fp ) fclose(fp);
  return rc;
}

/*
** Get backup metadata as JSON.
*/
char *pqc_backup_info(const char *backup_path){
  FILE *fp;
  uint8_t magic[8], buf[4];
  uint32_t version, kem_alg, sig_alg, page_size, total_pages;

  fp = fopen(backup_path, "rb");
  if( !fp ) return NULL;

  fread(magic, 1, 8, fp);
  if( memcmp(magic, PQLITE_BACKUP_MAGIC, 8) != 0 ){
    fclose(fp);
    return NULL;
  }

  fread(buf, 1, 4, fp); version = read_be32(buf);
  fread(buf, 1, 4, fp); kem_alg = read_be32(buf);
  fread(buf, 1, 4, fp); sig_alg = read_be32(buf);
  fread(buf, 1, 4, fp); page_size = read_be32(buf);
  fread(buf, 1, 4, fp); total_pages = read_be32(buf);
  fclose(fp);

  return sqlite3_mprintf(
    "{\"format\":\"PQLite Backup v%u\","
    "\"kem_algorithm\":\"%s\","
    "\"sig_algorithm\":\"%s\","
    "\"page_size\":%u,"
    "\"total_pages\":%u,"
    "\"estimated_size_mb\":%.1f}",
    version,
    pqc_kem_alg_name((PqcKemAlgorithm)kem_alg),
    pqc_sig_alg_name((PqcSigAlgorithm)sig_alg),
    page_size, total_pages,
    (double)(total_pages * page_size) / (1024.0 * 1024.0));
}

#endif /* PQLITE_ENABLE_PQC */
