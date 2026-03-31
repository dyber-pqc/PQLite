/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** PQC Common Implementation - Algorithm Registry & liboqs Wrapper
**
** Initializes the liboqs library, populates algorithm metadata tables,
** and provides lookup functions. All real crypto — no stubs.
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_common.h"
#include <oqs/oqs.h>
#include <string.h>
#include <stdio.h>

#define PQLITE_VERSION "1.0.0"
#define PQLITE_SQLITE_VERSION "3.53.0"

/*
** Global PQC state (module-level singleton)
*/
static PqcGlobal g_pqc = {0};

/*
** Mapping from PqcKemAlgorithm enum to liboqs algorithm name strings.
** These are the official NIST FIPS 203 algorithm identifiers as
** registered in the liboqs library.
*/
static const char *kem_oqs_names[PQC_KEM_COUNT] = {
  "ML-KEM-512",    /* PQC_KEM_ML_KEM_512  — FIPS 203, Level 1 */
  "ML-KEM-768",    /* PQC_KEM_ML_KEM_768  — FIPS 203, Level 3 */
  "ML-KEM-1024",   /* PQC_KEM_ML_KEM_1024 — FIPS 203, Level 5 */
};

static const char *kem_display_names[PQC_KEM_COUNT] = {
  "ML-KEM-512 (NIST Level 1)",
  "ML-KEM-768 (NIST Level 3)",
  "ML-KEM-1024 (NIST Level 5, CNSA 2.0)",
};

static const int kem_nist_levels[PQC_KEM_COUNT] = { 1, 3, 5 };

/*
** Mapping from PqcSigAlgorithm enum to liboqs algorithm name strings.
** ML-DSA: FIPS 204 (CRYSTALS-Dilithium)
** SLH-DSA: FIPS 205 (SPHINCS+)
*/
static const char *sig_oqs_names[PQC_SIG_COUNT] = {
  "ML-DSA-44",             /* PQC_SIG_ML_DSA_44 */
  "ML-DSA-65",             /* PQC_SIG_ML_DSA_65 */
  "ML-DSA-87",             /* PQC_SIG_ML_DSA_87 */
  "SLH-DSA-SHA2-128s",    /* PQC_SIG_SLH_DSA_SHA2_128s */
  "SLH-DSA-SHA2-128f",    /* PQC_SIG_SLH_DSA_SHA2_128f */
  "SLH-DSA-SHA2-192s",    /* PQC_SIG_SLH_DSA_SHA2_192s */
  "SLH-DSA-SHA2-192f",    /* PQC_SIG_SLH_DSA_SHA2_192f */
  "SLH-DSA-SHA2-256s",    /* PQC_SIG_SLH_DSA_SHA2_256s */
  "SLH-DSA-SHA2-256f",    /* PQC_SIG_SLH_DSA_SHA2_256f */
  "SLH-DSA-SHAKE-128s",   /* PQC_SIG_SLH_DSA_SHAKE_128s */
  "SLH-DSA-SHAKE-128f",   /* PQC_SIG_SLH_DSA_SHAKE_128f */
  "SLH-DSA-SHAKE-192s",   /* PQC_SIG_SLH_DSA_SHAKE_192s */
  "SLH-DSA-SHAKE-192f",   /* PQC_SIG_SLH_DSA_SHAKE_192f */
  "SLH-DSA-SHAKE-256s",   /* PQC_SIG_SLH_DSA_SHAKE_256s */
  "SLH-DSA-SHAKE-256f",   /* PQC_SIG_SLH_DSA_SHAKE_256f */
};

static const char *sig_display_names[PQC_SIG_COUNT] = {
  "ML-DSA-44 (NIST Level 2)",
  "ML-DSA-65 (NIST Level 3)",
  "ML-DSA-87 (NIST Level 5, CNSA 2.0)",
  "SLH-DSA-SHA2-128s (NIST Level 1, small)",
  "SLH-DSA-SHA2-128f (NIST Level 1, fast)",
  "SLH-DSA-SHA2-192s (NIST Level 3, small)",
  "SLH-DSA-SHA2-192f (NIST Level 3, fast)",
  "SLH-DSA-SHA2-256s (NIST Level 5, small)",
  "SLH-DSA-SHA2-256f (NIST Level 5, fast)",
  "SLH-DSA-SHAKE-128s (NIST Level 1, small)",
  "SLH-DSA-SHAKE-128f (NIST Level 1, fast)",
  "SLH-DSA-SHAKE-192s (NIST Level 3, small)",
  "SLH-DSA-SHAKE-192f (NIST Level 3, fast)",
  "SLH-DSA-SHAKE-256s (NIST Level 5, small)",
  "SLH-DSA-SHAKE-256f (NIST Level 5, fast)",
};

static const int sig_nist_levels[PQC_SIG_COUNT] = {
  2, 3, 5,              /* ML-DSA */
  1, 1, 3, 3, 5, 5,    /* SLH-DSA-SHA2 */
  1, 1, 3, 3, 5, 5,    /* SLH-DSA-SHAKE */
};

/*
** Initialize the PQC subsystem.
** Must be called once before any PQC operations.
** Calls OQS_init() and populates algorithm metadata from liboqs.
*/
int pqc_init(void){
  int i;
  OQS_KEM *kem;
  OQS_SIG *sig;

  if( g_pqc.initialized ) return PQC_OK;

  /* Initialize liboqs */
  OQS_init();

  /* Populate KEM algorithm info from liboqs */
  for(i = 0; i < PQC_KEM_COUNT; i++){
    kem = OQS_KEM_new(kem_oqs_names[i]);
    if( kem == NULL ){
      /* Algorithm not available in this liboqs build */
      g_pqc.kem_info[i].name = kem_oqs_names[i];
      g_pqc.kem_info[i].display_name = kem_display_names[i];
      g_pqc.kem_info[i].nist_level = kem_nist_levels[i];
      g_pqc.kem_info[i].pk_len = 0;
      g_pqc.kem_info[i].sk_len = 0;
      g_pqc.kem_info[i].ct_len = 0;
      g_pqc.kem_info[i].ss_len = 0;
      continue;
    }
    g_pqc.kem_info[i].name = kem_oqs_names[i];
    g_pqc.kem_info[i].display_name = kem_display_names[i];
    g_pqc.kem_info[i].nist_level = kem_nist_levels[i];
    g_pqc.kem_info[i].pk_len = kem->length_public_key;
    g_pqc.kem_info[i].sk_len = kem->length_secret_key;
    g_pqc.kem_info[i].ct_len = kem->length_ciphertext;
    g_pqc.kem_info[i].ss_len = kem->length_shared_secret;
    OQS_KEM_free(kem);
  }

  /* Populate SIG algorithm info from liboqs */
  for(i = 0; i < PQC_SIG_COUNT; i++){
    sig = OQS_SIG_new(sig_oqs_names[i]);
    if( sig == NULL ){
      g_pqc.sig_info[i].name = sig_oqs_names[i];
      g_pqc.sig_info[i].display_name = sig_display_names[i];
      g_pqc.sig_info[i].nist_level = sig_nist_levels[i];
      g_pqc.sig_info[i].pk_len = 0;
      g_pqc.sig_info[i].sk_len = 0;
      g_pqc.sig_info[i].sig_len = 0;
      continue;
    }
    g_pqc.sig_info[i].name = sig_oqs_names[i];
    g_pqc.sig_info[i].display_name = sig_display_names[i];
    g_pqc.sig_info[i].nist_level = sig_nist_levels[i];
    g_pqc.sig_info[i].pk_len = sig->length_public_key;
    g_pqc.sig_info[i].sk_len = sig->length_secret_key;
    g_pqc.sig_info[i].sig_len = sig->length_signature;
    OQS_SIG_free(sig);
  }

  g_pqc.initialized = 1;
  return PQC_OK;
}

/*
** Cleanup the PQC subsystem. Wipes global state.
*/
void pqc_cleanup(void){
  if( !g_pqc.initialized ) return;
  OQS_destroy();
  memset(&g_pqc, 0, sizeof(g_pqc));
}

/*
** Look up KEM algorithm metadata.
*/
const PqcKemInfo *pqc_kem_get_info(PqcKemAlgorithm alg){
  if( alg < 0 || alg >= PQC_KEM_COUNT ) return NULL;
  if( !g_pqc.initialized ) return NULL;
  if( g_pqc.kem_info[alg].pk_len == 0 ) return NULL;  /* not available */
  return &g_pqc.kem_info[alg];
}

/*
** Look up SIG algorithm metadata.
*/
const PqcSigInfo *pqc_sig_get_info(PqcSigAlgorithm alg){
  if( alg < 0 || alg >= PQC_SIG_COUNT ) return NULL;
  if( !g_pqc.initialized ) return NULL;
  if( g_pqc.sig_info[alg].pk_len == 0 ) return NULL;
  return &g_pqc.sig_info[alg];
}

/*
** Get the liboqs algorithm name for a KEM.
*/
const char *pqc_kem_alg_name(PqcKemAlgorithm alg){
  if( alg < 0 || alg >= PQC_KEM_COUNT ) return NULL;
  return kem_oqs_names[alg];
}

/*
** Get the liboqs algorithm name for a SIG.
*/
const char *pqc_sig_alg_name(PqcSigAlgorithm alg){
  if( alg < 0 || alg >= PQC_SIG_COUNT ) return NULL;
  return sig_oqs_names[alg];
}

/*
** Parse a KEM algorithm from its string name.
** Case-insensitive comparison. Returns -1 if not found.
*/
int pqc_kem_alg_from_name(const char *name){
  int i;
  if( name == NULL ) return -1;
  for(i = 0; i < PQC_KEM_COUNT; i++){
    if( OQS_MEM_secure_bcmp == NULL ){
      /* Fallback: simple case-insensitive compare */
      const char *a = kem_oqs_names[i];
      const char *b = name;
      while( *a && *b ){
        char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
        if( ca != cb ) break;
        a++; b++;
      }
      if( *a == 0 && *b == 0 ) return i;
    }else{
      /* Use liboqs-provided compare where available */
      if( strlen(name) == strlen(kem_oqs_names[i]) ){
        const char *a = kem_oqs_names[i];
        const char *b = name;
        int match = 1;
        while( *a ){
          char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
          char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
          if( ca != cb ){ match = 0; break; }
          a++; b++;
        }
        if( match ) return i;
      }
    }
  }
  return -1;
}

/*
** Parse a SIG algorithm from its string name.
*/
int pqc_sig_alg_from_name(const char *name){
  int i;
  if( name == NULL ) return -1;
  for(i = 0; i < PQC_SIG_COUNT; i++){
    const char *a = sig_oqs_names[i];
    const char *b = name;
    int match = 1;
    while( *a && *b ){
      char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
      char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
      if( ca != cb ){ match = 0; break; }
      a++; b++;
    }
    if( match && *a == 0 && *b == 0 ) return i;
  }
  return -1;
}

/*
** Return the PQLite version string.
*/
const char *pqc_version(void){
  return "PQLite " PQLITE_VERSION " (based on SQLite " PQLITE_SQLITE_VERSION
         ", liboqs " OQS_VERSION_TEXT ")";
}

#endif /* PQLITE_ENABLE_PQC */
