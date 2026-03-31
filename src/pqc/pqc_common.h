/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** PQC Common Definitions - Algorithm Registry & liboqs Wrapper
**
** This file provides the core PQC type definitions, algorithm enumeration,
** and initialization/cleanup routines that wrap the Open Quantum Safe (liboqs)
** library. All PQC code in PQLite is guarded by PQLITE_ENABLE_PQC.
*/
#ifndef PQLITE_PQC_COMMON_H
#define PQLITE_PQC_COMMON_H

#ifdef PQLITE_ENABLE_PQC

#include <stdint.h>
#include <stddef.h>

/*
** Return codes
*/
#define PQC_OK          0
#define PQC_ERROR      -1
#define PQC_NOMEM      -2
#define PQC_UNSUPPORTED -3
#define PQC_VERIFY_FAIL -4
#define PQC_DECRYPT_FAIL -5

/*
** Key Encapsulation Mechanism (KEM) algorithms
** Based on NIST FIPS 203 (ML-KEM / CRYSTALS-Kyber)
*/
typedef enum {
  PQC_KEM_ML_KEM_512  = 0,   /* NIST Level 1 — 128-bit security */
  PQC_KEM_ML_KEM_768  = 1,   /* NIST Level 3 — 192-bit security (DEFAULT) */
  PQC_KEM_ML_KEM_1024 = 2,   /* NIST Level 5 — 256-bit security (CNSA 2.0) */
  PQC_KEM_COUNT        = 3
} PqcKemAlgorithm;

/*
** Digital Signature algorithms
** Based on NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium)
** and NIST FIPS 205 (SLH-DSA / SPHINCS+)
*/
typedef enum {
  /* ML-DSA (Module-Lattice Digital Signature Algorithm) */
  PQC_SIG_ML_DSA_44           = 0,   /* NIST Level 2 */
  PQC_SIG_ML_DSA_65           = 1,   /* NIST Level 3 (DEFAULT) */
  PQC_SIG_ML_DSA_87           = 2,   /* NIST Level 5 (CNSA 2.0) */

  /* SLH-DSA with SHA-2 backend */
  PQC_SIG_SLH_DSA_SHA2_128s   = 3,
  PQC_SIG_SLH_DSA_SHA2_128f   = 4,
  PQC_SIG_SLH_DSA_SHA2_192s   = 5,
  PQC_SIG_SLH_DSA_SHA2_192f   = 6,
  PQC_SIG_SLH_DSA_SHA2_256s   = 7,
  PQC_SIG_SLH_DSA_SHA2_256f   = 8,

  /* SLH-DSA with SHAKE backend */
  PQC_SIG_SLH_DSA_SHAKE_128s  = 9,
  PQC_SIG_SLH_DSA_SHAKE_128f  = 10,
  PQC_SIG_SLH_DSA_SHAKE_192s  = 11,
  PQC_SIG_SLH_DSA_SHAKE_192f  = 12,
  PQC_SIG_SLH_DSA_SHAKE_256s  = 13,
  PQC_SIG_SLH_DSA_SHAKE_256f  = 14,

  PQC_SIG_COUNT                = 15
} PqcSigAlgorithm;

/*
** Algorithm metadata — populated from liboqs at runtime
*/
typedef struct PqcKemInfo {
  const char *name;            /* liboqs algorithm name string */
  const char *display_name;    /* Human-readable name */
  int nist_level;              /* NIST security level (1, 3, or 5) */
  size_t pk_len;               /* Public key length in bytes */
  size_t sk_len;               /* Secret key length in bytes */
  size_t ct_len;               /* Ciphertext length in bytes */
  size_t ss_len;               /* Shared secret length in bytes */
} PqcKemInfo;

typedef struct PqcSigInfo {
  const char *name;            /* liboqs algorithm name string */
  const char *display_name;    /* Human-readable name */
  int nist_level;              /* NIST security level */
  size_t pk_len;               /* Public key length */
  size_t sk_len;               /* Secret key length */
  size_t sig_len;              /* Maximum signature length */
} PqcSigInfo;

/*
** Global PQC state — initialized once via pqc_init()
*/
typedef struct PqcGlobal {
  int initialized;
  PqcKemInfo kem_info[PQC_KEM_COUNT];
  PqcSigInfo sig_info[PQC_SIG_COUNT];
} PqcGlobal;

/*
** Initialization and cleanup
*/
int pqc_init(void);
void pqc_cleanup(void);

/*
** Algorithm info lookups
*/
const PqcKemInfo *pqc_kem_get_info(PqcKemAlgorithm alg);
const PqcSigInfo *pqc_sig_get_info(PqcSigAlgorithm alg);
const char *pqc_kem_alg_name(PqcKemAlgorithm alg);
const char *pqc_sig_alg_name(PqcSigAlgorithm alg);

/*
** Parse algorithm from string (returns -1 on failure)
*/
int pqc_kem_alg_from_name(const char *name);
int pqc_sig_alg_from_name(const char *name);

/*
** Version string
*/
const char *pqc_version(void);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_COMMON_H */
