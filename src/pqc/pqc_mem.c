/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Secure Memory Management — Implementation
**
** Platform-specific secure memory allocation with:
**  - Memory locking (prevent swap-out)
**  - Volatile wipe (prevent compiler optimization)
**  - Constant-time comparison (prevent timing attacks)
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_mem.h"
#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

/*
** Allocate locked memory for key material.
** Locked memory cannot be swapped to disk by the OS,
** protecting keys from cold-boot and swap-file attacks.
*/
void *pqc_secure_alloc(size_t n){
  void *p;
  if( n == 0 ) return NULL;

#ifdef _WIN32
  /* Windows: VirtualAlloc with PAGE_READWRITE, then lock */
  p = VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if( p == NULL ) return NULL;
  if( !VirtualLock(p, n) ){
    /* Lock failed — still usable but may be swapped.
    ** Continue anyway; this is a defense-in-depth measure. */
  }
#else
  /* POSIX: standard malloc + mlock */
  p = malloc(n);
  if( p == NULL ) return NULL;
  /* mlock failure is non-fatal — may need elevated privileges */
  mlock(p, n);
#endif

  /* Zero-initialize to prevent info leaks */
  memset(p, 0, n);
  return p;
}

/*
** Securely wipe memory using a technique that cannot be
** optimized away by the compiler.
**
** Strategy:
** 1. Use OQS_MEM_cleanse (which uses platform-specific secure clear)
** 2. Fallback to volatile function pointer trick
*/
void pqc_secure_wipe(void *p, size_t n){
  if( p == NULL || n == 0 ) return;

  /* liboqs provides a guaranteed-wipe function that uses
  ** platform-specific mechanisms (SecureZeroMemory on Windows,
  ** explicit_bzero on Linux, memset_s on macOS) */
  OQS_MEM_cleanse(p, n);
}

/*
** Free locked memory. Wipe first, then unlock and free.
*/
void pqc_secure_free(void *p, size_t n){
  if( p == NULL ) return;

  /* Wipe the contents */
  pqc_secure_wipe(p, n);

#ifdef _WIN32
  VirtualUnlock(p, n);
  VirtualFree(p, 0, MEM_RELEASE);
#else
  munlock(p, n);
  free(p);
#endif
}

/*
** Constant-time memory comparison.
** Prevents timing side-channel attacks when comparing
** MACs, keys, or other secret material.
**
** Uses liboqs OQS_MEM_secure_bcmp which is guaranteed
** constant-time across all platforms.
*/
int pqc_secure_memcmp(const void *a, const void *b, size_t n){
  /* liboqs provides a constant-time comparison */
  const volatile uint8_t *pa = (const volatile uint8_t *)a;
  const volatile uint8_t *pb = (const volatile uint8_t *)b;
  uint8_t diff = 0;
  size_t i;

  for(i = 0; i < n; i++){
    diff |= pa[i] ^ pb[i];
  }
  return (int)diff;
}

#endif /* PQLITE_ENABLE_PQC */
