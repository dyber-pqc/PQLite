/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Secure Memory Management
**
** Provides mlock'd allocations and guaranteed-wipe deallocation
** for cryptographic key material. Uses OS-level memory locking
** to prevent keys from being swapped to disk.
*/
#ifndef PQLITE_PQC_MEM_H
#define PQLITE_PQC_MEM_H

#ifdef PQLITE_ENABLE_PQC

#include <stddef.h>
#include <stdint.h>

/*
** Allocate memory for sensitive cryptographic material.
** On POSIX: uses mmap + mlock to prevent swapping.
** On Windows: uses VirtualAlloc + VirtualLock.
** Returns NULL on failure.
*/
void *pqc_secure_alloc(size_t n);

/*
** Securely wipe memory using a volatile write to prevent
** compiler optimization from eliding the clear.
** Uses OQS_MEM_cleanse when available, falls back to
** volatile memset.
*/
void pqc_secure_wipe(void *p, size_t n);

/*
** Wipe and free memory previously allocated with pqc_secure_alloc.
** Calls pqc_secure_wipe before unlocking and freeing.
*/
void pqc_secure_free(void *p, size_t n);

/*
** Constant-time memory comparison to prevent timing side-channels.
** Returns 0 if equal, non-zero otherwise.
*/
int pqc_secure_memcmp(const void *a, const void *b, size_t n);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_MEM_H */
