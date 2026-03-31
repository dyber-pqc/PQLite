/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Key Management Provider Framework
**
** Supports multiple key storage backends:
**   - PASSWORD: User-supplied password (default, PBKDF2 derivation)
**   - FILE:     Read raw key from a protected file
**   - ENV:      Read key from environment variable
**   - COMMAND:  Execute external command to retrieve key
**   - KEYCHAIN: OS keychain (macOS Keychain, Windows DPAPI, Linux Secret Service)
**   - PKCS11:   Hardware Security Module via PKCS#11 interface
**
** SQL Interface:
**   PRAGMA pqc_key_provider='file';
**   PRAGMA pqc_key_file='/secure/path/db.key';
**   PRAGMA pqc_key_command='/usr/bin/vault read secret/db-key';
**
** NO other SQLite fork provides pluggable key management.
**
** PQLite is a product of Dyber, Inc.
*/
#ifndef PQLITE_PQC_KEYMANAGER_H
#define PQLITE_PQC_KEYMANAGER_H

#ifdef PQLITE_ENABLE_PQC

#include "pqc_common.h"
#include <stdint.h>
#include <stddef.h>

/*
** Key provider types
*/
typedef enum {
  PQC_KEYPROV_PASSWORD  = 0,  /* User password + PBKDF2 (default) */
  PQC_KEYPROV_FILE      = 1,  /* Read from file */
  PQC_KEYPROV_ENV       = 2,  /* Environment variable */
  PQC_KEYPROV_COMMAND   = 3,  /* External command output */
  PQC_KEYPROV_KEYCHAIN  = 4,  /* OS keychain / credential store */
  PQC_KEYPROV_PKCS11    = 5,  /* Hardware Security Module */
} PqcKeyProviderType;

/*
** Key provider configuration
*/
typedef struct PqcKeyProvider {
  PqcKeyProviderType type;
  char *param;                  /* File path, env var name, command, etc. */
  char *pkcs11_module;          /* PKCS#11 .so/.dll path */
  char *pkcs11_token_label;     /* PKCS#11 token label */
  char *pkcs11_pin;             /* PKCS#11 PIN (will be wiped after use) */
  unsigned long pkcs11_key_id;  /* PKCS#11 key object ID */
} PqcKeyProvider;

/*
** Retrieve a key using the configured provider.
** The key is written to out_key (must be >= 32 bytes).
** Returns PQC_OK on success.
*/
int pqc_key_retrieve(const PqcKeyProvider *provider,
                       uint8_t *out_key, size_t key_len);

/*
** Store a key using the configured provider (for key rotation).
** Only supported for FILE, KEYCHAIN, and PKCS11 providers.
*/
int pqc_key_store(const PqcKeyProvider *provider,
                    const uint8_t *key, size_t key_len);

/*
** Free provider resources and wipe sensitive params.
*/
void pqc_key_provider_free(PqcKeyProvider *provider);

/*
** OS Keychain operations (platform-specific implementations)
*/
#ifdef __APPLE__
/* macOS Keychain Services */
int pqc_keychain_store(const char *service, const char *account,
                         const uint8_t *key, size_t key_len);
int pqc_keychain_retrieve(const char *service, const char *account,
                            uint8_t *key, size_t *key_len);
int pqc_keychain_delete(const char *service, const char *account);
#endif

#ifdef _WIN32
/* Windows DPAPI (Data Protection API) */
int pqc_dpapi_encrypt(const uint8_t *plaintext, size_t pt_len,
                        uint8_t **ciphertext, size_t *ct_len);
int pqc_dpapi_decrypt(const uint8_t *ciphertext, size_t ct_len,
                        uint8_t **plaintext, size_t *pt_len);
#endif

#ifdef __linux__
/* Linux Secret Service (via libsecret / D-Bus) */
int pqc_secret_service_store(const char *label, const char *attribute,
                               const uint8_t *key, size_t key_len);
int pqc_secret_service_retrieve(const char *label, const char *attribute,
                                  uint8_t *key, size_t *key_len);
#endif

/*
** Key rotation: re-encrypt database with key from a new provider.
**
** @param db              Database connection
** @param old_provider    Current key provider
** @param new_provider    New key provider
** @return PQC_OK on success
*/
int pqc_key_rotate(void *db, /* sqlite3* */
                     const PqcKeyProvider *old_provider,
                     const PqcKeyProvider *new_provider);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_KEYMANAGER_H */
