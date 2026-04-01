/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Key Management Provider — Implementation
**
** Retrieves database encryption keys from various backends.
** The key never touches disk unprotected (except for the FILE
** provider, where the file must be permission-protected).
**
** PQLite is a product of Dyber, Inc.
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_keymanager.h"
#include "pqc_mem.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef _WIN32
#include <sys/stat.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <dpapi.h>
#pragma comment(lib, "crypt32.lib")
#endif

#ifdef __APPLE__
#include <Security/Security.h>
#endif

/*
** FILE provider: read raw key bytes from a file.
** The key file should contain exactly 32 bytes (256-bit key).
** File must be protected by OS permissions (chmod 600).
*/
static int key_from_file(const char *path, uint8_t *out, size_t len){
  FILE *fp;
  size_t n;

  if( !path ) return PQC_ERROR;

  fp = fopen(path, "rb");
  if( !fp ) return PQC_ERROR;

  n = fread(out, 1, len, fp);
  fclose(fp);

  if( n != len ) return PQC_ERROR;
  return PQC_OK;
}

/*
** ENV provider: read key from an environment variable (hex-encoded).
*/
static int key_from_env(const char *var_name, uint8_t *out, size_t len){
  const char *hex;
  size_t hex_len, i;

  if( !var_name ) return PQC_ERROR;

  hex = getenv(var_name);
  if( !hex ) return PQC_ERROR;

  hex_len = strlen(hex);
  if( hex_len != len * 2 ) return PQC_ERROR;

  for(i = 0; i < len; i++){
    uint8_t hi, lo;
    char c;
    c = hex[i*2];
    if( c >= '0' && c <= '9' ) hi = c - '0';
    else if( c >= 'a' && c <= 'f' ) hi = c - 'a' + 10;
    else if( c >= 'A' && c <= 'F' ) hi = c - 'A' + 10;
    else return PQC_ERROR;
    c = hex[i*2+1];
    if( c >= '0' && c <= '9' ) lo = c - '0';
    else if( c >= 'a' && c <= 'f' ) lo = c - 'a' + 10;
    else if( c >= 'A' && c <= 'F' ) lo = c - 'A' + 10;
    else return PQC_ERROR;
    out[i] = (hi << 4) | lo;
  }

  return PQC_OK;
}

/*
** COMMAND provider: execute a command and read key from stdout.
** Useful for integration with HashiCorp Vault, AWS KMS CLI, etc.
**
** The command should output exactly 32 hex-encoded bytes (64 chars).
*/
static int key_from_command(const char *command, uint8_t *out, size_t len){
  FILE *fp;
  char hex_buf[128];
  size_t n, i;

  if( !command ) return PQC_ERROR;

#ifdef _WIN32
  fp = _popen(command, "r");
#else
  fp = popen(command, "r");
#endif
  if( !fp ) return PQC_ERROR;

  n = fread(hex_buf, 1, sizeof(hex_buf) - 1, fp);

#ifdef _WIN32
  _pclose(fp);
#else
  pclose(fp);
#endif

  if( n < len * 2 ) return PQC_ERROR;
  hex_buf[n] = '\0';

  /* Strip trailing whitespace */
  while( n > 0 && (hex_buf[n-1] == '\n' || hex_buf[n-1] == '\r' ||
         hex_buf[n-1] == ' ') ){
    hex_buf[--n] = '\0';
  }

  if( n != len * 2 ) return PQC_ERROR;

  /* Decode hex */
  for(i = 0; i < len; i++){
    uint8_t hi, lo;
    char c;
    c = hex_buf[i*2];
    if( c >= '0' && c <= '9' ) hi = c - '0';
    else if( c >= 'a' && c <= 'f' ) hi = c - 'a' + 10;
    else if( c >= 'A' && c <= 'F' ) hi = c - 'A' + 10;
    else{ pqc_secure_wipe(hex_buf, sizeof(hex_buf)); return PQC_ERROR; }
    c = hex_buf[i*2+1];
    if( c >= '0' && c <= '9' ) lo = c - '0';
    else if( c >= 'a' && c <= 'f' ) lo = c - 'a' + 10;
    else if( c >= 'A' && c <= 'F' ) lo = c - 'A' + 10;
    else{ pqc_secure_wipe(hex_buf, sizeof(hex_buf)); return PQC_ERROR; }
    out[i] = (hi << 4) | lo;
  }

  pqc_secure_wipe(hex_buf, sizeof(hex_buf));
  return PQC_OK;
}

#ifdef _WIN32
/*
** Windows DPAPI: encrypt data with user's login credentials.
*/
int pqc_dpapi_encrypt(const uint8_t *plaintext, size_t pt_len,
                        uint8_t **ciphertext, size_t *ct_len){
  DATA_BLOB in_blob, out_blob;
  in_blob.pbData = (BYTE *)plaintext;
  in_blob.cbData = (DWORD)pt_len;

  if( !CryptProtectData(&in_blob, L"PQLite Key", NULL, NULL, NULL,
                          CRYPTPROTECT_UI_FORBIDDEN, &out_blob) ){
    return PQC_ERROR;
  }

  *ciphertext = (uint8_t *)malloc(out_blob.cbData);
  if( !*ciphertext ){
    LocalFree(out_blob.pbData);
    return PQC_NOMEM;
  }
  memcpy(*ciphertext, out_blob.pbData, out_blob.cbData);
  *ct_len = out_blob.cbData;
  LocalFree(out_blob.pbData);
  return PQC_OK;
}

int pqc_dpapi_decrypt(const uint8_t *ciphertext, size_t ct_len,
                        uint8_t **plaintext, size_t *pt_len){
  DATA_BLOB in_blob, out_blob;
  in_blob.pbData = (BYTE *)ciphertext;
  in_blob.cbData = (DWORD)ct_len;

  if( !CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL,
                            CRYPTPROTECT_UI_FORBIDDEN, &out_blob) ){
    return PQC_ERROR;
  }

  *plaintext = (uint8_t *)pqc_secure_alloc(out_blob.cbData);
  if( !*plaintext ){
    LocalFree(out_blob.pbData);
    return PQC_NOMEM;
  }
  memcpy(*plaintext, out_blob.pbData, out_blob.cbData);
  *pt_len = out_blob.cbData;
  LocalFree(out_blob.pbData);
  return PQC_OK;
}
#endif /* _WIN32 */

#ifdef __APPLE__
/*
** macOS Keychain: store and retrieve keys.
*/
int pqc_keychain_store(const char *service, const char *account,
                         const uint8_t *key, size_t key_len){
  OSStatus status;
  /* Delete existing item first */
  pqc_keychain_delete(service, account);

  status = SecKeychainAddGenericPassword(
    NULL,                           /* default keychain */
    (UInt32)strlen(service), service,
    (UInt32)strlen(account), account,
    (UInt32)key_len, key,
    NULL                            /* item ref */
  );

  return (status == errSecSuccess) ? PQC_OK : PQC_ERROR;
}

int pqc_keychain_retrieve(const char *service, const char *account,
                            uint8_t *key, size_t *key_len){
  OSStatus status;
  UInt32 pw_len = 0;
  void *pw_data = NULL;

  status = SecKeychainFindGenericPassword(
    NULL,
    (UInt32)strlen(service), service,
    (UInt32)strlen(account), account,
    &pw_len, &pw_data,
    NULL
  );

  if( status != errSecSuccess ) return PQC_ERROR;
  if( pw_len > *key_len ){
    SecKeychainItemFreeContent(NULL, pw_data);
    return PQC_ERROR;
  }

  memcpy(key, pw_data, pw_len);
  *key_len = pw_len;
  SecKeychainItemFreeContent(NULL, pw_data);
  return PQC_OK;
}

int pqc_keychain_delete(const char *service, const char *account){
  OSStatus status;
  SecKeychainItemRef item = NULL;

  status = SecKeychainFindGenericPassword(
    NULL,
    (UInt32)strlen(service), service,
    (UInt32)strlen(account), account,
    NULL, NULL, &item);

  if( status == errSecSuccess && item ){
    SecKeychainItemDelete(item);
    CFRelease(item);
  }
  return PQC_OK;
}
#endif /* __APPLE__ */

/*
** Retrieve a key using the configured provider.
*/
int pqc_key_retrieve(const PqcKeyProvider *provider,
                       uint8_t *out_key, size_t key_len){
  if( !provider || !out_key ) return PQC_ERROR;

  switch( provider->type ){
    case PQC_KEYPROV_FILE:
      return key_from_file(provider->param, out_key, key_len);

    case PQC_KEYPROV_ENV:
      return key_from_env(provider->param, out_key, key_len);

    case PQC_KEYPROV_COMMAND:
      return key_from_command(provider->param, out_key, key_len);

    case PQC_KEYPROV_KEYCHAIN:
#ifdef __APPLE__
      {
        size_t len = key_len;
        return pqc_keychain_retrieve("PQLite", provider->param, out_key, &len);
      }
#elif defined(_WIN32)
      {
        /* Read DPAPI-encrypted key from file, then decrypt */
        uint8_t enc_buf[512];
        FILE *fp = fopen(provider->param, "rb");
        if( !fp ) return PQC_ERROR;
        size_t n = fread(enc_buf, 1, sizeof(enc_buf), fp);
        fclose(fp);

        uint8_t *decrypted = NULL;
        size_t dec_len = 0;
        int rc = pqc_dpapi_decrypt(enc_buf, n, &decrypted, &dec_len);
        if( rc != PQC_OK ) return rc;
        if( dec_len < key_len ){
          pqc_secure_free(decrypted, dec_len);
          return PQC_ERROR;
        }
        memcpy(out_key, decrypted, key_len);
        pqc_secure_free(decrypted, dec_len);
        return PQC_OK;
      }
#else
      return PQC_UNSUPPORTED;
#endif

    case PQC_KEYPROV_PASSWORD:
      /* Password provider is handled at a higher level (PBKDF2) */
      return PQC_ERROR;

    case PQC_KEYPROV_PKCS11:
      /* PKCS#11 requires more complex setup — placeholder for HSM integration.
      ** A full implementation would use dlopen() to load the PKCS#11 module,
      ** call C_Initialize, C_OpenSession, C_Login, C_FindObjects to locate
      ** the key, then C_GetAttributeValue to extract the key bytes. */
      return PQC_UNSUPPORTED;

    default:
      return PQC_ERROR;
  }
}

/*
** Store a key using the configured provider.
*/
int pqc_key_store(const PqcKeyProvider *provider,
                    const uint8_t *key, size_t key_len){
  if( !provider || !key ) return PQC_ERROR;

  switch( provider->type ){
    case PQC_KEYPROV_FILE: {
      FILE *fp = fopen(provider->param, "wb");
      if( !fp ) return PQC_ERROR;
      fwrite(key, 1, key_len, fp);
      fclose(fp);
      /* Set restrictive permissions on Unix */
#ifndef _WIN32
      chmod(provider->param, 0600);
#endif
      return PQC_OK;
    }

    case PQC_KEYPROV_KEYCHAIN:
#ifdef __APPLE__
      return pqc_keychain_store("PQLite", provider->param, key, key_len);
#elif defined(_WIN32)
      {
        uint8_t *encrypted = NULL;
        size_t enc_len = 0;
        int rc = pqc_dpapi_encrypt(key, key_len, &encrypted, &enc_len);
        if( rc != PQC_OK ) return rc;
        FILE *fp = fopen(provider->param, "wb");
        if( !fp ){ free(encrypted); return PQC_ERROR; }
        fwrite(encrypted, 1, enc_len, fp);
        fclose(fp);
        free(encrypted);
        return PQC_OK;
      }
#else
      return PQC_UNSUPPORTED;
#endif

    default:
      return PQC_UNSUPPORTED;
  }
}

/*
** Free provider resources.
*/
void pqc_key_provider_free(PqcKeyProvider *provider){
  if( !provider ) return;
  if( provider->param ) free(provider->param);
  if( provider->pkcs11_module ) free(provider->pkcs11_module);
  if( provider->pkcs11_token_label ) free(provider->pkcs11_token_label);
  if( provider->pkcs11_pin ){
    pqc_secure_wipe(provider->pkcs11_pin, strlen(provider->pkcs11_pin));
    free(provider->pkcs11_pin);
  }
  memset(provider, 0, sizeof(*provider));
}

#endif /* PQLITE_ENABLE_PQC */
