/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Dynamic Data Masking & Redaction — Implementation
**
** Masking is applied transparently at query time. The underlying
** data is never modified. Different roles see different views of
** the same data.
**
** Example:
**   Role 'admin':   SELECT ssn FROM employees → '123-45-6789'
**   Role 'analyst': SELECT ssn FROM employees → '***-**-6789'
**   Role 'public':  SELECT ssn FROM employees → '***'
**
** PQLite is a product of Dyber, Inc.
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_masking.h"
#include "pqc_mem.h"
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *MASK_CREATE_SQL =
  "CREATE TABLE IF NOT EXISTS _pqlite_mask_policies("
  "  id INTEGER PRIMARY KEY,"
  "  table_name TEXT NOT NULL,"
  "  column_name TEXT NOT NULL,"
  "  role TEXT,"
  "  mask_type INTEGER NOT NULL,"
  "  param1 INTEGER DEFAULT 0,"
  "  param2 INTEGER DEFAULT 0,"
  "  custom_func TEXT,"
  "  UNIQUE(table_name, column_name, role)"
  ")";

/*
** Apply FULL masking — replace entire value with '***'.
*/
static int mask_full(void **out, int *out_len, int *out_type){
  *out = sqlite3_mprintf("***");
  *out_len = 3;
  *out_type = SQLITE_TEXT;
  return PQC_OK;
}

/*
** Apply PARTIAL masking — show first/last N characters.
** Example: 'John Smith' with show_first=1, show_last=1 → 'J********h'
*/
static int mask_partial(const void *value, int value_len,
                          int show_first, int show_last,
                          void **out, int *out_len, int *out_type){
  const char *s = (const char *)value;
  char *masked;
  int i, mask_len;

  if( value_len <= show_first + show_last ){
    return mask_full(out, out_len, out_type);
  }

  masked = (char *)malloc(value_len + 1);
  if( !masked ) return PQC_NOMEM;

  mask_len = value_len - show_first - show_last;
  memcpy(masked, s, show_first);
  for(i = 0; i < mask_len; i++){
    masked[show_first + i] = '*';
  }
  memcpy(masked + show_first + mask_len, s + value_len - show_last, show_last);
  masked[value_len] = '\0';

  *out = masked;
  *out_len = value_len;
  *out_type = SQLITE_TEXT;
  return PQC_OK;
}

/*
** Apply EMAIL masking — mask local part, preserve domain suffix.
** 'john.doe@example.com' → 'j***@***.com'
*/
static int mask_email(const void *value, int value_len,
                        void **out, int *out_len, int *out_type){
  const char *s = (const char *)value;
  const char *at = NULL;
  const char *dot = NULL;
  char *masked;
  int i;

  /* Find @ and last . */
  for(i = 0; i < value_len; i++){
    if( s[i] == '@' && !at ) at = s + i;
    if( s[i] == '.' ) dot = s + i;
  }

  if( !at || !dot || dot <= at ){
    return mask_full(out, out_len, out_type);
  }

  masked = (char *)malloc(value_len + 1);
  if( !masked ) return PQC_NOMEM;

  /* Show first char, mask until @, show @, mask domain, show TLD */
  masked[0] = s[0];
  for(i = 1; i < (int)(at - s); i++) masked[i] = '*';
  masked[at - s] = '@';
  for(i = (int)(at - s) + 1; i < (int)(dot - s); i++) masked[i] = '*';
  memcpy(masked + (dot - s), dot, value_len - (int)(dot - s));
  masked[value_len] = '\0';

  *out = masked;
  *out_len = value_len;
  *out_type = SQLITE_TEXT;
  return PQC_OK;
}

/*
** Apply HASH masking — replace with SHA-256 hex string.
*/
static int mask_hash(const void *value, int value_len,
                       void **out, int *out_len, int *out_type){
  uint8_t hash[32];
  char *hex;
  unsigned int hash_len = 32;
  EVP_MD_CTX *ctx;
  int i;

  ctx = EVP_MD_CTX_new();
  if( !ctx ) return PQC_ERROR;

  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(ctx, value, value_len);
  EVP_DigestFinal_ex(ctx, hash, &hash_len);
  EVP_MD_CTX_free(ctx);

  hex = (char *)malloc(65);
  if( !hex ) return PQC_NOMEM;

  for(i = 0; i < 32; i++){
    sprintf(hex + i*2, "%02x", hash[i]);
  }
  hex[64] = '\0';

  *out = hex;
  *out_len = 64;
  *out_type = SQLITE_TEXT;
  return PQC_OK;
}

/*
** Apply RANGE masking — replace number with range bracket.
** salary=67500, bracket=25000 → '50000-75000'
*/
static int mask_range(const void *value, int value_type, int bracket,
                        void **out, int *out_len, int *out_type){
  double num;
  int64_t lower, upper;
  char *result;

  if( value_type == SQLITE_INTEGER ){
    num = (double)(*(sqlite3_int64 *)value);
  }else if( value_type == SQLITE_FLOAT ){
    num = *(double *)value;
  }else{
    return mask_full(out, out_len, out_type);
  }

  if( bracket <= 0 ) bracket = 10000;
  lower = ((int64_t)(num / bracket)) * bracket;
  upper = lower + bracket;

  result = sqlite3_mprintf("%lld-%lld", lower, upper);
  *out = result;
  *out_len = (int)strlen(result);
  *out_type = SQLITE_TEXT;
  return PQC_OK;
}

/*
** Initialize the masking engine.
*/
int pqc_mask_init(PqcMaskEngine *engine, sqlite3 *db){
  char *err = NULL;
  sqlite3_stmt *stmt = NULL;
  int rc;

  if( !engine || !db ) return PQC_ERROR;
  memset(engine, 0, sizeof(*engine));

  rc = sqlite3_exec(db, MASK_CREATE_SQL, NULL, NULL, &err);
  if( rc != SQLITE_OK ){
    sqlite3_free(err);
    return PQC_ERROR;
  }

  /* Load policies */
  rc = sqlite3_prepare_v2(db,
    "SELECT table_name, column_name, role, mask_type, "
    "param1, param2, custom_func FROM _pqlite_mask_policies",
    -1, &stmt, NULL);
  if( rc != SQLITE_OK ) return PQC_OK; /* No policies yet */

  while( sqlite3_step(stmt) == SQLITE_ROW ){
    if( engine->n_policies >= engine->n_alloc ){
      int new_alloc = engine->n_alloc ? engine->n_alloc * 2 : 16;
      PqcMaskPolicy *new_p = (PqcMaskPolicy *)realloc(
        engine->policies, new_alloc * sizeof(PqcMaskPolicy));
      if( !new_p ){ sqlite3_finalize(stmt); return PQC_NOMEM; }
      engine->policies = new_p;
      engine->n_alloc = new_alloc;
    }

    PqcMaskPolicy *p = &engine->policies[engine->n_policies];
    memset(p, 0, sizeof(*p));
    p->table_name = sqlite3_mprintf("%s", sqlite3_column_text(stmt, 0));
    p->column_name = sqlite3_mprintf("%s", sqlite3_column_text(stmt, 1));
    const char *role = (const char *)sqlite3_column_text(stmt, 2);
    p->role = role ? sqlite3_mprintf("%s", role) : NULL;
    p->mask_type = (PqcMaskType)sqlite3_column_int(stmt, 3);
    p->param1 = sqlite3_column_int(stmt, 4);
    p->param2 = sqlite3_column_int(stmt, 5);
    const char *func = (const char *)sqlite3_column_text(stmt, 6);
    p->custom_func = func ? sqlite3_mprintf("%s", func) : NULL;

    engine->n_policies++;
  }

  sqlite3_finalize(stmt);
  engine->enabled = 1;
  return PQC_OK;
}

/*
** Set the current session role.
*/
int pqc_mask_set_role(PqcMaskEngine *engine, const char *role){
  if( !engine ) return PQC_ERROR;
  if( engine->current_role ) sqlite3_free(engine->current_role);
  engine->current_role = role ? sqlite3_mprintf("%s", role) : NULL;
  return PQC_OK;
}

/*
** Add a masking policy.
*/
int pqc_mask_add_policy(PqcMaskEngine *engine, sqlite3 *db,
                          const char *table_name,
                          const char *column_name,
                          const char *role,
                          PqcMaskType mask_type,
                          int param1, int param2,
                          const char *custom_func){
  sqlite3_stmt *stmt = NULL;
  int rc;

  if( !engine || !db || !table_name || !column_name ) return PQC_ERROR;

  rc = sqlite3_prepare_v2(db,
    "INSERT OR REPLACE INTO _pqlite_mask_policies"
    "(table_name, column_name, role, mask_type, param1, param2, custom_func)"
    " VALUES(?,?,?,?,?,?,?)",
    -1, &stmt, NULL);
  if( rc != SQLITE_OK ) return PQC_ERROR;

  sqlite3_bind_text(stmt, 1, table_name, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, column_name, -1, SQLITE_TRANSIENT);
  if( role ) sqlite3_bind_text(stmt, 3, role, -1, SQLITE_TRANSIENT);
  else sqlite3_bind_null(stmt, 3);
  sqlite3_bind_int(stmt, 4, (int)mask_type);
  sqlite3_bind_int(stmt, 5, param1);
  sqlite3_bind_int(stmt, 6, param2);
  if( custom_func ) sqlite3_bind_text(stmt, 7, custom_func, -1, SQLITE_TRANSIENT);
  else sqlite3_bind_null(stmt, 7);

  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  return PQC_OK;
}

/*
** Apply masking to a value.
*/
int pqc_mask_apply(const PqcMaskEngine *engine,
                     const char *table_name,
                     const char *column_name,
                     const void *value, int value_len, int value_type,
                     void **masked_value, int *masked_len, int *masked_type){
  int i;
  const PqcMaskPolicy *policy = NULL;

  if( !engine || !engine->enabled ){
    /* Masking not active — pass through */
    return PQC_OK;
  }

  /* Find applicable policy for current role */
  for(i = 0; i < engine->n_policies; i++){
    const PqcMaskPolicy *p = &engine->policies[i];
    if( strcmp(p->table_name, table_name) != 0 ) continue;
    if( strcmp(p->column_name, column_name) != 0 ) continue;

    /* Check role match */
    if( p->role == NULL ){
      /* Default policy (applies to all roles without specific policy) */
      if( !policy ) policy = p;
    }else if( engine->current_role &&
              strcmp(p->role, engine->current_role) == 0 ){
      /* Exact role match takes priority */
      policy = p;
      break;
    }
  }

  if( !policy || policy->mask_type == PQC_MASK_NONE ){
    /* No masking needed */
    return PQC_OK;
  }

  switch( policy->mask_type ){
    case PQC_MASK_FULL:
      return mask_full(masked_value, masked_len, masked_type);
    case PQC_MASK_PARTIAL:
      return mask_partial(value, value_len, policy->param1, policy->param2,
                           masked_value, masked_len, masked_type);
    case PQC_MASK_EMAIL:
      return mask_email(value, value_len, masked_value, masked_len, masked_type);
    case PQC_MASK_HASH:
      return mask_hash(value, value_len, masked_value, masked_len, masked_type);
    case PQC_MASK_NULLIFY:
      *masked_value = NULL;
      *masked_len = 0;
      *masked_type = SQLITE_NULL;
      return PQC_OK;
    case PQC_MASK_RANGE:
      return mask_range(value, value_type, policy->param1,
                         masked_value, masked_len, masked_type);
    default:
      return mask_full(masked_value, masked_len, masked_type);
  }
}

/*
** Check if a column is masked for the current role.
*/
int pqc_mask_is_masked(const PqcMaskEngine *engine,
                         const char *table_name,
                         const char *column_name){
  int i;
  if( !engine || !engine->enabled ) return 0;

  for(i = 0; i < engine->n_policies; i++){
    if( strcmp(engine->policies[i].table_name, table_name) == 0 &&
        strcmp(engine->policies[i].column_name, column_name) == 0 ){
      if( engine->policies[i].role == NULL ||
          (engine->current_role &&
           strcmp(engine->policies[i].role, engine->current_role) == 0) ){
        return 1;
      }
    }
  }
  return 0;
}

/*
** Free the masking engine.
*/
void pqc_mask_free(PqcMaskEngine *engine){
  int i;
  if( !engine ) return;

  for(i = 0; i < engine->n_policies; i++){
    sqlite3_free(engine->policies[i].table_name);
    sqlite3_free(engine->policies[i].column_name);
    sqlite3_free(engine->policies[i].role);
    sqlite3_free(engine->policies[i].custom_func);
  }
  free(engine->policies);
  sqlite3_free(engine->current_role);
  memset(engine, 0, sizeof(*engine));
}

#endif /* PQLITE_ENABLE_PQC */
