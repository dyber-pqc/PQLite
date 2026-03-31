/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Row-Level Security (RLS) — Implementation
**
** Policies are stored in _pqlite_rls_policies and applied
** by injecting WHERE clauses into queries at parse time.
** SQL functions pqc_current_user(), pqc_current_role(), and
** pqc_clearance() allow policies to reference session context.
**
** PQLite is a product of Dyber, Inc.
*/
#ifdef PQLITE_ENABLE_PQC

#include "pqc_rls.h"
#include <string.h>
#include <stdlib.h>

static const char *RLS_CREATE_SQL =
  "CREATE TABLE IF NOT EXISTS _pqlite_rls_policies("
  "  id INTEGER PRIMARY KEY,"
  "  table_name TEXT NOT NULL,"
  "  policy_name TEXT NOT NULL,"
  "  role TEXT,"
  "  filter_expr TEXT NOT NULL,"
  "  bypass_for_admin INTEGER DEFAULT 1,"
  "  UNIQUE(table_name, policy_name, role)"
  ")";

/* Context SQL functions */
static void pqcCurrentUserFunc(sqlite3_context *ctx, int argc, sqlite3_value **argv){
  PqcRlsEngine *engine = (PqcRlsEngine *)sqlite3_user_data(ctx);
  (void)argc; (void)argv;
  if( engine && engine->current_user ){
    sqlite3_result_text(ctx, engine->current_user, -1, SQLITE_TRANSIENT);
  }else{
    sqlite3_result_null(ctx);
  }
}

static void pqcCurrentRoleFunc(sqlite3_context *ctx, int argc, sqlite3_value **argv){
  PqcRlsEngine *engine = (PqcRlsEngine *)sqlite3_user_data(ctx);
  (void)argc; (void)argv;
  if( engine && engine->current_role ){
    sqlite3_result_text(ctx, engine->current_role, -1, SQLITE_TRANSIENT);
  }else{
    sqlite3_result_null(ctx);
  }
}

static void pqcClearanceFunc(sqlite3_context *ctx, int argc, sqlite3_value **argv){
  PqcRlsEngine *engine = (PqcRlsEngine *)sqlite3_user_data(ctx);
  (void)argc; (void)argv;
  if( engine ){
    sqlite3_result_int(ctx, engine->current_clearance);
  }else{
    sqlite3_result_int(ctx, 0);
  }
}

int pqc_rls_init(PqcRlsEngine *engine, sqlite3 *db){
  char *err = NULL;
  sqlite3_stmt *stmt = NULL;
  int rc;

  if( !engine || !db ) return PQC_ERROR;
  memset(engine, 0, sizeof(*engine));

  rc = sqlite3_exec(db, RLS_CREATE_SQL, NULL, NULL, &err);
  if( rc != SQLITE_OK ){
    sqlite3_free(err);
    return PQC_ERROR;
  }

  /* Load policies */
  rc = sqlite3_prepare_v2(db,
    "SELECT table_name, policy_name, role, filter_expr, bypass_for_admin "
    "FROM _pqlite_rls_policies",
    -1, &stmt, NULL);
  if( rc != SQLITE_OK ) return PQC_OK;

  while( sqlite3_step(stmt) == SQLITE_ROW ){
    if( engine->n_policies >= engine->n_alloc ){
      int new_alloc = engine->n_alloc ? engine->n_alloc * 2 : 16;
      PqcRlsPolicy *new_p = (PqcRlsPolicy *)realloc(
        engine->policies, new_alloc * sizeof(PqcRlsPolicy));
      if( !new_p ){ sqlite3_finalize(stmt); return PQC_NOMEM; }
      engine->policies = new_p;
      engine->n_alloc = new_alloc;
    }

    PqcRlsPolicy *p = &engine->policies[engine->n_policies];
    memset(p, 0, sizeof(*p));
    p->table_name = sqlite3_mprintf("%s", sqlite3_column_text(stmt, 0));
    p->policy_name = sqlite3_mprintf("%s", sqlite3_column_text(stmt, 1));
    const char *role = (const char *)sqlite3_column_text(stmt, 2);
    p->role = role ? sqlite3_mprintf("%s", role) : NULL;
    p->filter_expr = sqlite3_mprintf("%s", sqlite3_column_text(stmt, 3));
    p->bypass_for_admin = sqlite3_column_int(stmt, 4);
    engine->n_policies++;
  }

  sqlite3_finalize(stmt);
  engine->enabled = 1;
  return PQC_OK;
}

int pqc_rls_set_role(PqcRlsEngine *engine, const char *role){
  if( !engine ) return PQC_ERROR;
  if( engine->current_role ) sqlite3_free(engine->current_role);
  engine->current_role = role ? sqlite3_mprintf("%s", role) : NULL;
  return PQC_OK;
}

int pqc_rls_set_user(PqcRlsEngine *engine, const char *user){
  if( !engine ) return PQC_ERROR;
  if( engine->current_user ) sqlite3_free(engine->current_user);
  engine->current_user = user ? sqlite3_mprintf("%s", user) : NULL;
  return PQC_OK;
}

int pqc_rls_set_clearance(PqcRlsEngine *engine, int level){
  if( !engine ) return PQC_ERROR;
  engine->current_clearance = level;
  return PQC_OK;
}

int pqc_rls_add_policy(PqcRlsEngine *engine, sqlite3 *db,
                          const char *table_name,
                          const char *policy_name,
                          const char *role,
                          const char *filter_expr,
                          int bypass_for_admin){
  sqlite3_stmt *stmt = NULL;
  int rc;

  if( !engine || !db ) return PQC_ERROR;

  rc = sqlite3_prepare_v2(db,
    "INSERT OR REPLACE INTO _pqlite_rls_policies"
    "(table_name, policy_name, role, filter_expr, bypass_for_admin)"
    " VALUES(?,?,?,?,?)",
    -1, &stmt, NULL);
  if( rc != SQLITE_OK ) return PQC_ERROR;

  sqlite3_bind_text(stmt, 1, table_name, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, policy_name, -1, SQLITE_TRANSIENT);
  if( role ) sqlite3_bind_text(stmt, 3, role, -1, SQLITE_TRANSIENT);
  else sqlite3_bind_null(stmt, 3);
  sqlite3_bind_text(stmt, 4, filter_expr, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 5, bypass_for_admin);

  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  return PQC_OK;
}

/*
** Get the combined WHERE filter for a table and the current role.
** Multiple policies are ANDed together.
*/
char *pqc_rls_get_filter(const PqcRlsEngine *engine,
                           const char *table_name){
  char *filter = NULL;
  int i;

  if( !engine || !engine->enabled ) return NULL;

  /* Admin bypass */
  if( engine->current_role && strcmp(engine->current_role, "admin") == 0 ){
    return NULL; /* Full access */
  }

  for(i = 0; i < engine->n_policies; i++){
    const PqcRlsPolicy *p = &engine->policies[i];
    if( strcmp(p->table_name, table_name) != 0 ) continue;

    /* Check role match */
    int applies = 0;
    if( p->role == NULL ){
      applies = 1; /* Default policy */
    }else if( engine->current_role &&
              strcmp(p->role, engine->current_role) == 0 ){
      applies = 1;
    }

    if( applies ){
      if( filter == NULL ){
        filter = sqlite3_mprintf("(%s)", p->filter_expr);
      }else{
        char *new_filter = sqlite3_mprintf("%s AND (%s)", filter, p->filter_expr);
        sqlite3_free(filter);
        filter = new_filter;
      }
    }
  }

  return filter;
}

int pqc_rls_register_functions(sqlite3 *db, PqcRlsEngine *engine){
  int rc = SQLITE_OK;

  rc |= sqlite3_create_function(db, "pqc_current_user", 0,
    SQLITE_UTF8 | SQLITE_DETERMINISTIC, engine,
    pqcCurrentUserFunc, NULL, NULL);

  rc |= sqlite3_create_function(db, "pqc_current_role", 0,
    SQLITE_UTF8 | SQLITE_DETERMINISTIC, engine,
    pqcCurrentRoleFunc, NULL, NULL);

  rc |= sqlite3_create_function(db, "pqc_clearance", 0,
    SQLITE_UTF8 | SQLITE_DETERMINISTIC, engine,
    pqcClearanceFunc, NULL, NULL);

  return rc;
}

void pqc_rls_free(PqcRlsEngine *engine){
  int i;
  if( !engine ) return;

  for(i = 0; i < engine->n_policies; i++){
    sqlite3_free(engine->policies[i].table_name);
    sqlite3_free(engine->policies[i].policy_name);
    sqlite3_free(engine->policies[i].role);
    sqlite3_free(engine->policies[i].filter_expr);
  }
  free(engine->policies);
  sqlite3_free(engine->current_role);
  sqlite3_free(engine->current_user);
  memset(engine, 0, sizeof(*engine));
}

#endif /* PQLITE_ENABLE_PQC */
