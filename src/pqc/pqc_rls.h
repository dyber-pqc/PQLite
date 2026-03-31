/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Row-Level Security (RLS)
**
** Enforces row-level access policies that filter query results
** based on the current session's role/user context. Policies
** are defined as SQL expressions that are automatically appended
** to WHERE clauses.
**
** SQL Interface:
**   PRAGMA pqc_rls_role='user:alice';
**   CREATE POLICY ON orders AS 'user_id = pqc_current_user()';
**   CREATE POLICY ON documents AS 'classification <= pqc_clearance()';
**
** Example:
**   Role 'user:alice':
**     SELECT * FROM orders;
**     → SELECT * FROM orders WHERE user_id = 'alice';
**
**   Role 'admin':
**     SELECT * FROM orders;
**     → SELECT * FROM orders;  (no filter — admin sees all)
**
** NO other SQLite fork provides row-level security.
**
** PQLite is a product of Dyber, Inc.
*/
#ifndef PQLITE_PQC_RLS_H
#define PQLITE_PQC_RLS_H

#ifdef PQLITE_ENABLE_PQC

#include "sqlite3.h"

/*
** RLS policy definition
*/
typedef struct PqcRlsPolicy {
  char *table_name;        /* Table this policy applies to */
  char *policy_name;       /* Policy identifier */
  char *role;              /* Role or NULL for default */
  char *filter_expr;       /* SQL expression for WHERE clause */
  int bypass_for_admin;    /* If true, 'admin' role bypasses this policy */
} PqcRlsPolicy;

/*
** RLS engine context
*/
typedef struct PqcRlsEngine {
  int enabled;
  char *current_role;
  char *current_user;
  int current_clearance;     /* Numeric clearance level */
  PqcRlsPolicy *policies;
  int n_policies;
  int n_alloc;
} PqcRlsEngine;

/*
** Initialize the RLS engine.
** Creates _pqlite_rls_policies table if not present.
*/
int pqc_rls_init(PqcRlsEngine *engine, sqlite3 *db);

/*
** Set the current session identity for RLS evaluation.
*/
int pqc_rls_set_role(PqcRlsEngine *engine, const char *role);
int pqc_rls_set_user(PqcRlsEngine *engine, const char *user);
int pqc_rls_set_clearance(PqcRlsEngine *engine, int level);

/*
** Add an RLS policy for a table.
*/
int pqc_rls_add_policy(PqcRlsEngine *engine, sqlite3 *db,
                          const char *table_name,
                          const char *policy_name,
                          const char *role,
                          const char *filter_expr,
                          int bypass_for_admin);

/*
** Get the combined WHERE clause for a table given current role.
** Returns NULL if no policies apply (full access).
** Caller must sqlite3_free() the result.
*/
char *pqc_rls_get_filter(const PqcRlsEngine *engine,
                           const char *table_name);

/*
** Register RLS SQL functions (pqc_current_user(), pqc_current_role(),
** pqc_clearance()) so policies can reference session context.
*/
int pqc_rls_register_functions(sqlite3 *db, PqcRlsEngine *engine);

/*
** Free RLS engine resources.
*/
void pqc_rls_free(PqcRlsEngine *engine);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_RLS_H */
