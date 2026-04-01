/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Dynamic Data Masking & Redaction Engine
**
** Applies real-time masking policies to query results based on
** the current session's role/context. The actual stored data is
** never modified — masking happens transparently at read time.
**
** Masking types:
**   FULL      — Replace entire value with '***'
**   PARTIAL   — Show first/last N characters: 'J*** ***n'
**   EMAIL     — Mask email: 'j***@***.com'
**   HASH      — Replace with SHA-256 hash (for analytics)
**   NULLIFY   — Replace with NULL
**   RANGE     — Replace number with range bracket: '50000-75000'
**   CUSTOM    — User-defined masking function
**
** SQL Interface:
**   PRAGMA pqc_mask_role='analyst';
**   CREATE MASK ON employees.salary AS 'RANGE' BRACKETS 25000;
**   CREATE MASK ON employees.ssn AS 'PARTIAL' SHOW_LAST 4;
**
** NO other SQLite fork provides dynamic data masking.
**
** PQLite is a product of Dyber, Inc.
*/
#ifndef PQLITE_PQC_MASKING_H
#define PQLITE_PQC_MASKING_H

#ifdef PQLITE_ENABLE_PQC

#include "sqlite3.h"
#include "pqc_common.h"
#include <stdint.h>

/*
** Masking types
*/
typedef enum {
  PQC_MASK_NONE     = 0,   /* No masking (full access) */
  PQC_MASK_FULL     = 1,   /* Replace with '***' */
  PQC_MASK_PARTIAL  = 2,   /* Show first/last N chars */
  PQC_MASK_EMAIL    = 3,   /* Email-specific masking */
  PQC_MASK_HASH     = 4,   /* SHA-256 hash of value */
  PQC_MASK_NULLIFY  = 5,   /* Replace with NULL */
  PQC_MASK_RANGE    = 6,   /* Numeric range bracket */
  PQC_MASK_CUSTOM   = 7,   /* User-defined SQL function */
} PqcMaskType;

/*
** Masking policy — one per column per role.
*/
typedef struct PqcMaskPolicy {
  char *table_name;          /* Target table */
  char *column_name;         /* Target column */
  char *role;                /* Role this policy applies to (NULL = default) */
  PqcMaskType mask_type;     /* How to mask */
  int param1;                /* Param: show_first N, range bracket size, etc. */
  int param2;                /* Param: show_last N */
  char *custom_func;         /* Name of custom masking SQL function */
} PqcMaskPolicy;

/*
** Masking engine context — attached to database connection.
*/
typedef struct PqcMaskEngine {
  int enabled;                 /* Non-zero if masking is active */
  char *current_role;          /* Current session role */
  PqcMaskPolicy *policies;    /* Array of policies */
  int n_policies;
  int n_alloc;
} PqcMaskEngine;

/*
** Initialize the masking engine.
** Creates _pqlite_mask_policies table if not present.
*/
int pqc_mask_init(PqcMaskEngine *engine, sqlite3 *db);

/*
** Set the current session role for masking decisions.
*/
int pqc_mask_set_role(PqcMaskEngine *engine, const char *role);

/*
** Add a masking policy.
*/
int pqc_mask_add_policy(PqcMaskEngine *engine, sqlite3 *db,
                          const char *table_name,
                          const char *column_name,
                          const char *role,
                          PqcMaskType mask_type,
                          int param1, int param2,
                          const char *custom_func);

/*
** Apply masking to a value based on current role and column policies.
** Returns the masked value (caller must free).
*/
int pqc_mask_apply(const PqcMaskEngine *engine,
                     const char *table_name,
                     const char *column_name,
                     const void *value, int value_len, int value_type,
                     void **masked_value, int *masked_len, int *masked_type);

/*
** Check if a column has a masking policy for the current role.
*/
int pqc_mask_is_masked(const PqcMaskEngine *engine,
                         const char *table_name,
                         const char *column_name);

/*
** Free the masking engine.
*/
void pqc_mask_free(PqcMaskEngine *engine);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_MASKING_H */
