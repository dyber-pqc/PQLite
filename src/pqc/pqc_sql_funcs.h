/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** PQLite SQL Functions
**
** Registers PQC SQL functions for application-level use:
**   pqc_kem_keygen(), pqc_kem_encapsulate(), pqc_kem_decapsulate()
**   pqc_sig_keygen(), pqc_sign(), pqc_verify()
**   pqc_encrypt(), pqc_decrypt()
**   pqc_version(), pqc_algorithm_info()
**
** PQLite is a product of Dyber, Inc.
*/
#ifndef PQLITE_PQC_SQL_FUNCS_H
#define PQLITE_PQC_SQL_FUNCS_H

#ifdef PQLITE_ENABLE_PQC

#include "sqlite3.h"

/*
** Register all PQLite SQL functions on a database connection.
** Called during database open when PQC is enabled.
*/
int pqc_register_sql_functions(sqlite3 *db);

#endif /* PQLITE_ENABLE_PQC */
#endif /* PQLITE_PQC_SQL_FUNCS_H */
