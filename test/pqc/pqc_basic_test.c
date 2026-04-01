/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Basic PQC integration test — verifies that PQC hooks are wired
** into the SQLite core and respond correctly.
**
** Build:
**   gcc -DPQLITE_ENABLE_PQC -o pqc_basic_test pqc_basic_test.c \
**       -lpqlite3 -loqs -lcrypto -lpthread -ldl -lm -I../../src -I../..
**
** PQLite is a product of Dyber, Inc.
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sqlite3.h"

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST(name) printf("  TEST: %-50s ", name)
#define PASS() do { printf("[PASS]\n"); g_tests_passed++; } while(0)
#define FAIL(msg) do { printf("[FAIL] %s\n", msg); g_tests_failed++; } while(0)

/*
** Test: pqc_version() SQL function returns a non-NULL string
*/
static void test_pqc_version_function(sqlite3 *db){
  sqlite3_stmt *stmt;
  int rc;
  TEST("pqc_version() SQL function");

  rc = sqlite3_prepare_v2(db, "SELECT pqc_version()", -1, &stmt, NULL);
  if( rc != SQLITE_OK ){ FAIL("prepare failed"); return; }

  rc = sqlite3_step(stmt);
  if( rc != SQLITE_ROW ){ sqlite3_finalize(stmt); FAIL("no result row"); return; }

  const char *ver = (const char *)sqlite3_column_text(stmt, 0);
  if( ver == NULL ){ sqlite3_finalize(stmt); FAIL("NULL result"); return; }
  if( strstr(ver, "PQLite") == NULL ){ sqlite3_finalize(stmt); FAIL("missing 'PQLite' in version"); return; }

  sqlite3_finalize(stmt);
  PASS();
}

/*
** Test: PRAGMA pqc_version returns a string
*/
static void test_pragma_pqc_version(sqlite3 *db){
  sqlite3_stmt *stmt;
  int rc;
  TEST("PRAGMA pqc_version");

  rc = sqlite3_prepare_v2(db, "PRAGMA pqc_version", -1, &stmt, NULL);
  if( rc != SQLITE_OK ){ FAIL("prepare failed"); return; }

  rc = sqlite3_step(stmt);
  if( rc != SQLITE_ROW ){ sqlite3_finalize(stmt); FAIL("no result row"); return; }

  const char *ver = (const char *)sqlite3_column_text(stmt, 0);
  if( ver == NULL ){ sqlite3_finalize(stmt); FAIL("NULL result"); return; }
  if( strstr(ver, "PQLite") == NULL ){ sqlite3_finalize(stmt); FAIL("missing 'PQLite'"); return; }

  sqlite3_finalize(stmt);
  PASS();
}

/*
** Test: PRAGMA pqc_algorithm returns ml-kem-768
*/
static void test_pragma_pqc_algorithm(sqlite3 *db){
  sqlite3_stmt *stmt;
  int rc;
  TEST("PRAGMA pqc_algorithm");

  rc = sqlite3_prepare_v2(db, "PRAGMA pqc_algorithm", -1, &stmt, NULL);
  if( rc != SQLITE_OK ){ FAIL("prepare failed"); return; }

  rc = sqlite3_step(stmt);
  if( rc != SQLITE_ROW ){ sqlite3_finalize(stmt); FAIL("no result row"); return; }

  const char *alg = (const char *)sqlite3_column_text(stmt, 0);
  if( alg == NULL || strcmp(alg, "ml-kem-768") != 0 ){
    sqlite3_finalize(stmt); FAIL("expected 'ml-kem-768'"); return;
  }

  sqlite3_finalize(stmt);
  PASS();
}

/*
** Test: PRAGMA pqc_cipher returns aes-256-gcm
*/
static void test_pragma_pqc_cipher(sqlite3 *db){
  sqlite3_stmt *stmt;
  int rc;
  TEST("PRAGMA pqc_cipher");

  rc = sqlite3_prepare_v2(db, "PRAGMA pqc_cipher", -1, &stmt, NULL);
  if( rc != SQLITE_OK ){ FAIL("prepare failed"); return; }

  rc = sqlite3_step(stmt);
  if( rc != SQLITE_ROW ){ sqlite3_finalize(stmt); FAIL("no result row"); return; }

  const char *cipher = (const char *)sqlite3_column_text(stmt, 0);
  if( cipher == NULL || strcmp(cipher, "aes-256-gcm") != 0 ){
    sqlite3_finalize(stmt); FAIL("expected 'aes-256-gcm'"); return;
  }

  sqlite3_finalize(stmt);
  PASS();
}

/*
** Test: PRAGMA pqc_status returns a status string
*/
static void test_pragma_pqc_status(sqlite3 *db){
  sqlite3_stmt *stmt;
  int rc;
  TEST("PRAGMA pqc_status");

  rc = sqlite3_prepare_v2(db, "PRAGMA pqc_status", -1, &stmt, NULL);
  if( rc != SQLITE_OK ){ FAIL("prepare failed"); return; }

  rc = sqlite3_step(stmt);
  if( rc != SQLITE_ROW ){ sqlite3_finalize(stmt); FAIL("no result row"); return; }

  const char *status = (const char *)sqlite3_column_text(stmt, 0);
  if( status == NULL ){ sqlite3_finalize(stmt); FAIL("NULL result"); return; }

  sqlite3_finalize(stmt);
  PASS();
}

/*
** Test: pqc_algorithm_info() returns JSON
*/
static void test_algorithm_info(sqlite3 *db){
  sqlite3_stmt *stmt;
  int rc;
  TEST("pqc_algorithm_info('ml-kem-768')");

  rc = sqlite3_prepare_v2(db,
    "SELECT pqc_algorithm_info('ml-kem-768')", -1, &stmt, NULL);
  if( rc != SQLITE_OK ){ FAIL("prepare failed"); return; }

  rc = sqlite3_step(stmt);
  if( rc != SQLITE_ROW ){ sqlite3_finalize(stmt); FAIL("no result row"); return; }

  const char *info = (const char *)sqlite3_column_text(stmt, 0);
  if( info == NULL ){ sqlite3_finalize(stmt); FAIL("NULL result"); return; }
  if( strstr(info, "kem") == NULL ){ sqlite3_finalize(stmt); FAIL("missing 'kem' in info"); return; }

  sqlite3_finalize(stmt);
  PASS();
}

/*
** Test: Basic database operations work with PQC enabled
*/
static void test_basic_db_operations(sqlite3 *db){
  int rc;
  sqlite3_stmt *stmt;
  TEST("Basic DB operations (CREATE/INSERT/SELECT)");

  rc = sqlite3_exec(db, "CREATE TABLE pqc_test(id INTEGER PRIMARY KEY, data TEXT)",
                     NULL, NULL, NULL);
  if( rc != SQLITE_OK ){ FAIL("CREATE TABLE failed"); return; }

  rc = sqlite3_exec(db, "INSERT INTO pqc_test VALUES(1, 'quantum safe')",
                     NULL, NULL, NULL);
  if( rc != SQLITE_OK ){ FAIL("INSERT failed"); return; }

  rc = sqlite3_prepare_v2(db, "SELECT data FROM pqc_test WHERE id=1", -1, &stmt, NULL);
  if( rc != SQLITE_OK ){ FAIL("prepare SELECT failed"); return; }

  if( sqlite3_step(stmt) != SQLITE_ROW ){ sqlite3_finalize(stmt); FAIL("no row returned"); return; }

  const char *data = (const char *)sqlite3_column_text(stmt, 0);
  if( data == NULL || strcmp(data, "quantum safe") != 0 ){
    sqlite3_finalize(stmt); FAIL("data mismatch"); return;
  }

  sqlite3_finalize(stmt);
  sqlite3_exec(db, "DROP TABLE pqc_test", NULL, NULL, NULL);
  PASS();
}

int main(int argc, char **argv){
  sqlite3 *db;
  int rc;

  printf("==============================================\n");
  printf("  PQLite PQC Integration Test Suite\n");
  printf("  Copyright (c) 2025-2026 Dyber, Inc.\n");
  printf("==============================================\n\n");

  rc = sqlite3_open(":memory:", &db);
  if( rc != SQLITE_OK ){
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    return 1;
  }

  /* Run all tests */
  test_pqc_version_function(db);
  test_pragma_pqc_version(db);
  test_pragma_pqc_algorithm(db);
  test_pragma_pqc_cipher(db);
  test_pragma_pqc_status(db);
  test_algorithm_info(db);
  test_basic_db_operations(db);

  sqlite3_close(db);

  printf("\n==============================================\n");
  printf("  Results: %d passed, %d failed\n", g_tests_passed, g_tests_failed);
  printf("==============================================\n");

  return g_tests_failed > 0 ? 1 : 0;
}
