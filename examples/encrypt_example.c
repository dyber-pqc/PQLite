/*
** PQLite - Post-Quantum SQLite
** Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
**
** Example: Basic PQLite usage with PQC functions
**
** Build:
**   gcc -o encrypt_example encrypt_example.c -lpqlite3 -loqs -lcrypto -lpthread -ldl -lm
**
** Or with the amalgamation:
**   gcc -DPQLITE_ENABLE_PQC -o encrypt_example encrypt_example.c \
**       ../sqlite3.c ../src/pqc/*.c -loqs -lcrypto -lpthread -ldl -lm \
**       -I../src -I..
**
** PQLite is a product of Dyber, Inc.
*/
#include <stdio.h>
#include <string.h>
#include "sqlite3.h"

int main(int argc, char **argv){
  sqlite3 *db;
  sqlite3_stmt *stmt;
  int rc;
  const char *dbfile = argc > 1 ? argv[1] : ":memory:";

  printf("PQLite Encryption Example\n");
  printf("Copyright (c) 2025-2026 Dyber, Inc.\n\n");

  /* Open database */
  rc = sqlite3_open(dbfile, &db);
  if( rc != SQLITE_OK ){
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    return 1;
  }

  /* Check PQLite version via SQL function */
  rc = sqlite3_prepare_v2(db, "SELECT pqc_version()", -1, &stmt, NULL);
  if( rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW ){
    printf("PQC Version: %s\n", sqlite3_column_text(stmt, 0));
  }else{
    printf("PQC functions not available (compiled without -DPQLITE_ENABLE_PQC)\n");
  }
  sqlite3_finalize(stmt);

  /* Check PQC algorithm info */
  rc = sqlite3_prepare_v2(db,
    "SELECT pqc_algorithm_info('ml-kem-768')", -1, &stmt, NULL);
  if( rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW ){
    printf("ML-KEM-768 info: %s\n", sqlite3_column_text(stmt, 0));
  }
  sqlite3_finalize(stmt);

  /* Check PQC status via PRAGMA */
  rc = sqlite3_prepare_v2(db, "PRAGMA pqc_version", -1, &stmt, NULL);
  if( rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW ){
    printf("PRAGMA pqc_version: %s\n", sqlite3_column_text(stmt, 0));
  }
  sqlite3_finalize(stmt);

  rc = sqlite3_prepare_v2(db, "PRAGMA pqc_algorithm", -1, &stmt, NULL);
  if( rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW ){
    printf("PRAGMA pqc_algorithm: %s\n", sqlite3_column_text(stmt, 0));
  }
  sqlite3_finalize(stmt);

  rc = sqlite3_prepare_v2(db, "PRAGMA pqc_cipher", -1, &stmt, NULL);
  if( rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW ){
    printf("PRAGMA pqc_cipher: %s\n", sqlite3_column_text(stmt, 0));
  }
  sqlite3_finalize(stmt);

  /* Create a test table and insert data */
  printf("\nCreating test table...\n");
  sqlite3_exec(db, "CREATE TABLE test(id INTEGER PRIMARY KEY, data TEXT)", NULL, NULL, NULL);
  sqlite3_exec(db, "INSERT INTO test VALUES(1, 'quantum-safe data')", NULL, NULL, NULL);
  sqlite3_exec(db, "INSERT INTO test VALUES(2, 'post-quantum encryption')", NULL, NULL, NULL);

  /* Read it back */
  rc = sqlite3_prepare_v2(db, "SELECT * FROM test", -1, &stmt, NULL);
  while( sqlite3_step(stmt) == SQLITE_ROW ){
    printf("  Row: id=%d, data=%s\n",
      sqlite3_column_int(stmt, 0),
      sqlite3_column_text(stmt, 1));
  }
  sqlite3_finalize(stmt);

  printf("\nPQLite example complete.\n");
  sqlite3_close(db);
  return 0;
}
