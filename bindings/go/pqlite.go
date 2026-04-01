// Package pqlite provides Go bindings for PQLite (Post-Quantum SQLite).
// Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
//
// PQLite is a fork of SQLite with NIST-standardized post-quantum
// cryptographic protection (FIPS 203/204/205).
//
// Usage:
//
//	import "github.com/dyber-pqc/PQLite/bindings/go"
//
//	db, err := pqlite.Open("secure.db")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer db.Close()
//
//	db.PQCKey("my-password")
//	db.Exec("CREATE TABLE t(x TEXT)")
//	db.Exec("INSERT INTO t VALUES(?)", "quantum-safe")
//
//	version, _ := db.PQCVersion()
//	fmt.Println(version)
//
// PQLite is a product of Dyber, Inc.
package pqlite

/*
#cgo CFLAGS: -I${SRCDIR}/../../src
#cgo LDFLAGS: -lpqlite3 -loqs -lcrypto -lpthread -ldl -lm
#cgo pkg-config: pqlite3

#include <sqlite3.h>
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// DB represents a PQLite database connection.
type DB struct {
	db *C.sqlite3
}

// Open opens a PQLite database file.
func Open(path string) (*DB, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var db *C.sqlite3
	rc := C.sqlite3_open(cPath, &db)
	if rc != C.SQLITE_OK {
		msg := C.GoString(C.sqlite3_errmsg(db))
		C.sqlite3_close(db)
		return nil, fmt.Errorf("pqlite: open failed: %s", msg)
	}
	return &DB{db: db}, nil
}

// OpenMemory opens an in-memory PQLite database.
func OpenMemory() (*DB, error) {
	return Open(":memory:")
}

// Close closes the database connection.
func (d *DB) Close() error {
	if d.db == nil {
		return nil
	}
	rc := C.sqlite3_close(d.db)
	d.db = nil
	if rc != C.SQLITE_OK {
		return fmt.Errorf("pqlite: close failed with code %d", rc)
	}
	return nil
}

// Exec executes a SQL statement that returns no rows.
func (d *DB) Exec(sql string, args ...interface{}) error {
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))

	var errmsg *C.char
	rc := C.sqlite3_exec(d.db, cSQL, nil, nil, &errmsg)
	if rc != C.SQLITE_OK {
		msg := "unknown error"
		if errmsg != nil {
			msg = C.GoString(errmsg)
			C.sqlite3_free(unsafe.Pointer(errmsg))
		}
		return fmt.Errorf("pqlite: exec failed: %s", msg)
	}
	return nil
}

// PQCKey sets the PQC encryption key for this database.
func (d *DB) PQCKey(password string) error {
	return d.Exec(fmt.Sprintf("PRAGMA pqc_key='%s'", password))
}

// PQCRekey changes the PQC encryption key.
func (d *DB) PQCRekey(newPassword string) error {
	return d.Exec(fmt.Sprintf("PRAGMA pqc_rekey='%s'", newPassword))
}

// PQCVersion returns the PQLite version string.
func (d *DB) PQCVersion() (string, error) {
	return d.queryString("SELECT pqc_version()")
}

// PQCAlgorithm returns the current KEM algorithm.
func (d *DB) PQCAlgorithm() (string, error) {
	return d.queryString("PRAGMA pqc_algorithm")
}

func (d *DB) queryString(sql string) (string, error) {
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))

	var stmt *C.sqlite3_stmt
	rc := C.sqlite3_prepare_v2(d.db, cSQL, -1, &stmt, nil)
	if rc != C.SQLITE_OK {
		return "", fmt.Errorf("pqlite: prepare failed: %s", C.GoString(C.sqlite3_errmsg(d.db)))
	}
	defer C.sqlite3_finalize(stmt)

	rc = C.sqlite3_step(stmt)
	if rc == C.SQLITE_ROW {
		text := C.sqlite3_column_text(stmt, 0)
		if text != nil {
			return C.GoString((*C.char)(unsafe.Pointer(text))), nil
		}
	}
	return "", nil
}
