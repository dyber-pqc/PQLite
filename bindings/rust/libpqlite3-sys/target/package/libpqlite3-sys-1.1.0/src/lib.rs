// PQLite - Post-Quantum SQLite
// Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
//
// Low-level FFI bindings to libpqlite3.
// For a safe Rust API, use the `pqlite` crate instead.
//
// PQLite is a product of Dyber, Inc.

#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

use std::os::raw::{c_char, c_int, c_void, c_double};

// Opaque types
pub enum sqlite3 {}
pub enum sqlite3_stmt {}
pub enum sqlite3_context {}
pub enum sqlite3_value {}

// Standard SQLite C API (subset)
extern "C" {
    pub fn sqlite3_open(filename: *const c_char, ppDb: *mut *mut sqlite3) -> c_int;
    pub fn sqlite3_open_v2(
        filename: *const c_char,
        ppDb: *mut *mut sqlite3,
        flags: c_int,
        zVfs: *const c_char,
    ) -> c_int;
    pub fn sqlite3_close(db: *mut sqlite3) -> c_int;
    pub fn sqlite3_close_v2(db: *mut sqlite3) -> c_int;

    pub fn sqlite3_exec(
        db: *mut sqlite3,
        sql: *const c_char,
        callback: Option<extern "C" fn(*mut c_void, c_int, *mut *mut c_char, *mut *mut c_char) -> c_int>,
        arg: *mut c_void,
        errmsg: *mut *mut c_char,
    ) -> c_int;

    pub fn sqlite3_prepare_v2(
        db: *mut sqlite3,
        sql: *const c_char,
        nByte: c_int,
        ppStmt: *mut *mut sqlite3_stmt,
        pzTail: *mut *const c_char,
    ) -> c_int;

    pub fn sqlite3_step(stmt: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_finalize(stmt: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_reset(stmt: *mut sqlite3_stmt) -> c_int;

    pub fn sqlite3_column_count(stmt: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_column_type(stmt: *mut sqlite3_stmt, iCol: c_int) -> c_int;
    pub fn sqlite3_column_int(stmt: *mut sqlite3_stmt, iCol: c_int) -> c_int;
    pub fn sqlite3_column_int64(stmt: *mut sqlite3_stmt, iCol: c_int) -> i64;
    pub fn sqlite3_column_double(stmt: *mut sqlite3_stmt, iCol: c_int) -> c_double;
    pub fn sqlite3_column_text(stmt: *mut sqlite3_stmt, iCol: c_int) -> *const c_char;
    pub fn sqlite3_column_blob(stmt: *mut sqlite3_stmt, iCol: c_int) -> *const c_void;
    pub fn sqlite3_column_bytes(stmt: *mut sqlite3_stmt, iCol: c_int) -> c_int;

    pub fn sqlite3_bind_int(stmt: *mut sqlite3_stmt, idx: c_int, val: c_int) -> c_int;
    pub fn sqlite3_bind_int64(stmt: *mut sqlite3_stmt, idx: c_int, val: i64) -> c_int;
    pub fn sqlite3_bind_double(stmt: *mut sqlite3_stmt, idx: c_int, val: c_double) -> c_int;
    pub fn sqlite3_bind_text(
        stmt: *mut sqlite3_stmt,
        idx: c_int,
        val: *const c_char,
        n: c_int,
        destructor: Option<extern "C" fn(*mut c_void)>,
    ) -> c_int;
    pub fn sqlite3_bind_blob(
        stmt: *mut sqlite3_stmt,
        idx: c_int,
        val: *const c_void,
        n: c_int,
        destructor: Option<extern "C" fn(*mut c_void)>,
    ) -> c_int;
    pub fn sqlite3_bind_null(stmt: *mut sqlite3_stmt, idx: c_int) -> c_int;

    pub fn sqlite3_errmsg(db: *mut sqlite3) -> *const c_char;
    pub fn sqlite3_errcode(db: *mut sqlite3) -> c_int;
    pub fn sqlite3_libversion() -> *const c_char;
    pub fn sqlite3_free(ptr: *mut c_void);
}

// SQLite constants
pub const SQLITE_OK: c_int = 0;
pub const SQLITE_ERROR: c_int = 1;
pub const SQLITE_ROW: c_int = 100;
pub const SQLITE_DONE: c_int = 101;
pub const SQLITE_OPEN_READWRITE: c_int = 0x00000002;
pub const SQLITE_OPEN_CREATE: c_int = 0x00000004;
pub const SQLITE_OPEN_URI: c_int = 0x00000040;
pub const SQLITE_TRANSIENT: Option<extern "C" fn(*mut c_void)> = None; // Actually -1 cast

pub const SQLITE_INTEGER: c_int = 1;
pub const SQLITE_FLOAT: c_int = 2;
pub const SQLITE_TEXT: c_int = 3;
pub const SQLITE_BLOB: c_int = 4;
pub const SQLITE_NULL: c_int = 5;
