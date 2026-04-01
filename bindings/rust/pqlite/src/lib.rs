// PQLite - Post-Quantum SQLite
// Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
//
// Safe Rust bindings for PQLite.
//
// Usage:
//   use pqlite::{Connection, Result};
//
//   let conn = Connection::open("secure.db")?;
//   conn.execute_batch("PRAGMA pqc_key='my-password'")?;
//   conn.execute("CREATE TABLE t(x TEXT)", [])?;
//   conn.execute("INSERT INTO t VALUES(?1)", ["quantum-safe"])?;
//
//   let version: String = conn.query_row(
//       "SELECT pqc_version()", [], |row| row.get(0)
//   )?;
//   println!("PQLite version: {}", version);
//
// PQLite is a product of Dyber, Inc.

use libpqlite3_sys as ffi;
use std::ffi::{CStr, CString};
use std::os::raw::c_int;
use std::ptr;

/// PQLite error type.
#[derive(Debug)]
pub enum Error {
    /// SQLite error with code and message.
    SqliteError { code: i32, message: String },
    /// UTF-8 conversion error.
    Utf8Error(std::str::Utf8Error),
    /// Null pointer error.
    NullError,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::SqliteError { code, message } => write!(f, "SQLite error {}: {}", code, message),
            Error::Utf8Error(e) => write!(f, "UTF-8 error: {}", e),
            Error::NullError => write!(f, "Null pointer"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// A PQLite database connection.
pub struct Connection {
    db: *mut ffi::sqlite3,
}

// Safety: sqlite3 is thread-safe when compiled with SQLITE_THREADSAFE=1
unsafe impl Send for Connection {}

impl Connection {
    /// Open a database file.
    pub fn open(path: &str) -> Result<Self> {
        let c_path = CString::new(path).map_err(|_| Error::NullError)?;
        let mut db: *mut ffi::sqlite3 = ptr::null_mut();
        let rc = unsafe { ffi::sqlite3_open(c_path.as_ptr(), &mut db) };
        if rc != ffi::SQLITE_OK {
            let msg = unsafe { Self::errmsg_raw(db) };
            unsafe { ffi::sqlite3_close(db) };
            return Err(Error::SqliteError { code: rc as i32, message: msg });
        }
        Ok(Connection { db })
    }

    /// Open an in-memory database.
    pub fn open_in_memory() -> Result<Self> {
        Self::open(":memory:")
    }

    /// Execute a SQL statement that returns no rows.
    pub fn execute(&self, sql: &str, params: &[&str]) -> Result<usize> {
        // Simple case: no params
        if params.is_empty() {
            return self.execute_batch(sql);
        }

        let c_sql = CString::new(sql).map_err(|_| Error::NullError)?;
        let mut stmt: *mut ffi::sqlite3_stmt = ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_prepare_v2(self.db, c_sql.as_ptr(), -1, &mut stmt, ptr::null_mut())
        };
        if rc != ffi::SQLITE_OK {
            return Err(self.last_error());
        }

        // Bind parameters
        for (i, param) in params.iter().enumerate() {
            let c_param = CString::new(*param).map_err(|_| Error::NullError)?;
            unsafe {
                ffi::sqlite3_bind_text(stmt, (i + 1) as c_int, c_param.as_ptr(), -1, ffi::SQLITE_TRANSIENT);
            }
        }

        let rc = unsafe { ffi::sqlite3_step(stmt) };
        unsafe { ffi::sqlite3_finalize(stmt) };

        match rc {
            ffi::SQLITE_DONE | ffi::SQLITE_ROW => Ok(0),
            _ => Err(self.last_error()),
        }
    }

    /// Execute one or more SQL statements (no result).
    pub fn execute_batch(&self, sql: &str) -> Result<usize> {
        let c_sql = CString::new(sql).map_err(|_| Error::NullError)?;
        let mut errmsg: *mut i8 = ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_exec(self.db, c_sql.as_ptr(), None, ptr::null_mut(), &mut errmsg)
        };
        if rc != ffi::SQLITE_OK {
            let msg = if !errmsg.is_null() {
                let s = unsafe { CStr::from_ptr(errmsg) }.to_string_lossy().into_owned();
                unsafe { ffi::sqlite3_free(errmsg as *mut std::os::raw::c_void) };
                s
            } else {
                "unknown error".to_string()
            };
            return Err(Error::SqliteError { code: rc as i32, message: msg });
        }
        Ok(0)
    }

    /// Set the PQC encryption key.
    pub fn pqc_key(&self, password: &str) -> Result<()> {
        self.execute_batch(&format!("PRAGMA pqc_key='{}'", password))
            .map(|_| ())
    }

    /// Get the PQLite version string.
    pub fn pqc_version(&self) -> Result<String> {
        let c_sql = CString::new("SELECT pqc_version()").unwrap();
        let mut stmt: *mut ffi::sqlite3_stmt = ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_prepare_v2(self.db, c_sql.as_ptr(), -1, &mut stmt, ptr::null_mut())
        };
        if rc != ffi::SQLITE_OK { return Err(self.last_error()); }

        let rc = unsafe { ffi::sqlite3_step(stmt) };
        if rc == ffi::SQLITE_ROW {
            let text = unsafe { ffi::sqlite3_column_text(stmt, 0) };
            let result = if !text.is_null() {
                unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned()
            } else {
                String::new()
            };
            unsafe { ffi::sqlite3_finalize(stmt) };
            Ok(result)
        } else {
            unsafe { ffi::sqlite3_finalize(stmt) };
            Err(self.last_error())
        }
    }

    fn last_error(&self) -> Error {
        Error::SqliteError {
            code: unsafe { ffi::sqlite3_errcode(self.db) } as i32,
            message: unsafe { Self::errmsg_raw(self.db) },
        }
    }

    unsafe fn errmsg_raw(db: *mut ffi::sqlite3) -> String {
        if db.is_null() { return "null database".to_string(); }
        let msg = ffi::sqlite3_errmsg(db);
        if msg.is_null() { return "unknown error".to_string(); }
        CStr::from_ptr(msg).to_string_lossy().into_owned()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if !self.db.is_null() {
            unsafe { ffi::sqlite3_close_v2(self.db) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_memory() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t(x)").unwrap();
        conn.execute_batch("INSERT INTO t VALUES('hello')").unwrap();
    }
}
