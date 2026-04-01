// PQLite - Post-Quantum SQLite
// Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
//
// C#/.NET bindings for PQLite via P/Invoke.
//
// Usage:
//   using PQLite;
//   var db = new PQLiteConnection("secure.db");
//   db.PqcKey("my-password");
//   db.Execute("CREATE TABLE t(x TEXT)");
//   Console.WriteLine(db.PqcVersion());
//   db.Dispose();
//
// For full ADO.NET support, use Microsoft.Data.Sqlite compiled against
// libpqlite3 instead of e_sqlite3.
//
// PQLite is a product of Dyber, Inc.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace PQLite
{
    /// <summary>
    /// PQLite database connection with PQC encryption support.
    /// </summary>
    public class PQLiteConnection : IDisposable
    {
        private IntPtr _db;
        private bool _disposed;

        // P/Invoke declarations for libpqlite3
        private const string LibName = "pqlite3";

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_open(byte[] filename, out IntPtr db);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_close(IntPtr db);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_exec(IntPtr db, byte[] sql,
            IntPtr callback, IntPtr arg, out IntPtr errmsg);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql,
            int nByte, out IntPtr stmt, out IntPtr tail);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_step(IntPtr stmt);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_column_text(IntPtr stmt, int col);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sqlite3_finalize(IntPtr stmt);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void sqlite3_free(IntPtr ptr);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sqlite3_errmsg(IntPtr db);

        private const int SQLITE_OK = 0;
        private const int SQLITE_ROW = 100;

        /// <summary>
        /// Open a PQLite database.
        /// </summary>
        /// <param name="path">Database file path or ":memory:"</param>
        public PQLiteConnection(string path)
        {
            byte[] pathBytes = Encoding.UTF8.GetBytes(path + "\0");
            int rc = sqlite3_open(pathBytes, out _db);
            if (rc != SQLITE_OK)
            {
                string msg = Marshal.PtrToStringAnsi(sqlite3_errmsg(_db)) ?? "unknown error";
                sqlite3_close(_db);
                throw new Exception($"PQLite: Failed to open database: {msg}");
            }
        }

        /// <summary>Execute a SQL statement.</summary>
        public void Execute(string sql)
        {
            byte[] sqlBytes = Encoding.UTF8.GetBytes(sql + "\0");
            int rc = sqlite3_exec(_db, sqlBytes, IntPtr.Zero, IntPtr.Zero, out IntPtr errmsg);
            if (rc != SQLITE_OK)
            {
                string msg = errmsg != IntPtr.Zero
                    ? Marshal.PtrToStringAnsi(errmsg) ?? "error"
                    : "error";
                if (errmsg != IntPtr.Zero) sqlite3_free(errmsg);
                throw new Exception($"PQLite: {msg}");
            }
        }

        /// <summary>Set the PQC encryption key.</summary>
        public void PqcKey(string password) => Execute($"PRAGMA pqc_key='{password}'");

        /// <summary>Change the PQC encryption key.</summary>
        public void PqcRekey(string newPassword) => Execute($"PRAGMA pqc_rekey='{newPassword}'");

        /// <summary>Get the PQLite version string.</summary>
        public string PqcVersion() => QueryScalar("SELECT pqc_version()");

        /// <summary>Get the PQC algorithm name.</summary>
        public string PqcAlgorithm() => QueryScalar("PRAGMA pqc_algorithm");

        private string QueryScalar(string sql)
        {
            byte[] sqlBytes = Encoding.UTF8.GetBytes(sql + "\0");
            int rc = sqlite3_prepare_v2(_db, sqlBytes, -1, out IntPtr stmt, out _);
            if (rc != SQLITE_OK) return null;

            try
            {
                rc = sqlite3_step(stmt);
                if (rc == SQLITE_ROW)
                {
                    IntPtr text = sqlite3_column_text(stmt, 0);
                    return text != IntPtr.Zero ? Marshal.PtrToStringAnsi(text) : null;
                }
                return null;
            }
            finally
            {
                sqlite3_finalize(stmt);
            }
        }

        public void Dispose()
        {
            if (!_disposed && _db != IntPtr.Zero)
            {
                sqlite3_close(_db);
                _db = IntPtr.Zero;
                _disposed = true;
            }
        }
    }
}
