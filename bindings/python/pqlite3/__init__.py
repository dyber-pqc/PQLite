"""
PQLite3 — Post-Quantum SQLite for Python
Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.

Drop-in replacement for Python's built-in sqlite3 module with
post-quantum cryptographic protection.

Usage:
    import pqlite3 as sqlite3

    conn = sqlite3.connect('secure.db')
    conn.execute("PRAGMA pqc_key='my-password'")
    conn.execute("CREATE TABLE t(x)")
    conn.execute("INSERT INTO t VALUES(?)", ('quantum-safe',))

    # PQC functions available in SQL
    cursor = conn.execute("SELECT pqc_version()")
    print(cursor.fetchone()[0])

    conn.close()

Install:
    pip install pqlite3

PQLite is a product of Dyber, Inc.
"""

__version__ = "1.1.0"
__author__ = "Dyber, Inc."
__license__ = "MIT"

import ctypes
import ctypes.util
import os
import sys

# Re-export standard sqlite3 module constants and exceptions
from sqlite3 import (
    Warning, Error, InterfaceError, DatabaseError,
    DataError, OperationalError, IntegrityError,
    InternalError, ProgrammingError, NotSupportedError,
    PARSE_DECLTYPES, PARSE_COLNAMES,
    Row,
    apilevel, paramstyle, threadsafety,
    sqlite_version, sqlite_version_info,
)

# Try to load the PQLite shared library
_lib_names = [
    'libpqlite3.so',
    'libpqlite3.dylib',
    'pqlite3.dll',
]

_lib_path = None
for name in _lib_names:
    # Check alongside this package first
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(pkg_dir, name)
    if os.path.exists(candidate):
        _lib_path = candidate
        break
    # Check system paths
    found = ctypes.util.find_library('pqlite3')
    if found:
        _lib_path = found
        break

# If PQLite library is not available, fall back to standard sqlite3
# with a warning. This allows the package to work even without
# the PQLite native library (just without PQC features).
_has_pqc = False

if _lib_path:
    try:
        _lib = ctypes.CDLL(_lib_path)
        _has_pqc = True
    except OSError:
        _has_pqc = False

if not _has_pqc:
    import warnings
    warnings.warn(
        "PQLite native library not found. Falling back to standard sqlite3. "
        "PQC features (PRAGMA pqc_key, pqc_version(), etc.) will not be available. "
        "Install the PQLite library: https://github.com/dyber-pqc/PQLite",
        RuntimeWarning, stacklevel=2
    )

# Import sqlite3's connect and wrap it
import sqlite3 as _stdlib_sqlite3

def connect(database, timeout=5.0, detect_types=0, isolation_level='',
            check_same_thread=True, factory=None, cached_statements=128,
            uri=False):
    """Open a connection to a PQLite/SQLite database.

    This is a drop-in replacement for sqlite3.connect() that uses the
    PQLite library for post-quantum encryption support.

    After connecting, set encryption with:
        conn.execute("PRAGMA pqc_key='your-password'")
    """
    if factory is None:
        factory = Connection

    conn = _stdlib_sqlite3.connect(
        database,
        timeout=timeout,
        detect_types=detect_types,
        isolation_level=isolation_level,
        check_same_thread=check_same_thread,
        factory=factory,
        cached_statements=cached_statements,
        uri=uri,
    )
    return conn


class Connection(_stdlib_sqlite3.Connection):
    """PQLite database connection.

    Extends sqlite3.Connection with PQC-aware methods.
    """

    def pqc_key(self, password):
        """Set the PQC encryption key for this database.

        Equivalent to: PRAGMA pqc_key='password'
        """
        self.execute(f"PRAGMA pqc_key='{password}'")

    def pqc_rekey(self, new_password):
        """Change the PQC encryption key.

        Equivalent to: PRAGMA pqc_rekey='new_password'
        """
        self.execute(f"PRAGMA pqc_rekey='{new_password}'")

    def pqc_version(self):
        """Return the PQLite version string."""
        cursor = self.execute("SELECT pqc_version()")
        row = cursor.fetchone()
        return row[0] if row else None

    def pqc_status(self):
        """Return the PQC encryption status."""
        cursor = self.execute("PRAGMA pqc_status")
        row = cursor.fetchone()
        return row[0] if row else None

    @property
    def is_encrypted(self):
        """Check if this database is PQC-encrypted."""
        cursor = self.execute("PRAGMA pqc_key")
        row = cursor.fetchone()
        return row and row[0] == 'encrypted'


# Module-level convenience
version = __version__
pqlite_version = __version__

def has_pqc():
    """Return True if PQLite native library is loaded."""
    return _has_pqc
