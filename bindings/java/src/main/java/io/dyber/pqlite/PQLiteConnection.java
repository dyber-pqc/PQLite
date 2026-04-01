/*
 * PQLite - Post-Quantum SQLite
 * Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
 *
 * Java JDBC-compatible wrapper for PQLite.
 *
 * Usage:
 *   PQLiteConnection conn = PQLiteConnection.open("secure.db");
 *   conn.pqcKey("my-password");
 *   conn.execute("CREATE TABLE t(x TEXT)");
 *   conn.execute("INSERT INTO t VALUES('quantum-safe')");
 *   System.out.println(conn.pqcVersion());
 *   conn.close();
 *
 * For full JDBC, use with org.xerial:sqlite-jdbc compiled against
 * libpqlite3 instead of libsqlite3.
 *
 * PQLite is a product of Dyber, Inc.
 */
package io.dyber.pqlite;

import java.sql.*;

/**
 * PQLite database connection wrapper.
 * Provides PQC-specific convenience methods on top of a standard
 * JDBC Connection to a PQLite/SQLite database.
 */
public class PQLiteConnection implements AutoCloseable {
    private final Connection jdbcConnection;

    private PQLiteConnection(Connection conn) {
        this.jdbcConnection = conn;
    }

    /**
     * Open a PQLite database.
     * Requires sqlite-jdbc compiled against libpqlite3.
     *
     * @param path Database file path or ":memory:"
     * @return PQLiteConnection instance
     * @throws SQLException if connection fails
     */
    public static PQLiteConnection open(String path) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:sqlite:" + path);
        return new PQLiteConnection(conn);
    }

    /**
     * Open an in-memory PQLite database.
     */
    public static PQLiteConnection openMemory() throws SQLException {
        return open(":memory:");
    }

    /**
     * Get the underlying JDBC connection.
     */
    public Connection getJdbcConnection() {
        return jdbcConnection;
    }

    /**
     * Execute a SQL statement.
     */
    public void execute(String sql) throws SQLException {
        try (Statement stmt = jdbcConnection.createStatement()) {
            stmt.execute(sql);
        }
    }

    /**
     * Set the PQC encryption key.
     *
     * @param password Encryption password
     */
    public void pqcKey(String password) throws SQLException {
        execute("PRAGMA pqc_key='" + password + "'");
    }

    /**
     * Change the PQC encryption key.
     *
     * @param newPassword New encryption password
     */
    public void pqcRekey(String newPassword) throws SQLException {
        execute("PRAGMA pqc_rekey='" + newPassword + "'");
    }

    /**
     * Get the PQLite version string.
     *
     * @return Version string (e.g., "PQLite 1.1.0 ...")
     */
    public String pqcVersion() throws SQLException {
        try (Statement stmt = jdbcConnection.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT pqc_version()")) {
            if (rs.next()) {
                return rs.getString(1);
            }
        }
        return null;
    }

    /**
     * Get the PQC algorithm name.
     *
     * @return Algorithm name (e.g., "ml-kem-768")
     */
    public String pqcAlgorithm() throws SQLException {
        try (Statement stmt = jdbcConnection.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA pqc_algorithm")) {
            if (rs.next()) {
                return rs.getString(1);
            }
        }
        return null;
    }

    /**
     * Get algorithm info as a JSON string.
     *
     * @param algorithm Algorithm name
     * @return JSON metadata string
     */
    public String algorithmInfo(String algorithm) throws SQLException {
        try (PreparedStatement pstmt = jdbcConnection.prepareStatement(
                "SELECT pqc_algorithm_info(?)")) {
            pstmt.setString(1, algorithm);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString(1);
                }
            }
        }
        return null;
    }

    @Override
    public void close() throws SQLException {
        if (jdbcConnection != null && !jdbcConnection.isClosed()) {
            jdbcConnection.close();
        }
    }
}
