/**
 * PQLite3 — Post-Quantum SQLite for Node.js
 * Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.
 *
 * Drop-in replacement for better-sqlite3 with PQC support.
 *
 * Usage:
 *   const PQLite = require('pqlite3');
 *   const db = new PQLite('secure.db');
 *   db.pragma("pqc_key='my-password'");
 *   db.exec("CREATE TABLE t(x TEXT)");
 *   db.prepare("INSERT INTO t VALUES(?)").run("quantum-safe");
 *   console.log(db.pqcVersion());
 *   db.close();
 *
 * PQLite is a product of Dyber, Inc.
 */

'use strict';

let BetterSqlite3;
try {
  BetterSqlite3 = require('better-sqlite3');
} catch (e) {
  throw new Error(
    'pqlite3 requires better-sqlite3 as a peer dependency. ' +
    'Install it with: npm install better-sqlite3'
  );
}

class PQLiteDatabase extends BetterSqlite3 {
  /**
   * Open a PQLite database.
   * @param {string} filename - Database file path or ':memory:'
   * @param {object} [options] - better-sqlite3 options
   */
  constructor(filename, options = {}) {
    super(filename, options);
  }

  /**
   * Set the PQC encryption key.
   * @param {string} password - Encryption password
   * @returns {object} Pragma result
   */
  pqcKey(password) {
    return this.pragma(`pqc_key='${password}'`);
  }

  /**
   * Change the PQC encryption key.
   * @param {string} newPassword - New encryption password
   * @returns {object} Pragma result
   */
  pqcRekey(newPassword) {
    return this.pragma(`pqc_rekey='${newPassword}'`);
  }

  /**
   * Get the PQLite version string.
   * @returns {string} Version string
   */
  pqcVersion() {
    const row = this.prepare("SELECT pqc_version()").get();
    return row ? Object.values(row)[0] : null;
  }

  /**
   * Get the PQC encryption status.
   * @returns {string} Status string
   */
  pqcStatus() {
    const result = this.pragma('pqc_status');
    return result && result.length > 0 ? result[0].pqc_status : null;
  }

  /**
   * Get the PQC algorithm.
   * @returns {string} Algorithm name (e.g., 'ml-kem-768')
   */
  pqcAlgorithm() {
    const result = this.pragma('pqc_algorithm');
    return result && result.length > 0 ? result[0].pqc_algorithm : null;
  }

  /**
   * Check if database is PQC-encrypted.
   * @returns {boolean}
   */
  get isEncrypted() {
    try {
      const result = this.pragma('pqc_key');
      return result && result.length > 0 && result[0].pqc_key === 'encrypted';
    } catch {
      return false;
    }
  }

  /**
   * Get algorithm info as JSON.
   * @param {string} algorithm - Algorithm name (e.g., 'ml-kem-768')
   * @returns {object} Algorithm metadata
   */
  algorithmInfo(algorithm) {
    const row = this.prepare("SELECT pqc_algorithm_info(?)").get(algorithm);
    if (row) {
      const json = Object.values(row)[0];
      return JSON.parse(json);
    }
    return null;
  }
}

module.exports = PQLiteDatabase;
module.exports.default = PQLiteDatabase;
module.exports.PQLiteDatabase = PQLiteDatabase;
