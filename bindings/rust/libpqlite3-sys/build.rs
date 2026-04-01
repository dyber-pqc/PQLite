// PQLite - Post-Quantum SQLite
// Copyright (c) 2025-2026 Dyber, Inc.
//
// Build script: compiles the PQLite amalgamation from source.

fn main() {
    // Try to find system-installed libpqlite3 first
    if pkg_config::probe_library("pqlite3").is_ok() {
        return;
    }

    // Fall back to compiling from source
    let mut build = cc::Build::new();
    build
        .file("../../../sqlite3.c")
        .define("SQLITE_CORE", None)
        .define("SQLITE_ENABLE_FTS5", None)
        .define("SQLITE_ENABLE_JSON1", None)
        .define("SQLITE_ENABLE_RTREE", None)
        .define("SQLITE_ENABLE_COLUMN_METADATA", None)
        .define("SQLITE_THREADSAFE", "1")
        .warnings(false);

    // Enable PQC if liboqs is available
    if pkg_config::probe_library("liboqs").is_ok() {
        build.define("PQLITE_ENABLE_PQC", None);
        // Add PQC source files
        for entry in std::fs::read_dir("../../../src/pqc").unwrap() {
            let path = entry.unwrap().path();
            if path.extension().map_or(false, |e| e == "c") {
                build.file(&path);
            }
        }
        build.include("../../../src/pqc");
        println!("cargo:rustc-link-lib=oqs");
        println!("cargo:rustc-link-lib=crypto");
    }

    build.include("../../../src");
    build.include("../../..");
    build.compile("pqlite3");
}
