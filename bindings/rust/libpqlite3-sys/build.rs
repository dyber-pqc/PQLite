// PQLite - Post-Quantum SQLite
// Copyright (c) 2025-2026 Dyber, Inc.
//
// Build script: links to system libpqlite3 or compiles from source.
//
// When publishing to crates.io, users must have libpqlite3 installed
// on their system (via apt, brew, or building from source).
// When building from the PQLite monorepo, it compiles the amalgamation.

fn main() {
    // Try system-installed libpqlite3 via pkg-config
    if pkg_config::probe_library("pqlite3").is_ok() {
        return;
    }

    // Try system-installed sqlite3 as fallback (PQC features won't be available)
    if pkg_config::probe_library("sqlite3").is_ok() {
        eprintln!("cargo:warning=Using system sqlite3 — PQC features not available. Install libpqlite3 for full PQC support.");
        return;
    }

    // Fall back to compiling from source (monorepo build)
    let amalgamation = std::path::Path::new("../../../sqlite3.c");
    if amalgamation.exists() {
        let mut build = cc::Build::new();
        build
            .file(amalgamation)
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
            let pqc_dir = std::path::Path::new("../../../src/pqc");
            if pqc_dir.exists() {
                for entry in std::fs::read_dir(pqc_dir).unwrap() {
                    let path = entry.unwrap().path();
                    if path.extension().map_or(false, |e| e == "c") {
                        build.file(&path);
                    }
                }
                build.include(pqc_dir);
            }
            println!("cargo:rustc-link-lib=oqs");
            println!("cargo:rustc-link-lib=crypto");
        }

        build.include("../../../src");
        build.include("../../..");
        build.compile("pqlite3");
    } else {
        // No system library, no amalgamation — fail with helpful message
        panic!(
            "Could not find libpqlite3 or sqlite3.c amalgamation.\n\
             Install PQLite: https://github.com/dyber-pqc/PQLite#installation\n\
             Or build from the monorepo: ./configure && make sqlite3.c"
        );
    }
}
