// PQLite - Post-Quantum SQLite
// Copyright (c) 2025-2026 Dyber, Inc.
//
// Build script: links to system libpqlite3 or libsqlite3.
//
// This crate does NOT bundle SQLite source code. Users must have
// either libpqlite3 or libsqlite3 installed on their system.

fn main() {
    // Try system-installed libpqlite3 via pkg-config
    if pkg_config::probe_library("pqlite3").is_ok() {
        return;
    }

    // Try finding libpqlite3 manually
    println!("cargo:rustc-link-lib=dylib=pqlite3");

    // On macOS, check common Homebrew paths
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-search=/usr/local/lib");
        println!("cargo:rustc-link-search=/opt/homebrew/lib");
    }

    // On Linux, check common paths
    if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-search=/usr/local/lib");
        println!("cargo:rustc-link-search=/usr/lib");
    }

    // On Windows, check common paths
    if cfg!(target_os = "windows") {
        if let Ok(dir) = std::env::var("PQLITE3_LIB_DIR") {
            println!("cargo:rustc-link-search={}", dir);
        }
    }
}
