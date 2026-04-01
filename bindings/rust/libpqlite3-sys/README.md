# libpqlite3-sys

Native FFI bindings to [PQLite](https://github.com/dyber-pqc/PQLite) (Post-Quantum SQLite).

For a safe Rust API, use the [`pqlite`](https://crates.io/crates/pqlite) crate instead.

## Requirements

Install PQLite on your system first:

```bash
# Ubuntu/Debian
sudo add-apt-repository ppa:dyber/pqlite
sudo apt install libpqlite3-dev

# macOS
brew tap dyber-pqc/tap && brew install pqlite

# Or build from source
git clone https://github.com/dyber-pqc/PQLite.git
cd PQLite && ./configure && make sqlite3.c && cmake -B build -DPQLITE_PQC=ON && cmake --build build && sudo cmake --install build
```

## License

MIT — Copyright (c) 2025-2026 Dyber, Inc.
