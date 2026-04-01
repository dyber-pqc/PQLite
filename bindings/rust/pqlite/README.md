# pqlite

Safe Rust bindings for [PQLite](https://github.com/dyber-pqc/PQLite) (Post-Quantum SQLite).

```rust
use pqlite::Connection;

let conn = Connection::open("secure.db")?;
conn.pqc_key("my-quantum-safe-password")?;
conn.execute_batch("CREATE TABLE t(x TEXT)")?;
conn.execute("INSERT INTO t VALUES(?1)", &["quantum-safe"])?;
println!("{}", conn.pqc_version()?);
```

## Features

- ML-KEM-768 key encapsulation (FIPS 203)
- AES-256-GCM transparent page encryption
- ML-DSA-65 digital signatures (FIPS 204)
- Drop-in replacement for rusqlite's API style

## Requirements

Install PQLite on your system: https://github.com/dyber-pqc/PQLite#installation

## License

MIT — Copyright (c) 2025-2026 Dyber, Inc.
