# PQLite Language Bindings

Copyright (c) 2025-2026 Dyber, Inc. All rights reserved.

## Available Bindings

| Language | Directory | Package | Install |
|----------|-----------|---------|---------|
| **Python** | `python/` | `pqlite3` | `pip install pqlite3` |
| **Rust** | `rust/` | `pqlite` / `libpqlite3-sys` | `cargo add pqlite` |
| **Node.js** | `node/` | `pqlite3` | `npm install pqlite3` |
| **Go** | `go/` | `github.com/dyber-pqc/PQLite/bindings/go` | `go get` |
| **Java** | `java/` | `io.dyber.pqlite` | Maven/Gradle |
| **C#/.NET** | `dotnet/` | `PQLite` | NuGet |

## Quick Examples

### Python
```python
import pqlite3 as sqlite3
conn = sqlite3.connect('secure.db')
conn.execute("PRAGMA pqc_key='my-password'")
conn.execute("CREATE TABLE t(x TEXT)")
print(conn.execute("SELECT pqc_version()").fetchone()[0])
```

### Rust
```rust
use pqlite::Connection;
let conn = Connection::open("secure.db")?;
conn.execute_batch("PRAGMA pqc_key='my-password'")?;
println!("{}", conn.pqc_version()?);
```

### Node.js
```javascript
const PQLite = require('pqlite3');
const db = new PQLite('secure.db');
db.pqcKey('my-password');
console.log(db.pqcVersion());
```

### Go
```go
db, _ := pqlite.Open("secure.db")
db.PQCKey("my-password")
ver, _ := db.PQCVersion()
fmt.Println(ver)
```

### Java
```java
var conn = PQLiteConnection.open("secure.db");
conn.pqcKey("my-password");
System.out.println(conn.pqcVersion());
```

### C#
```csharp
var db = new PQLiteConnection("secure.db");
db.PqcKey("my-password");
Console.WriteLine(db.PqcVersion());
```

All bindings are MIT licensed. PQLite is a product of Dyber, Inc.
