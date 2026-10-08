# myloginpath - Hardened Go utilities for MySQL's `~/.mylogin.cnf`

[![GoDoc](https://pkg.go.dev/badge/github.com/edsilegxrepo/myloginpath)](https://pkg.go.dev/github.com/edsilegxrepo/myloginpath)

`github.com/edsilegxrepo/myloginpath` is a pure Go library and toolset for reading, writing, and managing MySQL's encrypted credential option files (`~/.mylogin.cnf`), compatible with MySQL's [`mysql_config_editor`](https://dev.mysql.com/doc/refman/8.4/en/mysql-config-editor.html).

This project is a hardened fork of [`github.com/dolmen-go/mylogin`](https://github.com/dolmen-go/mylogin), modernized for current Go versions (Go 1.22+) and enhanced with critical bug fixes, credential leak prevention, structured logging safety, and high-level database connection helpers.

---

## Key Improvements Over the Original

1. **Security & Credential Redaction**:
   - **Masked Password Redaction**: `Login.String()` and `Login.RedactedDSN()` mask passwords (`******`), preventing credential leaks in logs and stack traces.
   - **Structured Logging Support (`slog.LogValuer`)**: Automatically redacts sensitive fields when passing `*Login` to `log/slog`.
   - **Direct Driver Connector**: Connect directly via `Login.Open(db)` or `Login.Connector(db)` without constructing plaintext DSN strings in memory.
2. **Pure-Go `mysql_config_editor` Replacement**:
   - `cmd/mylogin` provides `set`, `remove`, and `list` subcommands matching `mysql_config_editor` behavior without requiring MySQL client tools installed.
3. **Crash & Panic Resilience**:
   - **Blank Line Immunity**: Fixed a runtime panic in `Parse` caused by unchecked `line[0]` indexing on empty lines or trailing newlines.
   - **Malformed Line Safety**: Guarded `parseLine` to safely return descriptive errors on malformed lines rather than panicking on `strings.SplitN`.
4. **Extended MySQL Options Support**:
   - Maps `ssl-mode` (`DISABLED`, `REQUIRED`, `VERIFY_CA`, `VERIFY_IDENTITY`), `connect-timeout`, and `max-allowed-packet` into `*mysql.Config`.
   - Added `Login.Extra map[string]string` to preserve arbitrary options (`default-auth`, `database`, etc.).
5. **Ergonomic API**:
   - Quick one-liners: `mylogin.Get("section")`, `mylogin.Default()`, and `mylogin.Load()`.
   - Direct file persistence: `sections.WriteFile(path)`.
6. **Modern Tooling & Hardened Builds**:
   - Zero `gosec` security findings, zero `govulncheck` vulnerabilities.
   - Position Independent Executable (PIE) builds with `-trimpath` and injected versioning.

---

## Installation

```sh
go get github.com/edsilegxrepo/myloginpath
```

---

## Usage Examples

### 1. Direct Database Connection (No Plaintext DSN in Logs)

```go
package main

import (
	"log"

	"github.com/edsilegxrepo/myloginpath"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	// Read credentials for the "production" login path (merging with [client])
	login, err := mylogin.Get("production")
	if err != nil {
		log.Fatalf("Failed to read login path: %v", err)
	}

	// Directly obtain a *sql.DB handle using database/sql driver.Connector
	db, err := login.Open("app_db")
	if err != nil {
		log.Fatalf("Failed to open connection: %v", err)
	}
	defer db.Close()
}
```

### 2. Customizing Connection Parameters via `*mysql.Config`

```go
package main

import (
	"database/sql"
	"log"

	"github.com/edsilegxrepo/myloginpath"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	login, err := mylogin.Get("client")
	if err != nil {
		log.Fatalf("Failed to read login path: %v", err)
	}

	// Obtain an official *mysql.Config
	cfg := login.Config()
	cfg.DBName = "reporting"
	cfg.ParseTime = true
	cfg.AllowNativePasswords = true

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
}
```

### 3. Safe Structured Logging (`slog`)

```go
package main

import (
	"log/slog"

	"github.com/edsilegxrepo/myloginpath"
)

func main() {
	login, err := mylogin.Get("client")
	if err != nil {
		return
	}

	// Password is automatically masked as "******" in structured log output
	slog.Info("Loaded MySQL login configuration", "login", login)
}
```

### 4. Creating & Encrypting `.mylogin.cnf` in Pure Go

```go
package main

import (
	"log"
	"strings"

	"github.com/edsilegxrepo/myloginpath"
)

func main() {
	raw := `
[client]
host = "db.internal"
port = 3306

[reporting]
user = "analyst"
password = "secretpassword"
`
	sections, err := mylogin.Parse(strings.NewReader(raw))
	if err != nil {
		log.Fatalf("Parse error: %v", err)
	}

	// Encrypts and writes with restrictive 0600 permissions
	if err := sections.WriteFile("/path/to/.mylogin.cnf"); err != nil {
		log.Fatalf("Write error: %v", err)
	}
}
```

See [`example_test.go`](example_test.go) and [pkg.go.dev](https://pkg.go.dev/github.com/edsilegxrepo/myloginpath) for additional testable examples.

---

## CLI Utilities

Install the included command-line utilities:

### `mylogin`
Manage and inspect `.mylogin.cnf` files in pure Go:
```sh
# Set login path credentials (interactive password prompt or piped stdin)
mylogin set --login-path=production --host=db.example.com --user=app --password

# List configured login paths
mylogin list

# Remove a login path
mylogin remove --login-path=production

# Export in JSON format
mylogin -json

# Print version
mylogin -V
```

### `mylogin-dsn`
Generates a connection string prefix for `go-sql-driver/mysql`:
```sh
mylogin-dsn -database mydb production
```

### `mylogin-key`
Inspects encryption keys in `.mylogin.cnf` files:
```sh
mylogin-key
```

---

## License & Attribution

Original work Copyright 2016-2018 Olivier Mengué.  
Hardened fork Copyright 2026.  
Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
