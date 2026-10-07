# myloginpath - Hardened Go utilities for MySQL's `~/.mylogin.cnf`

[![GoDoc](https://pkg.go.dev/badge/github.com/edsilegxrepo/myloginpath)](https://pkg.go.dev/github.com/edsilegxrepo/myloginpath)

`github.com/edsilegxrepo/myloginpath` is a pure Go library and toolset for reading, writing, and parsing MySQL's encrypted credential option files (`~/.mylogin.cnf`), created and managed by MySQL's [`mysql_config_editor`](https://dev.mysql.com/doc/refman/8.4/en/mysql-config-editor.html).

This project is a hardened fork of [`github.com/dolmen-go/mylogin`](https://github.com/dolmen-go/mylogin), modernized for current Go versions (Go 1.22+) and enhanced with critical bug fixes, improved error handling, and robust production features.

---

## Key Improvements Over the Original

1. **Crash & Panic Resilience**:
   - **Blank Line Immunity**: Fixed a runtime panic in `Parse` caused by unchecked `line[0]` indexing on empty lines or trailing newlines.
   - **Malformed Line Safety**: Guarded `parseLine` to safely return descriptive errors on malformed lines rather than panicking on `strings.SplitN`.
2. **Extended MySQL Options Support**:
   - Added `Login.Extra map[string]string` to store non-standard or newer client options (such as `default-auth`, `ssl-mode`, `database`, `ssl-ca`) without failing.
3. **Deep Copying in Merge**:
   - Prevents pointer aliasing issues when merging multiple sections (e.g. `[client]` and a specific `--login-path`).
4. **Driver Integration Helpers**:
   - Added `Login.Config() *mysql.Config` method directly returning an official `*mysql.Config` from [`github.com/go-sql-driver/mysql`](https://github.com/go-sql-driver/mysql) for safe formatting and connection parameters.
   - Added high-level `WriteFile(path, reader)` and `NewFile` helpers for one-line encrypted file generation.
5. **Modernized Standard Library Conventions**:
   - Cross-platform home directory resolution using standard `os.UserHomeDir()` with fallback to `$HOME` and `%APPDATA%`.
   - Fixed `NewKey` error-swallowing bug where random generator errors were replaced with `nil`.

---

## Installation

```sh
go get github.com/edsilegxrepo/myloginpath
```

---

## Usage Examples

### 1. Reading Credentials & Constructing a DSN

```go
package main

import (
	"database/sql"
	"log"

	"github.com/edsilegxrepo/myloginpath"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	// Read credentials, merging global [client] with [production]
	login, err := mylogin.ReadLogin(mylogin.DefaultFile(), []string{mylogin.DefaultSection, "production"})
	if err != nil {
		log.Fatalf("Failed to read login file: %v", err)
	}

	// Format DSN using built-in helper or driver config
	cfg := login.Config()
	cfg.DBName = "app_db"
	cfg.ParseTime = true

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
}
```

### 2. Creating an Encrypted `.mylogin.cnf`

```go
package main

import (
	"log"
	"strings"

	"github.com/edsilegxrepo/myloginpath"
)

func main() {
	rawContent := "[client]\nhost = \"db.internal\"\nport = 3306\n" +
		"[reporting]\nuser = \"analyst\"\npassword = \"secret\"\n"

	err := mylogin.WriteFile("/path/to/.mylogin.cnf", strings.NewReader(rawContent))
	if err != nil {
		log.Fatalf("Failed to write encrypted file: %v", err)
	}
}
```

---

## CLI Utilities

Install the included command-line utilities:

- **`mylogin`**: Dumps `.mylogin.cnf` contents in plaintext, JSON, or `mysql_config_editor set` replay commands.
  ```sh
  go install github.com/edsilegxrepo/myloginpath/cmd/mylogin@latest
  mylogin -json
  ```

- **`mylogin-dsn`**: Generates a connection string prefix for `go-sql-driver/mysql`.
  ```sh
  go install github.com/edsilegxrepo/myloginpath/cmd/mylogin-dsn@latest
  mylogin-dsn -database mydb production
  ```

- **`mylogin-key`**: Inspects encryption keys in `.mylogin.cnf` files.
  ```sh
  go install github.com/edsilegxrepo/myloginpath/cmd/mylogin-key@latest
  mylogin-key
  ```

---

## License & Attribution

Original work Copyright 2016-2018 Olivier Mengué.  
Hardened fork Copyright 2026.  
Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
