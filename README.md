# mylogin - Hardened Go Utilities and Driver Integration for MySQL `~/.mylogin.cnf`

[![GoDoc](https://pkg.go.dev/badge/github.com/edsilegxrepo/mylogin)](https://pkg.go.dev/github.com/edsilegxrepo/mylogin)

The `github.com/edsilegxrepo/mylogin` module is an enterprise-grade Go library and command-line utility suite for reading, writing, and managing MySQL encrypted option files (`~/.mylogin.cnf`). It provides full interoperability with MySQL's native [`mysql_config_editor`](https://dev.mysql.com/doc/refman/8.4/en/mysql-config-editor.html) and implements direct `database/sql` driver connection facilities that eliminate plaintext credential exposure in application memory, logs, and stack traces.

---

## Technical Documentation Index

- [Architecture and Technical Specification](./ARCHITECTURE.md): Design decisions, cryptographic mechanics, data flows, edge cases, and memory models.
- [Test Suite and Verification Architecture](./TESTING.md): Test harness architecture, test catalog, 93.4% coverage metrics, and live integration verification.

---

## 1. Application Overview and Objectives

MySQL client utilities read obfuscated authentication credentials from `~/.mylogin.cnf` to eliminate hardcoded passwords in command-line invocations and shell scripts. The `mylogin` module modernizes and hardens this capability for cloud-native Go microservices and administrative tooling.

### Primary Objectives

1. **Native Pure-Go Implementation**: Execute reading, writing, and administrative operations on `.mylogin.cnf` without requiring MySQL client binaries (`mysql`, `mysql_config_editor`) or CGO dynamic libraries installed in the runtime container.
2. **Plaintext DSN Elimination**: Provide direct `driver.Connector` and `sql.OpenDB` handles via [`Login.Open()`](./login.go#L277) and [`Login.Connector()`](./login.go#L267), preventing passwords from being exposed in Data Source Name (DSN) connection strings and downstream driver error logs.
3. **Automated Credential Redaction**: Mask credentials by default in [`Login.String()`](./login.go#L237) and implement [`slog.LogValuer`](./login.go#L242) so that passing credential instances to structured logging systems (`log/slog`) never leaks passwords to log aggregators.
4. **Resilience and Panic Immunity**: Ensure robust AST parsing that rejects malformed tokens, prevents nil pointer dereferences, handles arbitrary newline formats, and uses atomic temporary file replacement for zero-corruption file writes.

---

## 2. Security Assessment

### 2.1 Encryption in Transit

The module parses connection parameters from `.mylogin.cnf` and maps security configurations directly into `*mysql.Config` instances from [`github.com/go-sql-driver/mysql`](https://github.com/go-sql-driver/mysql):

- **SSL Mode Translation**: Client directives specified via `ssl-mode` are mapped directly to driver TLS states:
  - `DISABLED`: Disables TLS on the wire (`cfg.TLSConfig = "false"`).
  - `REQUIRED`: Enforces TLS connection negotiation (`cfg.TLSConfig = "true"`).
  - `VERIFY_CA` / `VERIFY_IDENTITY`: Configures certificate chain validation modes.
- **Wire Protection**: All database queries executed through handles returned by `Login.Open()` enforce configured in-transit encryption between the client process and the MySQL server.

### 2.2 Secret Management and Memory Sanitization

- **Credential Redaction**: The string representation of any `Login` struct automatically masks the password:
  ```go
  // Output format from login.String() or login.RedactedDSN()
  "app_user:******@tcp(db.example.internal:3306)/"
  ```
- **Structured Telemetry Protection**: The `Login` struct implements the `slog.LogValuer` interface. Passing `*Login` to `slog.Info`, `slog.Warn`, or `slog.Error` generates structured groups with sensitive fields replaced by `******`.
- **In-Memory Sanitization**: Cryptographic keys implement [`Key.Zero()`](./mylogin.go#L63) and credential models implement [`Login.Zero()`](./login.go#L111). Applications can explicitly wipe key bytes and credential pointers from process heap memory immediately after establishing database connections.

### 2.3 Authentication Configuration

- **Supported Mechanisms**: Compatible with all MySQL authentication plugins supported by `go-sql-driver/mysql`, including `caching_sha2_password`, `mysql_native_password`, and `sha256_password`.
- **Direct Connector Pattern**: By leveraging `mysql.NewConnector`, the application bypasses connection string serialization. The driver maintains credentials inside internal driver state, protecting credentials against inspection via process argument listings or generic connection URL inspectors.

### 2.4 Access Control and RBAC

- **Host Discretionary Access Control (DAC)**: The security model of `.mylogin.cnf` relies on host-level operating system user boundaries.
- **Strict Permission Enforcement**: On POSIX filesystems, [`CheckPermissions`](./mylogin.go#L126) validates that the target file has permissions no more permissive than `0600` (`-rw-------`). If group or world permissions (`0644`, `0666`, etc.) are detected, file operations abort immediately with an error.
- **Atomic File Creation**: When writing configuration updates, [`WriteFile`](./mylogin.go#L471) initializes descriptors strictly with mode `0600` prior to writing ciphertext, eliminating permission race conditions during file generation.

### 2.5 Current and Non-Vulnerable Libraries Used

The module maintains a minimal dependency profile:

| Dependency | Version | Vulnerability Status | Architectural Role |
| :--- | :--- | :--- | :--- |
| `github.com/go-sql-driver/mysql` | `v1.10.1` | 0 Known Vulnerabilities (`govulncheck`) | Official MySQL driver, connection configuration, connector interfaces. |
| `golang.org/x/term` | Standard Subrepo | 0 Known Vulnerabilities (`govulncheck`) | Terminal raw mode handling for non-echoing password prompts. |
| `filippo.io/edwards25519` | `v1.2.0` | 0 Known Vulnerabilities (`govulncheck`) | Indirect cryptographic dependency required by `go-sql-driver/mysql`. |

- **Security Auditing**: The repository is continuously audited using `govulncheck ./...` (0 vulnerabilities found) and `gosec ./...` (0 security findings across all AST rules).

### 2.6 Unprivileged Execution Context

The module and its associated command-line binaries are designed to operate exclusively in unprivileged user space:
- No root privileges, `setuid` bits, or elevated capabilities (`CAP_*`) are required.
- All configuration files default to the standard user home directory (`~/.mylogin.cnf`).
- Complies with non-root container deployment standards (e.g. running under arbitrary non-zero UIDs in Kubernetes or OpenShift).

---

## 3. Code Quality Assessment and Best Practices

### 3.1 Codebase Metrics

- **Total Module Statement Coverage**: **93.4%** across all packages (exceeding the 80% enterprise standard).
- **Concurrency Verification**: All unit and integration suites pass under the Go race detector (`go test -race ./...`).
- **Static Analysis Compliance**: 100% compliant with `go vet`, `gofumpt`, and `gosec`.
- **Compiler Hardening**: Built with `-trimpath` (strips absolute filesystem paths from compiled binaries) and `-buildmode=pie` (generates Position Independent Executables compatible with OS ASLR protections).

### 3.2 Automated Makefile Quality Pipeline

The repository provides automated pipeline targets in [Makefile](./Makefile):

```sh
# 1. Format code according to strict canonical rules
make fmt

# 2. Run static analysis (go vet, govulncheck, gosec)
make vet

# 3. Execute unit tests with data race detection
make test

# 4. Generate statement coverage report without polluting repo
make coverage

# 5. Build hardened, stripped PIE binaries
make build
```

---

## 4. Command Line Arguments

### 4.1 `mylogin` (Root Command and Flags)

The `mylogin` binary inspects, formats, and manages `.mylogin.cnf` files.

```
Usage: mylogin [flags] [subcommand] [subcommand-flags]
```

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-file` | `string` | `~/.mylogin.cnf` | Absolute or relative path to the `.mylogin.cnf` option file. |
| `-json` | `bool` | `false` | Export configuration sections in JSON format. Section names are mapped to parent objects. |
| `-remove` | `bool` | `false` | Emit `mysql_config_editor remove` shell commands to recreate deletions. |
| `-replay` | `bool` | `false` | Emit `mysql_config_editor set` shell commands to recreate configuration entries. |
| `-template` | `string` | `""` | Go `text/template` format string. Available custom template functions include `json`. |
| `-templateln` | `string` | `""` | Go `text/template` format string with an automatic trailing newline. |
| `-version` | `bool` | `false` | Display detailed binary version information and exit. |
| `-V` | `bool` | `false` | Display short version string and exit. |

#### Subcommands

##### `mylogin set`
Creates or updates a login path section.

| Flag | Shorthand | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--login-path` | `-p` *(via name)* | `string` | `client` | Name of the configuration section to create or update. |
| `--host` | `-h` | `string` | `""` | Database server hostname or IP address. |
| `--user` | `-u` | `string` | `""` | Database username. |
| `--password` | `-p` | `bool`/`string` | `false` | When passed without value, prompts interactively with terminal echo disabled. Reads from stdin pipe if redirected. Accepts plaintext password when assigned directly (`--password=secret`). |
| `--port` | `-P` | `string` | `""` | Database TCP listening port (e.g. `3306`). |
| `--socket` | `-S` | `string` | `""` | Path to MySQL UNIX domain socket. |
| `--file` | *(none)* | `string` | `~/.mylogin.cnf` | Path to target option file. |
| `--warn` | `-w` | `bool` | `true` | Retained for compatibility with `mysql_config_editor`. |

##### `mylogin remove`
Removes an entire section or selective options within a section.

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--login-path` | `string` | `client` | Target section name. |
| `--user` | `bool` | `false` | Delete only the user key from the specified section. |
| `--host` | `bool` | `false` | Delete only the host key from the specified section. |
| `--password` | `bool` | `false` | Delete only the password key from the specified section. |
| `--port` | `bool` | `false` | Delete only the port key from the specified section. |
| `--socket` | `bool` | `false` | Delete only the socket key from the specified section. |
| `--file` | `string` | `~/.mylogin.cnf` | Path to target option file. |
| `--warn` | `bool` | `true` | Retained for compatibility. |

##### `mylogin list`
Lists configured sections and options.

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--login-path` | `string` | `""` | Optional filter to display only the specified section. When omitted, lists all sections. |
| `--file` | `string` | `~/.mylogin.cnf` | Path to target option file. |

---

### 4.2 `mylogin-dsn`

Generates Data Source Name (DSN) connection prefixes suitable for `go-sql-driver/mysql` or MySQL CLI connection arguments.

```
Usage: mylogin-dsn [flags] [section-name]
```

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-file` | `string` | `~/.mylogin.cnf` | Path to option file. |
| `-database` | `string` | `""` | Database schema name appended to the resulting DSN. |
| `-version` | `bool` | `false` | Display version and exit. |
| `-V` | `bool` | `false` | Short version display. |

---

### 4.3 `mylogin-key`

Inspects and extracts the 20-byte encryption key stored in the header of `.mylogin.cnf`.

```
Usage: mylogin-key [flags]
```

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-file` | `string` | `~/.mylogin.cnf` | Path to option file. |
| `-version` | `bool` | `false` | Display version and exit. |
| `-V` | `bool` | `false` | Short version display. |

---

## 5. Deployment and Usage Examples

### 5.1 Programmatic Go Integration

#### Connecting via `database/sql` (Direct Driver Connector)

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	mylogin "github.com/edsilegxrepo/mylogin"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	// 1. Read and merge global [client] options with [reporting_service] section
	login, err := mylogin.Get("reporting_service")
	if err != nil {
		log.Fatalf("Failed to resolve login configuration: %v", err)
	}

	// 2. Open database connection using direct driver connector (no plaintext DSN)
	db, err := login.Open("analytics")
	if err != nil {
		log.Fatalf("Failed to initialize database pool: %v", err)
	}
	defer db.Close()

	// 3. Configure standard library connection pool parameters
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// 4. Verify connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("Database ping failed: %v", err)
	}

	fmt.Println("Database connection pool established successfully.")
}
```

#### Safe Structured Logging (`slog.LogValuer`)

```go
package main

import (
	"log/slog"
	"os"

	mylogin "github.com/edsilegxrepo/mylogin"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	login, err := mylogin.Get("production")
	if err != nil {
		logger.Error("Failed to load credentials", "error", err)
		return
	}

	// The password field is automatically masked by the slog.LogValuer implementation
	logger.Info("Database profile loaded", "login", login)
}
```

**JSON Log Output Sample:**
```json
{"time":"2026-10-07T20:30:00.000-05:00","level":"INFO","msg":"Database profile loaded","login":{"user":"app_svc","host":"db.internal","port":3306,"socket":"","password":"******"}}
```

---

### 5.2 Command Line Operations

#### Scenario 1: Provisioning a Login Path in Automated Pipelines

Provision credentials non-interactively in automated deployment scripts using either arguments or standard input pipes:

```bash
# Set credentials non-interactively using arguments
mylogin set --login-path=service_db --host=db.production.internal --port=3306 --user=svc_writer --password=VaultProvidedSecret456

# Or pass password via stdin pipe to prevent exposure in process table (ps aux)
echo "VaultProvidedSecret456" | mylogin set --login-path=service_db --host=db.production.internal --port=3306 --user=svc_writer --password
```

#### Scenario 2: Inspecting and Exporting Configurations

```bash
# List all configured login paths
mylogin list
```

**Output Sample:**
```ini
[client]
host = "db.production.internal"
port = 3306
user = "svc_reader"
password = ********

[service_db]
host = "db.production.internal"
port = 3306
user = "svc_writer"
password = ********
```

```bash
# Export configuration to JSON for automation scripts
mylogin -json
```

**Output Sample:**
```json
{
  "client": {
    "host": "db.production.internal",
    "password": "******",
    "port": "3306",
    "user": "svc_reader"
  },
  "service_db": {
    "host": "db.production.internal",
    "password": "******",
    "port": "3306",
    "user": "svc_writer"
  }
}
```

#### Scenario 3: Interoperating with the MySQL Client CLI

Execute queries using MySQL client binaries by injecting connection flags from `mylogin-dsn`:

```bash
# Connect using the native MySQL CLI tool via mylogin-dsn
mysql $(mylogin-dsn -database analytics service_db) -e "SELECT @@version, NOW();"
```

---

## 6. Installation and Compilation

### Compiling from Source

```bash
git clone https://github.com/edsilegxrepo/mylogin.git
cd mylogin
make all
```

Compiled binaries will be generated in `bin/`:
- `bin/mylogin`
- `bin/mylogin-dsn`
- `bin/mylogin-key`

### Installing via Go Toolchain

```bash
go install github.com/edsilegxrepo/mylogin/cmd/mylogin@latest
go install github.com/edsilegxrepo/mylogin/cmd/mylogin-dsn@latest
go install github.com/edsilegxrepo/mylogin/cmd/mylogin-key@latest
```

---

## 7. License and Attribution

- Original work Copyright 2016-2018 Olivier Mengué.
- Modernized and hardened fork Copyright 2026.
- Licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for details.
