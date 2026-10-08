# mylogin - Hardened Go Utilities and Driver Integration for MySQL `~/.mylogin.cnf`

[![GoDoc](https://pkg.go.dev/badge/github.com/edsilegxrepo/mylogin)](https://pkg.go.dev/github.com/edsilegxrepo/mylogin)

The `github.com/edsilegxrepo/mylogin` module is an enterprise-grade Go library and command-line utility suite for reading, writing, and managing MySQL encrypted option files (`~/.mylogin.cnf`). It provides full interoperability with MySQL's native [`mysql_config_editor`](https://dev.mysql.com/doc/refman/8.4/en/mysql-config-editor.html) and implements direct `database/sql` driver connection facilities that eliminate plaintext credential exposure in application memory, logs, and stack traces.

---

## Technical Documentation Index

To maintain a single source of truth without content duplication, detailed architectural models and test specifications reside in dedicated documentation files:

- [ARCHITECTURE.md](./ARCHITECTURE.md): Authoritative specification for system architecture, AES-128-ECB mechanics, AST parsing, concurrency guarantees, security threat models, and package dependencies.
- [TESTING.md](./TESTING.md): Authoritative specification for test suite architecture, logic flows, master test inventory, live MySQL daemon provisioning, and statement coverage metrics (94.2%).

---

## 1. Application Overview and Objectives

MySQL client utilities read obfuscated authentication credentials from `~/.mylogin.cnf` to eliminate hardcoded passwords in command-line invocations and shell scripts. The `mylogin` module modernizes and hardens this capability for cloud-native Go microservices and administrative tooling.

### Primary Objectives

1. **Native Pure-Go Implementation**: Execute reading, writing, and administrative operations on `.mylogin.cnf` without requiring MySQL client binaries (`mysql`, `mysql_config_editor`) or CGO dynamic libraries installed in the runtime container.
2. **Plaintext DSN Elimination**: Provide direct `driver.Connector` and `sql.OpenDB` handles via [`Login.Open()`](./login.go#L277) and [`Login.Connector()`](./login.go#L267), preventing passwords from being exposed in Data Source Name (DSN) connection strings and downstream driver error logs.
3. **Automated Credential Redaction**: Mask credentials by default in [`Login.String()`](./login.go#L237) and implement [`slog.LogValuer`](./login.go#L242) so that passing credential instances to structured logging systems (`log/slog`) never leaks passwords to log aggregators.
4. **Resilience and Panic Immunity**: Ensure robust AST parsing that rejects malformed tokens, prevents nil pointer dereferences, handles arbitrary newline formats, and uses atomic temporary file replacement for zero-corruption file writes.

*For architectural design choices, component block diagrams, and edge-case handling strategies, refer to [ARCHITECTURE.md § 1. Architecture, Design Choices, Assumptions, Edge Cases, and Efficiency](./ARCHITECTURE.md#1-architecture-design-choices-assumptions-edge-cases-and-efficiency).*

---

## 2. Security Assessment

### 2.1 Encryption in Transit

The module parses connection parameters from `.mylogin.cnf` and maps security configurations directly into `*mysql.Config` instances from [`github.com/go-sql-driver/mysql`](https://github.com/go-sql-driver/mysql):
- `ssl-mode` parameters (`DISABLED`, `REQUIRED`, `VERIFY_CA`, `VERIFY_IDENTITY`) translate directly into driver TLS configurations.
- Queries executed through handles returned by `Login.Open()` enforce encrypted TLS wire transport between the client process and MySQL.

### 2.2 Secret Management and Memory Sanitization

- **Credential Redaction**: `Login.String()` and `Login.RedactedDSN()` mask passwords (`app_user:******@tcp(host:port)/`).
- **Structured Telemetry Protection**: Passing `*Login` to `log/slog` formats sensitive fields with `******`.
- **In-Memory Sanitization**: Explicit memory scrubbing via [`Key.Zero()`](./mylogin.go#L63) and [`Login.Zero()`](./login.go#L111) clears key bytes and sensitive pointers from process heap memory.

### 2.3 Access Control and Unprivileged Execution Context

- **Host Discretionary Access Control (DAC)**: Security relies on OS file isolation. On POSIX filesystems, [`CheckPermissions`](./mylogin.go#L126) rejects files with permissions more permissive than `0600` (`-rw-------`).
- **Unprivileged Runtime**: Operates strictly within user-space context (`~/.mylogin.cnf`). No root privileges or elevated capabilities (`CAP_*`) are required, supporting non-root container deployment standards.
- **Dependency Audit**: Verified clean with 0 known vulnerabilities (`govulncheck`) and 0 static security issues (`gosec`).

*For the complete threat model, cryptographic limitations of AES-128-ECB, security architecture diagrams, and runtime module inventories, refer to [ARCHITECTURE.md § 5. Security Architecture](./ARCHITECTURE.md#5-security-architecture) and [ARCHITECTURE.md § 4. Dependencies and Runtime Environment](./ARCHITECTURE.md#4-dependencies-and-runtime-environment).*

---

## 3. Code Quality and Verification Summary

- **Total Module Statement Coverage**: **94.2%** across all packages, verified with Go's data race detector (`-race`).
- **Compiler Hardening**: Built with `-trimpath` and `-buildmode=pie` Position Independent Executables with stripped debug symbols (`-ldflags "-s -w"`).
- **Code Standards**: 100% compliant with canonical `gofumpt` formatting, `go vet`, and `gosec` AST analysis.

*For complete statement coverage tables, package breakdowns, and execution recipes in Bash and PowerShell, refer to [TESTING.md § 6. Code Coverage Report](./TESTING.md#6-code-coverage-report) and [TESTING.md § 8. How to Run the Tests](./TESTING.md#8-how-to-run-the-tests).*

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
- Modernized and hardened fork Copyright 2026 Critical Systems.
- Licensed under the MIT License. See [LICENSE](./LICENSE) for details.
