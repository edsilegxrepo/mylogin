# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v2.0.0] - 2026-10-07

### Overview
Version 2.0.0 marks a major enterprise hardening and modernization milestone following the fork from `github.com/dolmen-go/mylogin`. This release transforms the project into a production-grade cryptographic library and CLI toolkit featuring direct `database/sql` driver connector integration, in-memory credential sanitization, atomic filesystem persistence, live integration testing against MySQL daemons, zero-disclosure telemetry, and complete elimination of legacy single-letter CLI shorthand flags.

### Added

#### Core Library & Driver Integration
- **Direct Driver Connector**: Added [`Login.Connector(database string)`](./login.go) and [`Login.Open(database string)`](./login.go) methods that initialize `*sql.DB` connection pools directly via `database/sql/driver.Connector`, bypassing plaintext DSN string construction and eliminating password exposure in driver logs and error stacks.
- **Zero-Disclosure Structured Logging**: Implemented `slog.LogValuer` interface on `*Login` to automatically mask credentials (`password="******"`) in Go's standard `log/slog` structured logging.
- **Redacted Connection String Formats**: Added [`Login.RedactedDSN()`](./login.go) and [`Login.RedactedFormatDSN(database string)`](./login.go) for safe operational telemetry.
- **In-Memory Buffer Sanitization**: Added [`Login.Zero()`](./login.go) and [`Key.Zero()`](./mylogin.go) to overwrite sensitive plaintext passwords and 20-byte key arrays with zeroes in memory.
- **Atomic File Persistence**: Added [`mylogin.WriteFile(filename string, plainText io.Reader)`](./mylogin.go) and [`Sections.WriteFile(filename string)`](./sections.go) enforcing staging temp files, `fsync` persistence to non-volatile storage, atomic rename swaps, and strict `0600` permissions.
- **Filesystem Permission Boundary Checks**: Added [`mylogin.CheckPermissions(filename string)`](./mylogin.go) to reject configuration files with permissions more permissive than `0600` (`0o077` mask check).
- **Extended Option Mapping**: Added `Extra map[string]string` to `Login` and updated [`Login.Config()`](./login.go) to parse and map `ssl-mode` (e.g. `DISABLED`, `REQUIRED`, `VERIFY_CA`, `VERIFY_IDENTITY`), `connect-timeout`, and `max-allowed-packet` into `*mysql.Config`.
- **Deep Cloning**: Added [`Login.Clone()`](./login.go) and [`Sections.Clone()`](./sections.go) routines to prevent data races and pointer aliasing across concurrent goroutines.
- **Convenience Top-Level Methods**: Added [`mylogin.Default()`](./mylogin.go), [`mylogin.Get(section string)`](./mylogin.go), and [`mylogin.Load()`](./mylogin.go) for quick programmatic access.

#### Command-Line Tooling (`cmd/mylogin`)
- **Native Subcommands (Pure Go)**: Added `mylogin set`, `mylogin remove` (alias `rm`), and `mylogin list` (alias `ls`) subcommands to manage `.mylogin.cnf` files natively in pure Go without requiring the external `mysql_config_editor` C++ binary.
- **Interactive & Automation Passwords**: Supported secure interactive password prompting on stderr/stdin in `mylogin set -password` alongside non-interactive direct assignment with `-pass` or standard input pipelines.
- **Compile-Time Version Metadata**: Injected build-time Git commit and version tags into `mylogin`, `mylogin-dsn`, and `mylogin-key` via `-ldflags` exposed through the `-version` flag.

#### Test Suite & Quality Assurance
- **Extensive Test Coverage**: Elevated code coverage from legacy baseline (< 50%) to **94.6% statement coverage** across the core library and **94.7% total repository coverage** (target $\ge 80.0\%$).
- **Live Integration Testing**: Implemented [`integration_test.go`](./integration_test.go) executing end-to-end integration workflows against live MySQL server daemons (TCP and UNIX sockets).
- **Hardened Security & Boundary Tests**: Implemented [`hardened_test.go`](./hardened_test.go) and [`coverage_test.go`](./coverage_test.go) verifying PKCS#7 padding boundary exhaustion, DSN injection defense, permission checks, nil receiver safety, and fault-injection mock readers.
- **Testable Godoc Examples**: Added compiler-verified documentation examples in [`example_test.go`](./example_test.go).

#### Documentation
- **Operational Manual**: Authoritative [`README.md`](./README.md) detailing security assessments, threat vectors, CLI flag specifications, programmatic Go usage, and container deployment guidelines.
- **Architecture Specification**: Enterprise [`ARCHITECTURE.md`](./ARCHITECTURE.md) with mermaid taxonomy flowcharts, AST data lifecycle diagrams, XOR key folding details, and thread-safety models.
- **Test Suite Specification**: Authoritative [`TESTING.md`](./TESTING.md) detailing test architecture, package trees, master inventory of test cases, coverage verification, and troubleshooting guides.
- **Complete Inline Documentation**: Systematically documented every exported symbol, internal helper, and test file with comprehensive package/file headers (Objectives, Core Components, Functionality, Data Flows, and Test Strategies).

### Changed
- **Module Rebranding**: Rebranded Go module from `github.com/dolmen-go/mylogin` to `github.com/edsilegxrepo/mylogin`.
- **License**: Relicensed project from original repository terms to the [MIT License](./LICENSE).
- **Build Infrastructure**: Modernized [`Makefile`](./Makefile) with hardened security tooling targets:
  - Formatter: `gofumpt -l -w`
  - Linter: `go vet ./...`
  - Vulnerability Scanner: `govulncheck ./...` (0 vulnerabilities found)
  - Security Static Analysis: `gosec ./...` (0 issues found)
  - Hardened Compilation: Integrated `GO_OPTS="-trimpath -buildmode=pie"` for Position Independent Executable binaries.
  - Test Runner: Enforced `-race` flag across all test invocations.
- **DRY Refactoring**: Centralized option mapping, unescaping routines, and CLI error handling across `cmd/mylogin`, `cmd/mylogin-dsn`, and `cmd/mylogin-key`.

### Removed
- **Shorthand CLI Flags**: Completely removed single-letter shorthand flags (`-G`, `-u`, `-h`, `-P`, `-S`, `-p`, `-V`) across all CLI binaries (`cmd/mylogin`, `cmd/mylogin-dsn`, `cmd/mylogin-key`) to eliminate cognitive ambiguity (e.g. MySQL's internal `-G` terminology and uppercase `-P` port vs. lowercase `-p` password collision) in favor of uniform, self-documenting flags (`-login-path`, `-user`, `-host`, `-port`, `-socket`, `-password`, `-pass`, `-version`).

### Security
- **Vulnerability Remediation**: Verified 0 vulnerabilities via `govulncheck` and 0 security issues via `gosec` (remediated G115 integer overflows, G104 unhandled errors, and G304 audited path handling).
- **Transient Memory Scavenging**: Added automatic zeroing of intermediate folded key material from stack memory during AES-128 XOR key derivation.
- **Hostile Payload Rejection**: Enforced strict AES block size checks and PKCS#7 validation to abort decompression upon encountering malformed ciphertext blocks.

---

## [v1.1.0] - 2023-04-02

### Added
- Added `-templateln` format flag to `cmd/mylogin` for emitting Go template output with an automatic trailing newline.
- Added `groupSuffix` metadata to JSON and template output representations.

---

## [v1.0.0] - 2023-01-24

### Fixed
- Fixed critical incomplete read bug during mylogin option file streaming and decryption.
- Resolved PKCS#7 padding boundary condition on exact 16-byte padded blocks.

### Added
- Initial implementation of AES-128-CBC decryption and XOR key folding compatible with MySQL `mysql_config_editor`.
- CLI utilities `mylogin`, `mylogin-dsn`, and `mylogin-key`.
- INI section tokenization and basic DSN formatting for `go-sql-driver/mysql`.
