# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v1.7.0] - 2026-10-13

### Overview
Version 1.7.0 introduces canonical global option file auto-discovery (`/etc/my.cnf`, `/etc/mysql/my.cnf`, `/usr/local/etc/my.cnf`, `%WINDIR%\my.ini`, `%PROGRAMDATA%\MySQL\MySQL Server *\my.ini`) establishing a full 4-tier configuration cascade hierarchy, robust AST INI parser hardening (tolerance for `!include` and `!includedir` directives, inline comment stripping, bare boolean flag support, and kebab-case/snake_case key normalization), comprehensive MySQL property mappings to `*mysql.Config` and TLS (read/write timeouts, character set vs. collation disambiguation, session pragmas, TLS version and cipher suite controls, CA path directory loading), and remote TCP socket hijacking prevention.

### Added

#### Global Option Files & 4-Tier Cascade
- **Global Option File Discovery**: Added [`mylogin.GlobalOptionFiles()`](./clientdefaults.go) and [`mylogin.DefaultOptionFiles()`](./clientdefaults.go) discovering canonical system configuration paths across Linux, macOS, and Windows.
- **Hierarchical Cascade Resolution**: Added [`mylogin.ReadResolvedLoginHierarchy(myloginFile string, optionFiles []string, sectionNames []string)`](./mylogin.go) and [`mylogin.ReadClientDefaultsHierarchy(filenames []string)`](./clientdefaults.go) executing the full 4-tier precedence:
  1. Global option files (`/etc/my.cnf`, `%WINDIR%\my.ini`, etc.) `[client]` section (lowest priority)
  2. User plaintext option files (`~/.my.cnf`, `%APPDATA%\MySQL\.my.cnf`) `[client]` section
  3. Encrypted `.mylogin.cnf` `[client]` section
  4. Encrypted `.mylogin.cnf` target login-path section (highest priority)
- **Environment Overrides**:
  - `MYSQL_GLOBAL_OPTION_FILE`: Explicitly overrides or specifies global option file path.
  - `MYSQL_OPTION_FILE`: Explicitly overrides user option file path.
  - `MYSQL_TEST_OPTION_FILE`: Enforces hermetic testing isolation by overriding option paths and suppressing global scanning.

#### INI Parser Hardening & Normalization
- **Directive Tolerance**: Safely skips `!include` and `!includedir` directives in `mylogin.Parse()` and `ReadClientDefaults()` without syntax errors.
- **Inline Comment Stripping**: Strips `#` and `;` comments outside quoted string literals.
- **Bare Boolean Client Flags**: Recognizes standard MySQL client flags (`compress`, `quick`, `skip-auto-rehash`, `auto-rehash`, `unbuffered`, `batch`, `silent`, `verbose`, `show-warnings`, `skip-column-names`, `skip-line-numbers`, `local-infile`, `skip-local-infile`, `skip-ssl`) without `=` and assigns `"true"`.
- **Negation Prefix Handling**: Normalizes bare negation flags (`skip-foo`, `disable-foo`, `no-foo`) to also negate the underlying base flag (e.g. `skip-local-infile` sets `local-infile=false`).
- **Key Normalization**: Automatically normalizes option keys to lowercase kebab-case (`connect_timeout` -> `connect-timeout`) and strips MySQL `loose-` prefixes (`loose-default-character-set` -> `default-character-set`).
- **Single-Quote Support**: Unquotes single-quoted values (`'value'`) in addition to double quotes (`"value"`).

#### Driver & TLS Property Mapping
- **Socket Hijacking Mitigation**: Prevents base global/client Unix sockets from hijacking remote TCP host definitions unless `protocol=socket` or `host=localhost`.
- **Extended Timeouts**: Maps `read-timeout` to `cfg.ReadTimeout` and `write-timeout` to `cfg.WriteTimeout`.
- **Character Set vs. Collation Disambiguation**: Distinguishes collations (containing `_`) from character sets (`utf8mb4`), mapping canonical default collations (e.g. `utf8mb4_general_ci`) and driver `cfg.Params["charset"]`.
- **Session & Driver Pragmas**: Maps `init-command`, `sql-mode`, `local-infile`, `enable-cleartext-plugin`, `allow-native-passwords`, `check-conn-liveness`, `client-found-rows`, `columns-with-alias`, `interpolate-params`, `multi-statements`, `parse-time`, `reject-read-only`, and `time-zone` / `loc` into `*mysql.Config`.
- **Advanced TLS Controls**:
  - `tls-version`: Maps minimum and maximum TLS protocol versions (`TLSv1.2`, `TLSv1.3`), handling surrounding single or double quotes gracefully.
  - `ssl-capath`: Loads all PEM-formatted CA certificates from a directory pool, supporting `.pem`, `.crt`, `.cer`, and OpenSSL `c_rehash` numeric hash symlinks (`.0`, `.1`, ...).
  - `ssl-cipher` / `tls-ciphersuites`: Customizes allowed cipher suites, checking both modern secure suites and legacy/insecure suites (e.g. `TLS_RSA_WITH_AES_128_CBC_SHA`).
  - `ssl-verify-server-cert`: Toggles server certificate hostname verification.
  - `skip-ssl` and `ssl=0`: Explicitly disables TLS configuration (`cfg.TLSConfig = "false"`).
  - SHA-256 profile caching includes all extended TLS attributes for deterministic registration.

#### CLI Enhancements
- **Multi-File Cascade Flags**: Added `-option-file` and `-global-option-file` flags to `mylogin-dsn`, `mylogin-connect`, and `mylogin-inspect`.
- **Inspection Reporting**: `mylogin-inspect` now reports all discovered option files in priority cascade order.

---

## [v1.6.0] - 2026-10-08

### Overview
Version 1.6.0 introduces automatic cascading resolution for plaintext MySQL client option files (`.my.cnf`), comprehensive TLS/SSL configuration with custom Certificate Authorities (CA) and mutual TLS (mTLS) client authentication directly in the database driver connector, cross-platform path resolution supporting Microsoft Windows, and new diagnostic inspection utilities.

### Added

#### Plaintext Option File Integration (`.my.cnf`)
- **Cascading Configuration Resolution**: Added [`mylogin.ReadResolvedLogin(myloginFile, optionFile string, sectionNames []string)`](./mylogin.go) implementing a 3-tier hierarchical configuration merge:
  1. Plaintext `.my.cnf` `[client]` options (base defaults)
  2. Encrypted `.mylogin.cnf` `[client]` options (overrides plaintext)
  3. Encrypted `.mylogin.cnf` target section options (highest priority)
- **Automatic Default File Discovery**: Added [`mylogin.DefaultOptionFile()`](./clientdefaults.go) to locate the user's plaintext option file via `MYSQL_TEST_OPTION_FILE` or operating system defaults:
  - Unix / macOS: `~/.my.cnf` via [`defaultoptionfile.go`](./defaultoptionfile.go)
  - Windows: `%APPDATA%\MySQL\.my.cnf` with roaming user profile fallback via [`defaultoptionfile_windows.go`](./defaultoptionfile_windows.go)
- **Client Defaults API**: Added [`mylogin.DefaultClientDefaults()`](./clientdefaults.go) and [`mylogin.ReadClientDefaults(filename string)`](./clientdefaults.go) to parse `[client]` options from plaintext configuration files, gracefully returning an empty `Login` if the file does not exist.
- **Seamless Top-Level Resolution**: Updated [`mylogin.Default()`](./mylogin.go) and [`mylogin.Get(section string)`](./mylogin.go) to automatically invoke `ReadResolvedLogin`, ensuring existing applications transparently inherit system-wide `.my.cnf` client defaults.

#### Driver TLS / SSL & Mutual TLS (mTLS)
- **Cryptographic TLS Negotiation**: Extended [`Login.Connector(database string)`](./login.go) to automatically configure and register TLS connection parameters using [`Login.configWithTLS()`](./login_tls.go).
- **SSL Mode Support**: Full compliance with MySQL `ssl-mode` directives:
  - `DISABLED`: Disables TLS encryption (`TLSConfig = "false"`).
  - `REQUIRED`: Enforces encrypted transport with `InsecureSkipVerify = true`.
  - `VERIFY_CA`: Validates server certificate chains against custom CA root pools without requiring hostname verification.
  - `VERIFY_IDENTITY`: Full cryptographic validation of certificate chains and Subject Alternative Names (SAN) / hostname matching.
- **Custom Certificate Authority (CA)**: Added `ssl-ca` parsing in [`loadRootCAs`](./login_tls.go) to construct dedicated `x509.CertPool` trust stores from custom PEM files.
- **Mutual TLS (mTLS) Client Authentication**: Added `ssl-cert` and `ssl-key` pairing via `tls.LoadX509KeyPair` to present client certificates for two-way authenticated database clusters.
- **Deterministic TLS Registration**: Implemented thread-safe, deterministic SHA-256 hash-based TLS profile caching and registration with `mysql.RegisterTLSConfig`, preventing duplicate registrations and unbounded memory leaks in driver registries.

#### Tooling & Diagnostics
- **Connection Test Utility**: Added [`cmd/mylogin-connect`](./cmd/mylogin-connect/main.go) for verifying end-to-end driver connection, dry-run connector creation, and ping operations against configured target databases.
- **Inspection Diagnostic Utility**: Added [`cmd/mylogin-inspect`](./cmd/mylogin-inspect/main.go) to inspect default option file discovery, resolved connection parameters, password status, and active `Extra` configuration keys.

#### Test Suite & Verification
- **Cascade Precedence Tests**: Implemented [`clientdefaults_test.go`](./clientdefaults_test.go) verifying missing file resilience, empty path handling, plaintext client inheritance, and encrypted section override hierarchies.
- **TLS & mTLS Verification**: Implemented [`login_tls_test.go`](./login_tls_test.go) and [`login_tls_internal_test.go`](./login_tls_internal_test.go) asserting missing key validation errors on partial mTLS configurations, deterministic cache reuse, system root fallback for `VERIFY_CA`, and in-memory PKI verification.
- **Diagnostic CLI Test Suites**: Implemented comprehensive CLI unit test suites in [`cmd/mylogin-inspect/main_test.go`](./cmd/mylogin-inspect/main_test.go) and [`cmd/mylogin-connect/main_test.go`](./cmd/mylogin-connect/main_test.go).

---

## [v1.5.0] - 2026-10-07

### Overview
Version 1.5.0 marks a major enterprise hardening and modernization milestone following the fork from `github.com/dolmen-go/mylogin`. This release transforms the project into a production-grade cryptographic library and CLI toolkit featuring direct `database/sql` driver connector integration, in-memory credential sanitization, atomic filesystem persistence, live integration testing against MySQL daemons, zero-disclosure telemetry, and complete elimination of legacy single-letter CLI shorthand flags.

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

## [v1.1.0] - 2023-04-02 — Upstream [dolmen-go/mylogin](https://github.com/dolmen-go/mylogin)

### Added
- Added `-templateln` format flag to `cmd/mylogin` for emitting Go template output with an automatic trailing newline.
- Added `groupSuffix` metadata to JSON and template output representations.

---

## [v1.0.0] - 2023-01-24 — Upstream [dolmen-go/mylogin](https://github.com/dolmen-go/mylogin)

### Fixed
- Fixed critical incomplete read bug during mylogin option file streaming and decryption.
- Resolved PKCS#7 padding boundary condition on exact 16-byte padded blocks.

### Added
- Initial implementation of AES-128-CBC decryption and XOR key folding compatible with MySQL `mysql_config_editor`.
- CLI utilities `mylogin`, `mylogin-dsn`, and `mylogin-key`.
- INI section tokenization and basic DSN formatting for `go-sql-driver/mysql`.

<!-- Release Link Definitions -->
[v1.7.0]: https://github.com/edsilegxrepo/mylogin/releases/tag/v1.7.0
[v1.6.0]: https://github.com/edsilegxrepo/mylogin/releases/tag/v1.6.0
[v1.5.0]: https://github.com/edsilegxrepo/mylogin/releases/tag/v1.5.0
[v1.1.0]: https://github.com/dolmen-go/mylogin/releases/tag/v1.1.0
[v1.0.0]: https://github.com/dolmen-go/mylogin/releases/tag/v1.0.0
