package mylogin

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Objective: Provide an in-memory domain model for MySQL client credentials,
// supporting secure credential redaction, official Go MySQL driver integration,
// structured logging telemetry, and direct connection pool instantiation.
//
// Core Components:
//   - Login: Strongly typed struct representing section options (user, password, host, port, socket, Extra).
//   - Clone / Merge: Deep-copy mechanisms providing memory isolation between goroutines.
//   - Set / Map: Consolidated key-value accessors unifying AST parsing and CLI operations.
//   - Zero: Defensive memory scrubber wiping passwords and sensitive byte allocations.
//   - Connector / Open: Direct database/sql integration bypassing plaintext DSN construction.
//   - RedactedDSN / LogValue: Telemetry protections preventing credential leakage in logs and traces.
//
// Functionality:
//   - Translates raw INI key-value pairs into structured Go pointers and maps.
//   - Maps MySQL 8.0 client parameters (ssl-mode, connect-timeout, max-allowed-packet) into *mysql.Config.
//   - Eliminates connection string exposure by leveraging mysql.NewConnector and sql.OpenDB.
//
// Data Flow:
//   Decrypted INI Stream -> parseLine -> Unescape/Unquote -> Login.Set -> Login Struct -> Driver Connector -> *sql.DB.

// Login represents the structured content of an individual section in a mylogin.cnf file.
// Pointers are used for string fields to distinguish between unset (nil) and empty ("") options.
type Login struct {
	User     *string           `json:"user,omitempty"`     // Database username
	Password *string           `json:"password,omitempty"` // Database password (sensitive)
	Host     *string           `json:"host,omitempty"`     // TCP hostname or IPv4/IPv6 address
	Port     *string           `json:"port,omitempty"`     // TCP port number as string (e.g. "3306")
	Socket   *string           `json:"socket,omitempty"`   // Unix domain socket path (e.g. "/var/run/mysqld/mysqld.sock")
	Extra    map[string]string `json:"extra,omitempty"`    // Arbitrary additional client options (e.g. database, ssl-mode)
}

// cloneStringPtr returns a distinct heap copy of the string pointed to by s.
// If s is nil, it returns nil.
func cloneStringPtr(s *string) *string {
	if s == nil {
		return nil
	}
	cp := *s
	return &cp
}

// Clone returns an independent, deep copy of the Login struct.
// It deep-copies all string pointer fields and the Extra options map to prevent
// memory aliasing and concurrent mutation races between goroutines.
func (l *Login) Clone() *Login {
	if l == nil {
		return nil
	}
	cp := &Login{
		User:     cloneStringPtr(l.User),
		Password: cloneStringPtr(l.Password),
		Host:     cloneStringPtr(l.Host),
		Port:     cloneStringPtr(l.Port),
		Socket:   cloneStringPtr(l.Socket),
	}
	if len(l.Extra) > 0 {
		cp.Extra = make(map[string]string, len(l.Extra))
		for k, v := range l.Extra {
			cp.Extra[k] = v
		}
	}
	return cp
}

// SetUser sets the database username and returns the Login pointer for method chaining.
func (l *Login) SetUser(user string) *Login {
	l.User = &user
	return l
}

// SetPassword sets the database password and returns the Login pointer for method chaining.
func (l *Login) SetPassword(password string) *Login {
	l.Password = &password
	return l
}

// SetHost sets the TCP host address and returns the Login pointer for method chaining.
func (l *Login) SetHost(host string) *Login {
	l.Host = &host
	return l
}

// SetPort sets the TCP port string and returns the Login pointer for method chaining.
func (l *Login) SetPort(port string) *Login {
	l.Port = &port
	return l
}

// SetSocket sets the Unix domain socket path and returns the Login pointer for method chaining.
func (l *Login) SetSocket(socket string) *Login {
	l.Socket = &socket
	return l
}

// SetExtra sets an arbitrary extra client option in the Extra map.
// It initializes the map if currently nil.
func (l *Login) SetExtra(key, value string) *Login {
	if l.Extra == nil {
		l.Extra = make(map[string]string)
	}
	l.Extra[key] = value
	return l
}

// Set sets an option by key name, updating standard typed fields or placing non-standard options in Extra.
// It returns the Login pointer to facilitate fluent configuration chaining.
func (l *Login) Set(key, value string) *Login {
	switch key {
	case "user":
		return l.SetUser(value)
	case "password":
		return l.SetPassword(value)
	case "host":
		return l.SetHost(value)
	case "port":
		return l.SetPort(value)
	case "socket":
		return l.SetSocket(value)
	default:
		return l.SetExtra(key, value)
	}
}

// Map returns a copy of all configured options as a key-value map.
// Only non-nil typed fields are included, alongside all entries from the Extra map.
func (l *Login) Map() map[string]string {
	m := make(map[string]string)
	if l == nil {
		return m
	}
	for _, opt := range []struct {
		k string
		v *string
	}{
		{"user", l.User},
		{"password", l.Password},
		{"host", l.Host},
		{"port", l.Port},
		{"socket", l.Socket},
	} {
		if opt.v != nil {
			m[opt.k] = *opt.v
		}
	}
	for k, v := range l.Extra {
		m[k] = v
	}
	return m
}

// IsEmpty reports true if l is nil or none of the options are set.
func (l *Login) IsEmpty() bool {
	return l == nil ||
		(l.User == nil &&
			l.Password == nil &&
			l.Host == nil &&
			l.Port == nil &&
			l.Socket == nil &&
			len(l.Extra) == 0)
}

// HasCredentials reports whether a user or password is set on the login.
func (l *Login) HasCredentials() bool {
	return l != nil && (l.User != nil || l.Password != nil)
}

// Zero securely wipes sensitive fields (specifically password) from memory.
// It zeroes the byte array backing the password string before pointing to an empty string.
func (l *Login) Zero() {
	if l == nil || l.Password == nil {
		return
	}
	pBytes := []byte(*l.Password)
	for i := range pBytes {
		pBytes[i] = 0
	}
	cleared := ""
	l.Password = &cleared
}

// DSN builds a DSN prefix for github.com/go-sql-driver/mysql.
//
// The DSN returned always ends with '/'.
// For an empty Login, it returns "/".
func (l *Login) DSN() string {
	if l.IsEmpty() {
		return "/"
	}
	cfg := l.Config()
	cfg.DBName = ""
	dsn := cfg.FormatDSN()
	// FormatDSN produces "..." without trailing slash when db is empty; ensure trailing '/'
	if !strings.HasSuffix(dsn, "/") {
		dsn += "/"
	}
	return dsn
}

// FormatDSN generates a complete and driver-compliant DSN using the official mysql driver parser.
// If database is non-empty, it is configured as the active schema.
func (l *Login) FormatDSN(database string) string {
	if l.IsEmpty() {
		if database != "" {
			return "/" + database
		}
		return "/"
	}
	cfg := l.Config()
	if database != "" {
		cfg.DBName = database
	}
	return cfg.FormatDSN()
}

// Config creates and initializes a *mysql.Config struct from the Login options.
// It is nil-safe and returns an empty config if l is nil.
// Handles socket resolution, host/port network targets, and extra option mapping.
func (l *Login) Config() *mysql.Config {
	cfg := mysql.NewConfig()
	if l == nil || l.IsEmpty() {
		return cfg
	}

	if l.User != nil {
		cfg.User = *l.User
	}
	if l.Password != nil {
		cfg.Passwd = *l.Password
	}

	// UNIX domain socket takes precedence over TCP network addresses
	if l.Socket != nil {
		cfg.Net = "unix"
		cfg.Addr = *l.Socket
	} else if l.Host != nil || l.Port != nil {
		cfg.Net = "tcp"
		host := "127.0.0.1"
		port := "3306"
		if l.Host != nil && *l.Host != "" {
			host = *l.Host
		}
		if l.Port != nil && *l.Port != "" {
			port = *l.Port
		}
		cfg.Addr = net.JoinHostPort(host, port)
	}

	// Map extended options from Extra into official driver config fields
	if l.Extra != nil {
		if db, ok := l.Extra["database"]; ok {
			cfg.DBName = db
		}
		if mode, ok := l.Extra["ssl-mode"]; ok {
			switch strings.ToUpper(mode) {
			case "DISABLED":
				cfg.TLSConfig = "false"
			case "REQUIRED":
				cfg.TLSConfig = "skip-verify"
			case "VERIFY_CA", "VERIFY_IDENTITY":
				cfg.TLSConfig = "true"
			default:
				cfg.TLSConfig = mode
			}
		}
		if timeoutStr, ok := l.Extra["connect-timeout"]; ok {
			if sec, err := strconv.Atoi(timeoutStr); err == nil && sec > 0 {
				cfg.Timeout = time.Duration(sec) * time.Second
			}
		}
		if packetStr, ok := l.Extra["max-allowed-packet"]; ok {
			if packet, err := strconv.Atoi(packetStr); err == nil && packet > 0 {
				cfg.MaxAllowedPacket = packet
			}
		}
	}
	return cfg
}

// RedactedDSN returns the connection string with the password masked as "******".
func (l *Login) RedactedDSN() string {
	return l.RedactedFormatDSN("")
}

// RedactedFormatDSN returns the connection string for database with the password masked as "******".
// Suitable for telemetry, debug logs, and metrics dashboards where passwords must not be exposed.
func (l *Login) RedactedFormatDSN(database string) string {
	if l == nil || l.IsEmpty() {
		if database != "" {
			return "/" + database
		}
		return "/"
	}
	cp := l.Clone()
	if cp.Password != nil && *cp.Password != "" {
		masked := "******"
		cp.Password = &masked
	}
	return cp.FormatDSN(database)
}

// String implements fmt.Stringer, returning a redacted DSN to prevent accidental password leaks in logs.
func (l *Login) String() string {
	return l.RedactedDSN()
}

// LogValue implements slog.LogValuer to safely represent credentials in structured logs without leaking passwords.
// It maps the Login into an slog.GroupValue with the password attribute masked as "******".
func (l *Login) LogValue() slog.Value {
	if l == nil || l.IsEmpty() {
		return slog.GroupValue()
	}
	attrs := make([]slog.Attr, 0, 6)
	if l.User != nil {
		attrs = append(attrs, slog.String("user", *l.User))
	}
	if l.Password != nil && *l.Password != "" {
		attrs = append(attrs, slog.String("password", "******"))
	}
	if l.Host != nil {
		attrs = append(attrs, slog.String("host", *l.Host))
	}
	if l.Port != nil {
		attrs = append(attrs, slog.String("port", *l.Port))
	}
	if l.Socket != nil {
		attrs = append(attrs, slog.String("socket", *l.Socket))
	}
	return slog.GroupValue(attrs...)
}

// Connector returns an official database/sql driver.Connector configured with these credentials.
// It completely avoids serializing passwords into cleartext DSN strings, preventing credential disclosure in driver logs.
func (l *Login) Connector(database string) (driver.Connector, error) {
	cfg := l.Config()
	if database != "" {
		cfg.DBName = database
	}
	return mysql.NewConnector(cfg)
}

// Open creates and initializes an active *sql.DB directly using driver.Connector.
// It provides a secure alternative to sql.Open("mysql", dsn) by preventing password leaks in DSN strings.
func (l *Login) Open(database string) (*sql.DB, error) {
	connector, err := l.Connector(database)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(connector), nil
}

// unescape handles legacy MySQL escape sequences in unquoted option values.
var unescape = strings.NewReplacer(
	`\b`, "\b",
	`\t`, "\t",
	`\n`, "\n",
	`\r`, "\r",
	`\\`, `\`,
	`\s`, ` `,
).Replace

// unquote unescapes quotes and backslashes in double-quoted option values (MySQL 8.0.24+).
var unquote = strings.NewReplacer(
	`\"`, `"`,
	`\\`, `\`,
).Replace

// parseLine parses a single "key = value" or "key=value" INI line and assigns it to the Login struct.
func (l *Login) parseLine(line string) error {
	s := strings.SplitN(line, "=", 2)
	if len(s) != 2 {
		return fmt.Errorf("invalid line format (missing '='): %q", line)
	}

	key := strings.TrimSpace(s[0])
	v := strings.TrimSpace(s[1])

	// mysql_config_editor quotes strings since MySQL 8.0.24
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = unquote(v[1 : len(v)-1])
	} else {
		v = unescape(strings.ReplaceAll(v, `\\`, `\`))
	}

	l.Set(key, v)
	return nil
}

// Merge merges other into l: options set in other take precedence over options in l.
// String pointers are deep-copied to prevent pointer aliasing between the merged structures.
func (l *Login) Merge(other *Login) {
	if other == nil {
		return
	}
	if other.User != nil {
		l.User = cloneStringPtr(other.User)
	}
	if other.Password != nil {
		l.Password = cloneStringPtr(other.Password)
	}
	if other.Host != nil {
		l.Host = cloneStringPtr(other.Host)
	}
	if other.Port != nil {
		l.Port = cloneStringPtr(other.Port)
	}
	if other.Socket != nil {
		l.Socket = cloneStringPtr(other.Socket)
	}
	if len(other.Extra) > 0 {
		if l.Extra == nil {
			l.Extra = make(map[string]string, len(other.Extra))
		}
		for k, v := range other.Extra {
			l.Extra[k] = v
		}
	}
}
