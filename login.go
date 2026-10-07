package mylogin

import (
	"fmt"
	"net"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// Login is the structured content of a section in mylogin.cnf.
type Login struct {
	User     *string           `json:"user,omitempty"`
	Password *string           `json:"password,omitempty"`
	Host     *string           `json:"host,omitempty"`   // TCP hostname
	Port     *string           `json:"port,omitempty"`   // TCP port
	Socket   *string           `json:"socket,omitempty"` // Unix socket path
	Extra    map[string]string `json:"extra,omitempty"`  // Additional client options (e.g. database, default-auth)
}

func cloneStringPtr(s *string) *string {
	if s == nil {
		return nil
	}
	cp := *s
	return &cp
}

// Clone returns a deep copy of the Login struct.
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

// SetUser sets the user field.
func (l *Login) SetUser(user string) *Login {
	l.User = &user
	return l
}

// SetPassword sets the password field.
func (l *Login) SetPassword(password string) *Login {
	l.Password = &password
	return l
}

// SetHost sets the TCP host field.
func (l *Login) SetHost(host string) *Login {
	l.Host = &host
	return l
}

// SetPort sets the TCP port field.
func (l *Login) SetPort(port string) *Login {
	l.Port = &port
	return l
}

// SetSocket sets the Unix socket path.
func (l *Login) SetSocket(socket string) *Login {
	l.Socket = &socket
	return l
}

// SetExtra sets an arbitrary extra client option.
func (l *Login) SetExtra(key, value string) *Login {
	if l.Extra == nil {
		l.Extra = make(map[string]string)
	}
	l.Extra[key] = value
	return l
}

// IsEmpty is true if l is nil or none of the options are set.
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
	if l.Extra != nil {
		if db, ok := l.Extra["database"]; ok {
			cfg.DBName = db
		}
	}
	return cfg
}

// String returns DSN().
func (l *Login) String() string {
	return l.DSN()
}

var unescape = strings.NewReplacer(
	`\b`, "\b",
	`\t`, "\t",
	`\n`, "\n",
	`\r`, "\r",
	`\\`, `\`,
	`\s`, ` `,
).Replace

var unquote = strings.NewReplacer(
	`\"`, `"`,
	`\\`, `\`,
).Replace

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

	switch key {
	case "user":
		l.User = &v
	case "password":
		l.Password = &v
	case "host":
		l.Host = &v
	case "port":
		l.Port = &v
	case "socket":
		l.Socket = &v
	default:
		if l.Extra == nil {
			l.Extra = make(map[string]string)
		}
		l.Extra[key] = v
	}
	return nil
}

// Merge merges other into l: options set in other take precedence over options in l.
// String pointers are deep-copied to prevent pointer aliasing.
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
