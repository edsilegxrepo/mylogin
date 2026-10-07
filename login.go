package mylogin

import (
	"bytes"
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

// DSN builds a DSN prefix for github.com/go-sql-driver/mysql.
//
// The DSN returned always ends with '/'.
// For an empty Login, it returns "/".
func (l *Login) DSN() string {
	if l.IsEmpty() {
		return "/"
	}

	var b bytes.Buffer
	if l.User != nil {
		b.WriteString(*l.User)
		if l.Password != nil {
			b.WriteByte(':')
			b.WriteString(*l.Password)
		}
		b.WriteByte('@')
	}
	if l.Socket != nil {
		b.WriteString("unix(")
		b.WriteString(*l.Socket)
		b.WriteByte(')')
	} else if l.Host != nil || l.Port != nil {
		var host, port string
		if l.Host != nil {
			host = *l.Host
		}
		if l.Port != nil {
			port = *l.Port
		} else {
			port = "3306" // MySQL default port
		}
		b.WriteString("tcp(")
		b.WriteString(net.JoinHostPort(host, port))
		b.WriteByte(')')
	}

	// The separator with the database name
	b.WriteByte('/')

	return b.String()
}

// Config creates and initializes a *mysql.Config struct from the Login options.
func (l *Login) Config() *mysql.Config {
	cfg := mysql.NewConfig()
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
		if l.Host != nil {
			host = *l.Host
		}
		if l.Port != nil {
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
		v = strings.ReplaceAll(v, `\\`, `\`)
	}
	v = unescape(v)

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
