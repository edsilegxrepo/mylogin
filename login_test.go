// Package mylogin provides unit tests for internal option line parsing.
//
// Objective: Validate lexical parsing, quote stripping, and escape sequence handling
// for individual INI option lines within Login.parseLine.
//
// Core Components:
//   - TestParseLine: Table-driven validation covering bare strings, whitespace, double quotes,
//     embedded equality signs, and escaped quotes.
//
// Test Strategy:
//   - Table-Driven Testing: Iterate across a matrix of syntactically diverse line formats.
//   - Escaping Invariant: Ensure escaped double-quotes (\") are correctly converted to literal quotes (")
//     and surrounding container quotes are stripped.
//
// Functionality:
//   - Guarantees option values are accurately tokenized regardless of formatting variations.
//
// Data Flow:
//
//	Raw INI Line -> Login.parseLine -> Option Extraction & Sanitization -> Assert Field Value.
package mylogin

import (
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	for _, test := range []struct {
		line string
		user string
	}{
		{`user = toto`, `toto`},
		{`user = toto titi`, `toto titi`},
		{`user = "toto"`, `toto`},
		{`user = "toto titi"`, `toto titi`},
		{`user = "toto = titi"`, `toto = titi`},
		{`user = "toto \" titi"`, `toto " titi`},
	} {
		var l Login
		err := l.parseLine(test.line)
		if err != nil {
			t.Errorf("%q: %v", test.line, err)
			continue
		}
		if *l.User != test.user {
			t.Errorf("%q: got %q, expected %q", test.line, *l.User, test.user)
		}
	}
}

func TestConfigProtocolAndSocketHijackingPrevention(t *testing.T) {
	// Scenario 1: Base options from /etc/my.cnf set socket, but section defines remote TCP host.
	// TCP must be selected to avoid socket hijacking.
	base := new(Login).SetSocket("/var/run/mysqld/mysqld.sock")
	remoteSection := new(Login).SetHost("db.example.com").SetPort("3307")
	merged := base.Clone()
	merged.Merge(remoteSection)

	cfg := merged.Config()
	if cfg.Net != "tcp" {
		t.Errorf("expected Net=tcp for remote host with base socket, got %q", cfg.Net)
	}
	if cfg.Addr != "db.example.com:3307" {
		t.Errorf("expected Addr=db.example.com:3307, got %q", cfg.Addr)
	}

	// Scenario 2: Host is localhost and socket is specified -> Unix socket is used.
	localLogin := new(Login).SetHost("localhost").SetSocket("/var/run/mysqld/mysqld.sock")
	localCfg := localLogin.Config()
	if localCfg.Net != "unix" {
		t.Errorf("expected Net=unix for localhost with socket, got %q", localCfg.Net)
	}
	if localCfg.Addr != "/var/run/mysqld/mysqld.sock" {
		t.Errorf("expected Addr=/var/run/mysqld/mysqld.sock, got %q", localCfg.Addr)
	}

	// Scenario 3: protocol=tcp explicitly overrides localhost socket.
	tcpEnforced := new(Login).SetHost("localhost").SetSocket("/var/run/mysqld/mysqld.sock").Set("protocol", "tcp")
	tcpCfg := tcpEnforced.Config()
	if tcpCfg.Net != "tcp" {
		t.Errorf("expected Net=tcp when protocol=tcp, got %q", tcpCfg.Net)
	}

	// Scenario 4: protocol=socket explicitly overrides TCP host.
	socketEnforced := new(Login).SetHost("192.168.1.100").SetSocket("/tmp/mysql.sock").Set("protocol", "socket")
	sockCfg := socketEnforced.Config()
	if sockCfg.Net != "unix" {
		t.Errorf("expected Net=unix when protocol=socket, got %q", sockCfg.Net)
	}
	if sockCfg.Addr != "/tmp/mysql.sock" {
		t.Errorf("expected Addr=/tmp/mysql.sock, got %q", sockCfg.Addr)
	}
}

func TestConfigExpandedProperties(t *testing.T) {
	login := new(Login).
		Set("connect-timeout", "10").
		Set("read-timeout", "20").
		Set("write-timeout", "30").
		Set("default-character-set", "utf8mb4").
		Set("init-command", "SET NAMES utf8mb4").
		Set("sql-mode", "STRICT_ALL_TABLES").
		Set("local-infile", "true").
		Set("parse-time", "1").
		Set("multi-statements", "yes").
		Set("interpolate-params", "true").
		Set("loc", "UTC")

	cfg := login.Config()

	if cfg.Timeout != 10*time.Second {
		t.Errorf("expected Timeout=10s, got %v", cfg.Timeout)
	}
	if cfg.ReadTimeout != 20*time.Second {
		t.Errorf("expected ReadTimeout=20s, got %v", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 30*time.Second {
		t.Errorf("expected WriteTimeout=30s, got %v", cfg.WriteTimeout)
	}
	if cfg.Collation != "utf8mb4_general_ci" {
		t.Errorf("expected Collation=utf8mb4_general_ci, got %q", cfg.Collation)
	}
	if cfg.Params["charset"] != "utf8mb4" {
		t.Errorf("expected Params[charset]=utf8mb4, got %q", cfg.Params["charset"])
	}
	if cfg.Params["init_command"] != "SET NAMES utf8mb4" {
		t.Errorf("expected Params[init_command]=SET NAMES utf8mb4, got %q", cfg.Params["init_command"])
	}
	if cfg.Params["sql_mode"] != "STRICT_ALL_TABLES" {
		t.Errorf("expected Params[sql_mode]=STRICT_ALL_TABLES, got %q", cfg.Params["sql_mode"])
	}
	if !cfg.AllowAllFiles {
		t.Errorf("expected AllowAllFiles=true for local-infile")
	}
	if !cfg.ParseTime {
		t.Errorf("expected ParseTime=true")
	}
	if !cfg.MultiStatements {
		t.Errorf("expected MultiStatements=true")
	}
	if !cfg.InterpolateParams {
		t.Errorf("expected InterpolateParams=true")
	}
	if cfg.Loc == nil || cfg.Loc.String() != "UTC" {
		t.Errorf("expected Loc=UTC, got %v", cfg.Loc)
	}
}

func TestConfigExpandedProperties_FullMatrix(t *testing.T) {
	// 1. Test character set and collation matrix
	for _, tc := range []struct {
		charset     string
		expectedCol string
	}{
		{"utf8", "utf8_general_ci"},
		{"utf8mb3", "utf8_general_ci"},
		{"latin1", "latin1_swedish_ci"},
		{"ascii", "ascii_general_ci"},
		{"binary", "binary"},
		{"unknowncharset", ""},
	} {
		login := new(Login).Set("charset", tc.charset)
		cfg := login.Config()
		if cfg.Collation != tc.expectedCol {
			t.Errorf("charset %q: expected Collation=%q, got %q", tc.charset, tc.expectedCol, cfg.Collation)
		}
		if cfg.Params["charset"] != tc.charset {
			t.Errorf("charset %q: expected Params[charset]=%q, got %q", tc.charset, tc.charset, cfg.Params["charset"])
		}
	}

	// 1b. Test charset value containing underscore is treated as full collation
	loginUnder := new(Login).Set("charset", "utf8mb4_bin")
	cfgUnder := loginUnder.Config()
	if cfgUnder.Collation != "utf8mb4_bin" {
		t.Errorf("expected Collation=utf8mb4_bin, got %q", cfgUnder.Collation)
	}

	// 2. Collation priority: explicit collation must not be overridden by charset
	loginCol := new(Login).
		Set("collation", "utf8mb4_unicode_ci").
		Set("charset", "utf8mb4")
	cfgCol := loginCol.Config()
	if cfgCol.Collation != "utf8mb4_unicode_ci" {
		t.Errorf("expected explicit collation utf8mb4_unicode_ci preserved, got %q", cfgCol.Collation)
	}

	// 3. Time zone without loc: should populate Params[time_zone] and set cfg.Loc
	loginTZ := new(Login).Set("time-zone", "UTC")
	cfgTZ := loginTZ.Config()
	if cfgTZ.Params["time_zone"] != "UTC" {
		t.Errorf("expected Params[time_zone]=UTC, got %q", cfgTZ.Params["time_zone"])
	}
	if cfgTZ.Loc == nil || cfgTZ.Loc.String() != "UTC" {
		t.Errorf("expected Loc=UTC from time-zone, got %v", cfgTZ.Loc)
	}

	// 4. Remaining driver boolean flags and alternate aliases
	loginFlags := new(Login).
		Set("allow-cleartext-passwords", "1").
		Set("allow-native-passwords", "yes").
		Set("check-conn-liveness", "true").
		Set("client-found-rows", "on").
		Set("columns-with-alias", "1").
		Set("reject-read-only", "true")

	cfgFlags := loginFlags.Config()
	if !cfgFlags.AllowCleartextPasswords {
		t.Error("expected AllowCleartextPasswords=true")
	}
	if !cfgFlags.AllowNativePasswords {
		t.Error("expected AllowNativePasswords=true")
	}
	if !cfgFlags.CheckConnLiveness {
		t.Error("expected CheckConnLiveness=true")
	}
	if !cfgFlags.ClientFoundRows {
		t.Error("expected ClientFoundRows=true")
	}
	if !cfgFlags.ColumnsWithAlias {
		t.Error("expected ColumnsWithAlias=true")
	}
	if !cfgFlags.RejectReadOnly {
		t.Error("expected RejectReadOnly=true")
	}

	// 5. Invalid numeric options should be handled gracefully without crashing
	loginInvalid := new(Login).
		Set("connect-timeout", "invalid").
		Set("read-timeout", "-10").
		Set("write-timeout", "not_a_number").
		Set("max-allowed-packet", "-5")
	cfgInvalid := loginInvalid.Config()
	if cfgInvalid.Timeout != 0 || cfgInvalid.ReadTimeout != 0 || cfgInvalid.WriteTimeout != 0 {
		t.Errorf("expected zero values for invalid timeouts, got %+v", cfgInvalid)
	}
}

func TestNormalizeOptionKey_LoosePrefix(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"loose-connect-timeout", "connect-timeout"},
		{"loose_default_character_set", "default-character-set"},
		{"LOOSE-PORT", "port"},
		{"loose_user", "user"},
		{"loose-host", "host"},
		{"loose-password", "password"},
		{"loose_socket", "socket"},
		{"loose-local-infile", "local-infile"},
		{"loose", "loose"},
		{"loose-", ""},
		{"standard_option", "standard-option"},
	}

	for _, tc := range cases {
		got := normalizeOptionKey(tc.input)
		if got != tc.expected {
			t.Errorf("normalizeOptionKey(%q) = %q; expected %q", tc.input, got, tc.expected)
		}
	}

	// Verify l.Set with loose- prefixes sets typed fields and extra correctly
	login := new(Login)
	login.Set("loose-user", "loose_user")
	login.Set("loose-password", "loose_pass")
	login.Set("loose-host", "db.example.internal")
	login.Set("loose-port", "3307")
	login.Set("loose-socket", "/tmp/mysql.sock")
	login.Set("loose-connect-timeout", "15")

	if login.User == nil || *login.User != "loose_user" {
		t.Errorf("expected User 'loose_user', got %v", login.User)
	}
	if login.Password == nil || *login.Password != "loose_pass" {
		t.Errorf("expected Password 'loose_pass', got %v", login.Password)
	}
	if login.Host == nil || *login.Host != "db.example.internal" {
		t.Errorf("expected Host 'db.example.internal', got %v", login.Host)
	}
	if login.Port == nil || *login.Port != "3307" {
		t.Errorf("expected Port '3307', got %v", login.Port)
	}
	if login.Socket == nil || *login.Socket != "/tmp/mysql.sock" {
		t.Errorf("expected Socket '/tmp/mysql.sock', got %v", login.Socket)
	}
	if login.Extra["connect-timeout"] != "15" {
		t.Errorf("expected Extra[connect-timeout]='15', got %q", login.Extra["connect-timeout"])
	}
}

func TestLocalInfile_BareAndNegations(t *testing.T) {
	// 1. Bare local-infile flag
	l1 := new(Login)
	if err := l1.parseLine("local-infile"); err != nil {
		t.Fatalf("unexpected error parsing bare local-infile: %v", err)
	}
	if !l1.Config().AllowAllFiles {
		t.Error("expected AllowAllFiles=true for bare local-infile")
	}

	// 2. Bare loose-local-infile flag
	l2 := new(Login)
	if err := l2.parseLine("loose-local-infile"); err != nil {
		t.Fatalf("unexpected error parsing bare loose-local-infile: %v", err)
	}
	if !l2.Config().AllowAllFiles {
		t.Error("expected AllowAllFiles=true for bare loose-local-infile")
	}

	// 3. Negation bare flags: skip-local-infile, disable-local-infile, no-local-infile
	for _, neg := range []string{"skip-local-infile", "disable-local-infile", "no-local-infile"} {
		l := new(Login)
		l.Set("local-infile", "true")
		if err := l.parseLine(neg); err != nil {
			t.Fatalf("unexpected error parsing %s: %v", neg, err)
		}
		if l.Config().AllowAllFiles {
			t.Errorf("expected AllowAllFiles=false after %s", neg)
		}
	}

	// 4. local-infile = 0 explicitly disables
	l4 := new(Login)
	if err := l4.parseLine("local-infile = 0"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l4.Config().AllowAllFiles {
		t.Error("expected AllowAllFiles=false for local-infile=0")
	}

	// 5. Merge override: base has local-infile, override has skip-local-infile
	base := new(Login)
	base.Set("local-infile", "true")
	override := new(Login)
	_ = override.parseLine("skip-local-infile")
	base.Merge(override)
	if base.Config().AllowAllFiles {
		t.Error("expected AllowAllFiles=false after merging skip-local-infile override")
	}
}

func TestSkipSSL_OptionFiles(t *testing.T) {
	// 1. Bare skip-ssl
	l1 := new(Login)
	if err := l1.parseLine("skip-ssl"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l1.Config().TLSConfig != "false" {
		t.Errorf("expected TLSConfig='false' for bare skip-ssl, got %q", l1.Config().TLSConfig)
	}

	// 2. ssl = 0
	l2 := new(Login)
	if err := l2.parseLine("ssl = 0"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l2.Config().TLSConfig != "false" {
		t.Errorf("expected TLSConfig='false' for ssl = 0, got %q", l2.Config().TLSConfig)
	}

	// 3. ssl = false
	l3 := new(Login)
	if err := l3.parseLine("ssl = false"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l3.Config().TLSConfig != "false" {
		t.Errorf("expected TLSConfig='false' for ssl = false, got %q", l3.Config().TLSConfig)
	}
}
