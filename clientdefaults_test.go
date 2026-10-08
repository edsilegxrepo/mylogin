// Objective: Validate discovery, parsing, and precedence-based cascading of MySQL plaintext
// option files (e.g., ~/.my.cnf, %APPDATA%\MySQL\.my.cnf) alongside encrypted .mylogin.cnf sections.
//
// Core Components Tested:
//   - DefaultOptionFile, DefaultClientDefaults, ReadClientDefaults, ReadResolvedLogin, Default, Get.
//
// Test Strategy:
//   - Isolation: Use t.TempDir() for all synthesized option and login configuration files to prevent side effects.
//   - Environment Manipulation: Safely override and restore MYSQL_TEST_OPTION_FILE and MYSQL_TEST_LOGIN_FILE.
//   - Boundary & Edge Cases: Test missing files (graceful degradation), malformed syntax, missing sections, and multi-tier override hierarchies.
//   - Precedence Verification: Assert the 3-tier cascade: .my.cnf [client] -> .mylogin.cnf [client] -> .mylogin.cnf [section].
//   - Top-Level Integration: Validate that high-level API methods (Default, Get) transparently resolve cascading client defaults.
//
// Functionality:
//   - Asserts missing option files return empty Login structs with nil errors.
//   - Asserts environment variable overrides take precedence over platform default paths.
//   - Asserts 3-tier cascade precedence correctly merges values and propagates parse errors.
//
// Data Flow:
//
//	Synthesized INI (.my.cnf) + Encrypted .mylogin.cnf -> ReadResolvedLogin() -> Assertions
package mylogin_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edsilegxrepo/mylogin"
)

// TestReadClientDefaultsMissingFileIgnored verifies that a non-existent option file
// degrades gracefully by returning an empty Login struct with nil error.
func TestReadClientDefaultsMissingFileIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.cnf")
	login, err := mylogin.ReadClientDefaults(path)
	if err != nil {
		t.Fatalf("ReadClientDefaults returned error: %v", err)
	}
	if login == nil || !login.IsEmpty() {
		t.Fatalf("expected empty login for missing file, got %+v", login)
	}
}

// TestReadClientDefaultsEmptyPath asserts that an empty path returns an empty Login
// with nil error rather than attempting to open the current working directory.
func TestReadClientDefaultsEmptyPath(t *testing.T) {
	login, err := mylogin.ReadClientDefaults("")
	if err != nil {
		t.Fatalf("ReadClientDefaults(\"\") returned error: %v", err)
	}
	if login == nil || !login.IsEmpty() {
		t.Fatalf("expected empty login for empty path, got %+v", login)
	}
}

// TestDefaultOptionFileEnvVar asserts that the MYSQL_TEST_OPTION_FILE environment variable
// overrides standard platform paths, and unsetting it falls back to canonical system paths.
func TestDefaultOptionFileEnvVar(t *testing.T) {
	orig := os.Getenv("MYSQL_TEST_OPTION_FILE")
	defer func() { _ = os.Setenv("MYSQL_TEST_OPTION_FILE", orig) }()

	customPath := filepath.Join(t.TempDir(), "custom_option.cnf")
	_ = os.Setenv("MYSQL_TEST_OPTION_FILE", customPath)
	if got := mylogin.DefaultOptionFile(); got != customPath {
		t.Errorf("expected %q, got %q", customPath, got)
	}

	_ = os.Unsetenv("MYSQL_TEST_OPTION_FILE")
	if got := mylogin.DefaultOptionFile(); got == "" {
		t.Errorf("expected platform default option file, got empty string")
	}
}

// TestDefaultClientDefaults validates reading the [client] group from an option file
// configured via the default option file path.
func TestDefaultClientDefaults(t *testing.T) {
	orig := os.Getenv("MYSQL_TEST_OPTION_FILE")
	defer func() { _ = os.Setenv("MYSQL_TEST_OPTION_FILE", orig) }()

	tmpDir := t.TempDir()
	optionFile := filepath.Join(tmpDir, ".my.cnf")
	plain := "[client]\nhost = \"global.mysql.corp\"\nuser = \"app_user\"\n"
	if err := os.WriteFile(optionFile, []byte(plain), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_ = os.Setenv("MYSQL_TEST_OPTION_FILE", optionFile)

	login, err := mylogin.DefaultClientDefaults()
	if err != nil {
		t.Fatalf("DefaultClientDefaults failed: %v", err)
	}
	if login.Host == nil || *login.Host != "global.mysql.corp" {
		t.Errorf("expected host global.mysql.corp, got %+v", login.Host)
	}
	if login.User == nil || *login.User != "app_user" {
		t.Errorf("expected user app_user, got %+v", login.User)
	}
}

// TestReadClientDefaultsEdgeCases tests syntax error rejection and handling of option files
// that lack a [client] group entirely.
func TestReadClientDefaultsEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Malformed syntax (missing delimiter)
	badFile := filepath.Join(tmpDir, "bad.cnf")
	if err := os.WriteFile(badFile, []byte("[client]\ninvalid line without equals\n"), 0o600); err != nil {
		t.Fatalf("WriteFile bad.cnf: %v", err)
	}
	if _, err := mylogin.ReadClientDefaults(badFile); err == nil {
		t.Error("expected error parsing malformed option file")
	}

	// 2. File without [client] section
	noClientFile := filepath.Join(tmpDir, "no_client.cnf")
	if err := os.WriteFile(noClientFile, []byte("[mysqld]\nport = 3306\n"), 0o600); err != nil {
		t.Fatalf("WriteFile no_client.cnf: %v", err)
	}
	login, err := mylogin.ReadClientDefaults(noClientFile)
	if err != nil {
		t.Fatalf("ReadClientDefaults failed: %v", err)
	}
	if login == nil || !login.IsEmpty() {
		t.Errorf("expected empty login when [client] is absent, got %+v", login)
	}
}

// TestReadResolvedLoginPrecedence asserts correct resolution across the 3-tier cascade:
// plaintext .my.cnf [client] -> encrypted .mylogin.cnf [client] -> encrypted .mylogin.cnf [section].
func TestReadResolvedLoginPrecedence(t *testing.T) {
	tmpDir := t.TempDir()
	optionFile := filepath.Join(tmpDir, ".my.cnf")
	loginFile := filepath.Join(tmpDir, ".mylogin.cnf")

	// Plaintext option file provides host and TLS settings
	plain := "[client]\nhost = \"tls.host\"\nssl-mode = \"VERIFY_CA\"\nssl-ca = \"/etc/pki/ca.pem\"\n"
	if err := os.WriteFile(optionFile, []byte(plain), 0o644); err != nil {
		t.Fatalf("WriteFile optionFile: %v", err)
	}

	// Encrypted file has [client] overriding host and [reporting] setting user/password
	sections := mylogin.Sections{
		{Name: "client", Login: *new(mylogin.Login).SetHost("encrypted-client-host")},
		{Name: "reporting", Login: *new(mylogin.Login).SetUser("report_user").SetPassword("secret")},
	}
	formatted, err := sections.Format()
	if err != nil {
		t.Fatalf("sections.Format: %v", err)
	}
	if err := mylogin.WriteFile(loginFile, strings.NewReader(formatted)); err != nil {
		t.Fatalf("WriteFile loginFile: %v", err)
	}

	resolved, err := mylogin.ReadResolvedLogin(loginFile, optionFile, []string{"client", "reporting"})
	if err != nil {
		t.Fatalf("ReadResolvedLogin: %v", err)
	}
	if resolved.Host == nil || *resolved.Host != "encrypted-client-host" {
		t.Fatalf("expected encrypted client host to override plaintext host, got %+v", resolved.Host)
	}
	if resolved.User == nil || *resolved.User != "report_user" {
		t.Fatalf("expected reporting user to be set, got %+v", resolved.User)
	}
	if resolved.Extra["ssl-mode"] != "VERIFY_CA" {
		t.Fatalf("expected ssl-mode from plaintext client defaults, got %q", resolved.Extra["ssl-mode"])
	}
	if resolved.Extra["ssl-ca"] != "/etc/pki/ca.pem" {
		t.Fatalf("expected ssl-ca from plaintext client defaults, got %q", resolved.Extra["ssl-ca"])
	}
}

// TestReadResolvedLoginErrors tests error propagation when either the option file or
// the encrypted mylogin file cannot be parsed or read.
func TestReadResolvedLoginErrors(t *testing.T) {
	tmpDir := t.TempDir()
	loginFile := filepath.Join(tmpDir, ".mylogin.cnf")
	_ = mylogin.WriteFile(loginFile, strings.NewReader("[client]\nhost=ok\n"))

	badOptionFile := filepath.Join(tmpDir, "bad.cnf")
	_ = os.WriteFile(badOptionFile, []byte("[client]\nmalformed line\n"), 0o600)

	// 1. Error in option file
	if _, err := mylogin.ReadResolvedLogin(loginFile, badOptionFile, []string{"client"}); err == nil {
		t.Error("expected error when option file is malformed")
	}

	// 2. Error in mylogin file
	goodOptionFile := filepath.Join(tmpDir, "good.cnf")
	_ = os.WriteFile(goodOptionFile, []byte("[client]\nhost=localhost\n"), 0o600)
	if _, err := mylogin.ReadResolvedLogin(filepath.Join(tmpDir, "nonexistent.cnf"), goodOptionFile, []string{"client"}); err == nil {
		t.Error("expected error when mylogin file does not exist")
	}
}

// TestTopLevelDefaultAndGetWithOptionFile asserts that the top-level API functions
// Default() and Get() automatically resolve and merge client defaults from option files.
func TestTopLevelDefaultAndGetWithOptionFile(t *testing.T) {
	origOpt := os.Getenv("MYSQL_TEST_OPTION_FILE")
	origLogin := os.Getenv("MYSQL_TEST_LOGIN_FILE")
	defer func() {
		_ = os.Setenv("MYSQL_TEST_OPTION_FILE", origOpt)
		_ = os.Setenv("MYSQL_TEST_LOGIN_FILE", origLogin)
	}()

	tmpDir := t.TempDir()
	optionFile := filepath.Join(tmpDir, ".my.cnf")
	loginFile := filepath.Join(tmpDir, ".mylogin.cnf")

	_ = os.Setenv("MYSQL_TEST_OPTION_FILE", optionFile)
	_ = os.Setenv("MYSQL_TEST_LOGIN_FILE", loginFile)

	_ = os.WriteFile(optionFile, []byte("[client]\nport = 3307\nssl-mode = \"REQUIRED\"\n"), 0o600)
	secs := mylogin.Sections{
		{Name: "client", Login: *new(mylogin.Login).SetHost("cluster.local")},
		{Name: "app", Login: *new(mylogin.Login).SetUser("webapp")},
	}
	formatted, _ := secs.Format()
	_ = mylogin.WriteFile(loginFile, strings.NewReader(formatted))

	// Test mylogin.Default()
	def, err := mylogin.Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}
	if def.Host == nil || *def.Host != "cluster.local" {
		t.Errorf("expected host cluster.local, got %+v", def.Host)
	}
	if def.Port == nil || *def.Port != "3307" {
		t.Errorf("expected port 3307 from option file, got %+v", def.Port)
	}
	if def.Extra["ssl-mode"] != "REQUIRED" {
		t.Errorf("expected ssl-mode REQUIRED from option file, got %q", def.Extra["ssl-mode"])
	}

	// Test mylogin.Get("app")
	app, err := mylogin.Get("app")
	if err != nil {
		t.Fatalf("Get('app') failed: %v", err)
	}
	if app.User == nil || *app.User != "webapp" {
		t.Errorf("expected user webapp, got %+v", app.User)
	}
	if app.Host == nil || *app.Host != "cluster.local" {
		t.Errorf("expected host cluster.local from client, got %+v", app.Host)
	}
	if app.Port == nil || *app.Port != "3307" {
		t.Errorf("expected port 3307 from option file, got %+v", app.Port)
	}
}
