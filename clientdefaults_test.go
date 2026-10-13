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

// TestParseOptionDirectivesAndBareFlags verifies that Parse and ReadClientDefaults gracefully
// tolerate !include directives, parse bare boolean flags, unquote single quotes, strip inline comments,
// and canonicalize keys across hyphens and underscores.
func TestParseOptionDirectivesAndBareFlags(t *testing.T) {
	rawINI := `
!include /etc/mysql/conf.d/extra.cnf
!includedir /etc/my.cnf.d

[client]
user = 'single_quoted_user' # inline comment with hash
password = "double_quoted_password" ; inline comment with semicolon
host = 127.0.0.1
port = 3306
compress
quick
connect_timeout = 15
default_character_set = utf8mb4
`
	tmpDir := t.TempDir()
	optFile := filepath.Join(tmpDir, "tolerant.cnf")
	if err := os.WriteFile(optFile, []byte(rawINI), 0o600); err != nil {
		t.Fatalf("failed to write option file: %v", err)
	}

	login, err := mylogin.ReadClientDefaults(optFile)
	if err != nil {
		t.Fatalf("ReadClientDefaults failed on resilient INI: %v", err)
	}

	if login.User == nil || *login.User != "single_quoted_user" {
		t.Errorf("expected user single_quoted_user, got %+v", login.User)
	}
	if login.Password == nil || *login.Password != "double_quoted_password" {
		t.Errorf("expected password double_quoted_password, got %+v", login.Password)
	}
	if login.Host == nil || *login.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %+v", login.Host)
	}
	if login.Port == nil || *login.Port != "3306" {
		t.Errorf("expected port 3306, got %+v", login.Port)
	}
	if login.Extra["compress"] != "true" {
		t.Errorf("expected compress=true, got %q", login.Extra["compress"])
	}
	if login.Extra["quick"] != "true" {
		t.Errorf("expected quick=true, got %q", login.Extra["quick"])
	}
	if login.Extra["connect-timeout"] != "15" {
		t.Errorf("expected canonical connect-timeout=15, got %q", login.Extra["connect-timeout"])
	}
	if login.Extra["default-character-set"] != "utf8mb4" {
		t.Errorf("expected canonical default-character-set=utf8mb4, got %q", login.Extra["default-character-set"])
	}
}

// Test4TierCascadePrecedence verifies that the multi-tier cascade correctly merges:
// Tier 1 (Global option file) -> Tier 2 (User option file) -> Tier 3 (.mylogin.cnf [client]) -> Tier 4 (.mylogin.cnf [section])
func Test4TierCascadePrecedence(t *testing.T) {
	tmpDir := t.TempDir()
	globalFile := filepath.Join(tmpDir, "my-client.cnf")
	userFile := filepath.Join(tmpDir, ".my.cnf")
	loginFile := filepath.Join(tmpDir, ".mylogin.cnf")

	// Tier 1: Global file defines port=3306, read-timeout=10, default-character-set=utf8mb4
	globalINI := "[client]\nport = 3306\nread-timeout = 10\ndefault-character-set = utf8mb4\n"
	if err := os.WriteFile(globalFile, []byte(globalINI), 0o600); err != nil {
		t.Fatalf("write global file: %v", err)
	}

	// Tier 2: User file overrides port=3307, sets write-timeout=20
	userINI := "[client]\nport = 3307\nwrite-timeout = 20\n"
	if err := os.WriteFile(userFile, []byte(userINI), 0o600); err != nil {
		t.Fatalf("write user file: %v", err)
	}

	// Tier 3 & 4: Encrypted login file
	secs := mylogin.Sections{
		{
			Name:  "client",
			Login: *new(mylogin.Login).SetUser("client_user").SetHost("cluster.local"),
		},
		{
			Name:  "production",
			Login: *new(mylogin.Login).SetUser("prod_user").SetHost("prod.internal"),
		},
	}
	formatted, err := secs.Format()
	if err != nil {
		t.Fatalf("format sections: %v", err)
	}
	if err := mylogin.WriteFile(loginFile, strings.NewReader(formatted)); err != nil {
		t.Fatalf("write encrypted login: %v", err)
	}

	resolved, err := mylogin.ReadResolvedLoginHierarchy(loginFile, []string{globalFile, userFile}, []string{"client", "production"})
	if err != nil {
		t.Fatalf("ReadResolvedLoginHierarchy: %v", err)
	}

	// Host should be overridden by Tier 4 [production]
	if resolved.Host == nil || *resolved.Host != "prod.internal" {
		t.Errorf("expected host prod.internal, got %+v", resolved.Host)
	}
	// User should be overridden by Tier 4 [production]
	if resolved.User == nil || *resolved.User != "prod_user" {
		t.Errorf("expected user prod_user, got %+v", resolved.User)
	}
	// Port should be overridden by Tier 2 [userFile] (3307 overriding Tier 1 3306)
	if resolved.Port == nil || *resolved.Port != "3307" {
		t.Errorf("expected port 3307, got %+v", resolved.Port)
	}
	// read-timeout should come from Tier 1 [globalFile]
	if resolved.Extra["read-timeout"] != "10" {
		t.Errorf("expected read-timeout 10, got %q", resolved.Extra["read-timeout"])
	}
	// write-timeout should come from Tier 2 [userFile]
	if resolved.Extra["write-timeout"] != "20" {
		t.Errorf("expected write-timeout 20, got %q", resolved.Extra["write-timeout"])
	}
	// default-character-set should come from Tier 1 [globalFile]
	if resolved.Extra["default-character-set"] != "utf8mb4" {
		t.Errorf("expected default-character-set utf8mb4, got %q", resolved.Extra["default-character-set"])
	}
}

func TestGlobalOptionFiles_EnvOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	customGlobal := filepath.Join(tmpDir, "custom-global.cnf")
	if err := os.WriteFile(customGlobal, []byte("[client]\n"), 0o600); err != nil {
		t.Fatalf("write custom global: %v", err)
	}

	// 1. Explicit override via MYSQL_GLOBAL_OPTION_FILE
	t.Setenv("MYSQL_TEST_OPTION_FILE", "")
	t.Setenv("MYSQL_GLOBAL_OPTION_FILE", customGlobal)
	files := mylogin.GlobalOptionFiles()
	if len(files) != 1 || files[0] != customGlobal {
		t.Errorf("expected [%s], got %+v", customGlobal, files)
	}

	// 2. Explicit suppression via "none"
	t.Setenv("MYSQL_GLOBAL_OPTION_FILE", "none")
	if files := mylogin.GlobalOptionFiles(); len(files) != 0 {
		t.Errorf("expected empty for MYSQL_GLOBAL_OPTION_FILE=none, got %+v", files)
	}

	// 3. Hermetic test boundary suppression via MYSQL_TEST_OPTION_FILE
	t.Setenv("MYSQL_GLOBAL_OPTION_FILE", customGlobal)
	t.Setenv("MYSQL_TEST_OPTION_FILE", filepath.Join(tmpDir, "test.cnf"))
	if files := mylogin.GlobalOptionFiles(); len(files) != 0 {
		t.Errorf("expected empty when MYSQL_TEST_OPTION_FILE is active, got %+v", files)
	}

	// 4. Nonexistent file specified via MYSQL_GLOBAL_OPTION_FILE returns nil
	t.Setenv("MYSQL_TEST_OPTION_FILE", "")
	t.Setenv("MYSQL_GLOBAL_OPTION_FILE", filepath.Join(tmpDir, "missing-global.cnf"))
	if files := mylogin.GlobalOptionFiles(); len(files) != 0 {
		t.Errorf("expected empty for missing MYSQL_GLOBAL_OPTION_FILE, got %+v", files)
	}

	// 5. Test MYSQL_OPTION_FILE override on DefaultOptionFile and DefaultOptionFiles
	userOpt := filepath.Join(tmpDir, "my-user.cnf")
	_ = os.WriteFile(userOpt, []byte("[client]\n"), 0o600)
	t.Setenv("MYSQL_GLOBAL_OPTION_FILE", customGlobal)
	t.Setenv("MYSQL_OPTION_FILE", userOpt)
	t.Setenv("MYSQL_TEST_OPTION_FILE", "")

	if got := mylogin.DefaultOptionFile(); got != userOpt {
		t.Errorf("expected DefaultOptionFile=%s, got %s", userOpt, got)
	}
	allFiles := mylogin.DefaultOptionFiles()
	if len(allFiles) != 2 || allFiles[0] != customGlobal || allFiles[1] != userOpt {
		t.Errorf("expected [customGlobal, userOpt], got %+v", allFiles)
	}
}

// TestReadClientDefaultsHierarchy_EdgeCases tests edge cases such as empty input slices and missing files.
func TestReadClientDefaultsHierarchy_EdgeCases(t *testing.T) {
	// 1. Empty slice returns empty login without error
	login, err := mylogin.ReadClientDefaultsHierarchy(nil)
	if err != nil || login == nil || !login.IsEmpty() {
		t.Errorf("expected empty login and nil error for nil slice, got %v, %+v", err, login)
	}

	// 2. Non-existent files in hierarchy are skipped gracefully
	tmpDir := t.TempDir()
	missing1 := filepath.Join(tmpDir, "missing1.cnf")
	missing2 := filepath.Join(tmpDir, "missing2.cnf")
	login, err = mylogin.ReadClientDefaultsHierarchy([]string{missing1, missing2})
	if err != nil || login == nil || !login.IsEmpty() {
		t.Errorf("expected empty login and nil error for missing files, got %v, %+v", err, login)
	}
}
