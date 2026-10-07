package mylogin_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edsilegxrepo/myloginpath"
	"github.com/go-sql-driver/mysql"
)

func TestParseResilience(t *testing.T) {
	// Tests:
	// 1. Blank lines between sections
	// 2. Trailing spaces and newlines
	// 3. Comments (# and ;)
	// 4. '=' without spaces around it
	// 5. Custom / unknown MySQL client options stored in Extra map
	input := `
# Global client options
[client]
host = "primary.db.internal"
port=3306

; Comments should be skipped
[reporting]

user= "rep_user"
password = "rep_password"
database = "analytics_dw"
ssl-mode = "REQUIRED"
default-auth = "caching_sha2_password"

`
	sections, err := mylogin.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(sections) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(sections))
	}

	if !sections.Has("client") || !sections.Has("reporting") {
		t.Errorf("missing expected section names: %v", sections.Names())
	}

	clientLogin := sections.Login("client")
	if clientLogin.Host == nil || *clientLogin.Host != "primary.db.internal" {
		t.Errorf("expected host primary.db.internal, got %v", clientLogin.Host)
	}
	if clientLogin.Port == nil || *clientLogin.Port != "3306" {
		t.Errorf("expected port 3306, got %v", clientLogin.Port)
	}

	repLogin := sections.Login("reporting")
	if repLogin.User == nil || *repLogin.User != "rep_user" {
		t.Errorf("expected user rep_user, got %v", repLogin.User)
	}
	if repLogin.Password == nil || *repLogin.Password != "rep_password" {
		t.Errorf("expected password rep_password, got %v", repLogin.Password)
	}

	// Verify Extra options
	if repLogin.Extra == nil {
		t.Fatalf("expected Extra options map, got nil")
	}
	if repLogin.Extra["database"] != "analytics_dw" {
		t.Errorf("expected database=analytics_dw, got %q", repLogin.Extra["database"])
	}
	if repLogin.Extra["ssl-mode"] != "REQUIRED" {
		t.Errorf("expected ssl-mode=REQUIRED, got %q", repLogin.Extra["ssl-mode"])
	}
	if repLogin.Extra["default-auth"] != "caching_sha2_password" {
		t.Errorf("expected default-auth=caching_sha2_password, got %q", repLogin.Extra["default-auth"])
	}
}

func TestParseMalformedLine(t *testing.T) {
	// Line without '=' should return an error, not panic
	input := "[client]\ninvalid_line_without_equals\n"
	_, err := mylogin.Parse(strings.NewReader(input))
	if err == nil {
		t.Fatalf("expected error on malformed line without '=', got nil")
	}
	t.Logf("Observed expected graceful error: %v", err)
}

func TestNewKeyErrorHandling(t *testing.T) {
	mockErr := errors.New("simulated random failure")
	failReader := func(b []byte) (int, error) {
		return 0, mockErr
	}

	_, err := mylogin.NewKey(failReader)
	if err == nil {
		t.Fatalf("expected error from NewKey when reader fails, got nil")
	}
	if !errors.Is(err, mockErr) {
		t.Errorf("expected %v, got %v", mockErr, err)
	}
}

func TestMergeDeepCopy(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	source := &mylogin.Login{
		User:     strPtr("original_user"),
		Password: strPtr("original_pass"),
		Extra:    map[string]string{"cluster": "alpha"},
	}

	dest := &mylogin.Login{
		Host: strPtr("shared.internal"),
	}

	dest.Merge(source)

	// Mutate source fields
	*source.User = "mutated_user"
	*source.Password = "mutated_pass"
	source.Extra["cluster"] = "mutated_cluster"

	// Verify dest has the original values and was not affected by mutation
	if *dest.User != "original_user" {
		t.Errorf("dest.User was mutated via pointer aliasing: %s", *dest.User)
	}
	if *dest.Password != "original_pass" {
		t.Errorf("dest.Password was mutated via pointer aliasing: %s", *dest.Password)
	}
	if dest.Extra["cluster"] != "alpha" {
		t.Errorf("dest.Extra was mutated: %s", dest.Extra["cluster"])
	}
}

func TestConfigMethod(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	login := &mylogin.Login{
		User:     strPtr("alice"),
		Password: strPtr("secret123"),
		Host:     strPtr("10.0.0.5"),
		Port:     strPtr("3307"),
		Extra:    map[string]string{"database": "shop_db"},
	}

	cfg := login.Config()
	if cfg.User != "alice" || cfg.Passwd != "secret123" || cfg.Addr != "10.0.0.5:3307" || cfg.DBName != "shop_db" {
		t.Errorf("unexpected Config values: %+v", cfg)
	}

	dsn := cfg.FormatDSN()
	parsed, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("mysql.ParseDSN failed on formatted DSN %q: %v", dsn, err)
	}
	if parsed.User != "alice" || parsed.Passwd != "secret123" || parsed.DBName != "shop_db" {
		t.Errorf("parsed DSN mismatch: %+v", parsed)
	}
}

func TestWriteFileHelper(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, ".mylogin.cnf")

	rawContent := "[client]\nhost = \"db.cluster.internal\"\nport = 3306\n\n[webapp]\nuser = \"web_srv\"\npassword = \"W3bPass#2026\"\n"

	err := mylogin.WriteFile(filePath, strings.NewReader(rawContent))
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Verify permissions are 0600
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("os.Stat failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got %o", info.Mode().Perm())
	}

	// Read and verify merged login
	merged, err := mylogin.ReadLogin(filePath, []string{"client", "webapp"})
	if err != nil {
		t.Fatalf("ReadLogin failed: %v", err)
	}

	if *merged.Host != "db.cluster.internal" || *merged.Port != "3306" {
		t.Errorf("inherited host/port incorrect: %v:%v", merged.Host, merged.Port)
	}
	if *merged.User != "web_srv" || *merged.Password != "W3bPass#2026" {
		t.Errorf("user/pass incorrect: %v / %v", merged.User, merged.Password)
	}
}

func TestFilterSectionResilience(t *testing.T) {
	// Verifies that FilterSection does not panic on empty lines
	input := "[client]\nhost = 127.0.0.1\n\n\n[staging]\nhost = 10.0.0.1\n\n"
	filtered := mylogin.FilterSection(strings.NewReader(input), "staging")
	sections, err := mylogin.Parse(filtered)
	if err != nil {
		t.Fatalf("Parse filtered section failed: %v", err)
	}
	if len(sections) != 1 || sections[0].Name != "staging" {
		t.Fatalf("expected 1 staging section, got: %+v", sections)
	}
	if *sections[0].Login.Host != "10.0.0.1" {
		t.Errorf("expected host 10.0.0.1, got %v", sections[0].Login.Host)
	}
}

func TestCheckPermissions(t *testing.T) {
	tempDir := t.TempDir()
	safeFile := filepath.Join(tempDir, "safe.cnf")
	unsafeFile := filepath.Join(tempDir, "unsafe.cnf")

	if err := os.WriteFile(safeFile, []byte("content"), 0600); err != nil {
		t.Fatalf("failed to create safe file: %v", err)
	}
	if err := os.WriteFile(unsafeFile, []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create unsafe file: %v", err)
	}

	if err := mylogin.CheckPermissions(safeFile); err != nil {
		t.Errorf("CheckPermissions failed on 0600 file: %v", err)
	}

	err := mylogin.CheckPermissions(unsafeFile)
	if err == nil {
		t.Errorf("expected ErrInsecurePermissions on 0644 file, got nil")
	} else if !errors.Is(err, mylogin.ErrInsecurePermissions) {
		t.Errorf("expected ErrInsecurePermissions, got: %v", err)
	}
}

func TestZeroSecurity(t *testing.T) {
	key := mylogin.Key{1, 2, 3, 4, 5}
	if key.IsZero() {
		t.Fatal("key should not be zero")
	}
	key.Zero()
	if !key.IsZero() {
		t.Fatal("key should be zero after Zero()")
	}

	secret := "sensitive_password_123"
	login := &mylogin.Login{Password: &secret}
	login.Zero()
	if *login.Password != "" {
		t.Errorf("password was not cleared: %q", *login.Password)
	}
}

func TestNilSafety(t *testing.T) {
	var nilLogin *mylogin.Login

	// None of these should panic
	if !nilLogin.IsEmpty() {
		t.Errorf("expected nil login to be empty")
	}
	if nilLogin.HasCredentials() {
		t.Errorf("expected nil login not to have credentials")
	}
	if dsn := nilLogin.DSN(); dsn != "/" {
		t.Errorf("expected '/', got %q", dsn)
	}
	if dsn := nilLogin.FormatDSN("testdb"); dsn != "/testdb" {
		t.Errorf("expected '/testdb', got %q", dsn)
	}
	cfg := nilLogin.Config()
	if cfg == nil {
		t.Errorf("expected non-nil Config() from nil login")
	}
	nilLogin.Zero() // should safely do nothing without panic
}

func TestInvalidPaddingError(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "corrupted.cnf")

	rawContent := "[client]\nhost = \"localhost\"\n"
	if err := mylogin.WriteFile(filePath, strings.NewReader(rawContent)); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Corrupt a ciphertext byte
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	// Corrupt the last byte of the ciphertext chunk
	data[len(data)-1] ^= 0xFF
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		t.Fatalf("WriteFile corrupted failed: %v", err)
	}

	// Reading the corrupted file should trigger ErrInvalidPadding or parse error
	_, err = mylogin.ReadSections(filePath)
	if err == nil {
		t.Fatal("expected error reading corrupted encrypted file, got nil")
	}
	t.Logf("Observed expected padding/corruption error: %v", err)
}

func TestSectionWriteToAndValidation(t *testing.T) {
	var sections mylogin.Sections

	// Build sections using new builder setters
	var sec1 mylogin.Login
	sec1.SetHost("cluster.internal").SetPort("3306")
	sections.Set("client", sec1)

	var sec2 mylogin.Login
	sec2.SetUser("app_admin").SetPassword(`P@ss"word\with\special`).SetExtra("database", "prod_db")
	sections.Set("production", sec2)

	// Format to plaintext
	formatted, err := sections.Format()
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	t.Logf("Formatted output:\n%s", formatted)

	// Parse it back to verify full roundtrip
	parsed, err := mylogin.Parse(strings.NewReader(formatted))
	if err != nil {
		t.Fatalf("Parse of Formatted output failed: %v", err)
	}

	if len(parsed) != 2 {
		t.Fatalf("expected 2 parsed sections, got %d", len(parsed))
	}

	prod := parsed.Login("production")
	if *prod.User != "app_admin" {
		t.Errorf("user mismatch: %s", *prod.User)
	}
	if *prod.Password != `P@ss"word\with\special` {
		t.Errorf("password unquoting mismatch: %q", *prod.Password)
	}
	if prod.Extra["database"] != "prod_db" {
		t.Errorf("extra database mismatch: %s", prod.Extra["database"])
	}

	// Test injection validation
	var badSec mylogin.Section
	badSec.Name = "bad\n[injected_section]"
	if err := badSec.Validate(); err == nil {
		t.Fatal("expected error on section name with newline, got nil")
	}

	// Test Sections.Delete
	if !sections.Delete("production") {
		t.Fatal("expected Delete to return true for existing section")
	}
	if sections.Has("production") {
		t.Fatal("section should be deleted")
	}
}

func TestDSNInjectionDefense(t *testing.T) {
	// If password or host has special characters, verify DSN formatting
	var l mylogin.Login
	l.SetUser("alice").SetPassword("pass@word:special").SetHost("db.internal").SetPort("3306")

	// DSN prefix
	dsnPrefix := l.DSN()
	cfg, err := mysql.ParseDSN(dsnPrefix + "testdb")
	if err != nil {
		t.Fatalf("mysql.ParseDSN failed on formatted DSN %q: %v", dsnPrefix, err)
	}

	if cfg.User != "alice" || cfg.Passwd != "pass@word:special" || cfg.Addr != "db.internal:3306" {
		t.Errorf("parsed DSN values mismatch: %+v", cfg)
	}
}


