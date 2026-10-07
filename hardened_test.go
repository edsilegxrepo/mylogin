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
