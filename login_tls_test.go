// Objective: External package-level integration tests for TLS/mTLS configuration enforcement
// and cascading client SSL defaults across option files and login paths.
//
// Core Components Tested:
//   - Login.Connector, ReadResolvedLogin.
//
// Test Strategy:
//   - Validation Failure Testing: Assert that partial mutual TLS configurations (e.g., providing ssl-cert without ssl-key)
//     fail immediately with clear descriptive errors when constructing a driver.Connector.
//   - Cascading Inheritance Testing: Synthesize option files containing global client SSL parameters (ssl-mode, ssl-ca)
//     and verify that ReadResolvedLogin accurately inherits them into application login profiles.
//
// Functionality:
//   - Enforces mTLS certificate-key pairing invariant.
//   - Verifies end-to-end inheritance of TLS parameters from plaintext option files to resolved login structures.
//
// Data Flow:
//
//	Login Struct with TLS settings -> Login.Connector() -> Validation Rejection / Error Check
//	Plaintext .my.cnf + Encrypted .mylogin.cnf -> ReadResolvedLogin() -> TLS Parameter Inheritance Assertions
package mylogin_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edsilegxrepo/mylogin"
)

// TestConnectorFailsOnIncompleteTLSMaterial verifies that setting ssl-cert without a matching
// ssl-key causes Login.Connector() to fail immediately with an explicit error.
func TestConnectorFailsOnIncompleteTLSMaterial(t *testing.T) {
	login := new(mylogin.Login)
	login.SetExtra("ssl-mode", "VERIFY_CA")
	login.SetExtra("ssl-cert", "/tmp/client-cert.pem")
	_, err := login.Connector("testdb")
	if err == nil {
		t.Fatal("expected Connector to fail when ssl-cert is set without ssl-key")
	}
}

// TestReadResolvedLoginUsesClientTLSDefaults verifies that plaintext option file client defaults
// supply baseline SSL settings (ssl-mode, ssl-ca) to resolved login paths.
func TestReadResolvedLoginUsesClientTLSDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	optionFile := filepath.Join(tmpDir, ".my.cnf")
	loginFile := filepath.Join(tmpDir, ".mylogin.cnf")

	// Write plaintext option file containing client TLS parameters
	plain := "[client]\nssl-mode = \"VERIFY_CA\"\nssl-ca = \"/etc/pki/tls/pem/mysql-server-ca.pem\"\n"
	if err := os.WriteFile(optionFile, []byte(plain), 0o644); err != nil {
		t.Fatalf("WriteFile optionFile: %v", err)
	}

	// Write encrypted login file containing credentials for section "source"
	sections := mylogin.Sections{
		{Name: "client", Login: *new(mylogin.Login).SetHost("db.internal")},
		{Name: "source", Login: *new(mylogin.Login).SetUser("dbbackup").SetPassword("secret")},
	}
	formatted, err := sections.Format()
	if err != nil {
		t.Fatalf("sections.Format: %v", err)
	}
	if err := mylogin.WriteFile(loginFile, strings.NewReader(formatted)); err != nil {
		t.Fatalf("WriteFile loginFile: %v", err)
	}

	// Resolve composite view: .my.cnf [client] -> .mylogin.cnf [client] -> .mylogin.cnf [source]
	resolved, err := mylogin.ReadResolvedLogin(loginFile, optionFile, []string{"client", "source"})
	if err != nil {
		t.Fatalf("ReadResolvedLogin: %v", err)
	}
	if resolved.Extra["ssl-mode"] != "VERIFY_CA" {
		t.Fatalf("expected ssl-mode from client defaults, got %q", resolved.Extra["ssl-mode"])
	}
	if resolved.Extra["ssl-ca"] != "/etc/pki/tls/pem/mysql-server-ca.pem" {
		t.Fatalf("expected ssl-ca from client defaults, got %q", resolved.Extra["ssl-ca"])
	}
}
