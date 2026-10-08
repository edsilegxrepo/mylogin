// Package mylogin_test validates MySQL Data Source Name (DSN) formatting and driver parsing.
//
// Objective: Validate that Login.DSN() outputs valid Data Source Names (DSN) compliant with
// go-sql-driver/mysql specifications and confirm roundtrip parser fidelity.
//
// Core Components:
//   - TestDSN: Tests formatting of user, password, host, and port into standard DSN syntax.
//   - stringPtr: Utility converting a string value to a heap pointer.
//
// Test Strategy:
//   - Driver Roundtrip Invariant: Format credentials via Login.DSN(), parse the result using
//     the official mysql.ParseDSN, re-format using cfg.FormatDSN(), and assert exact string equality.
//
// Functionality:
//   - Validates seamless interoperability between mylogin credential objects and the go-sql-driver/mysql driver.
//
// Data Flow:
//
//	Login Struct -> Login.DSN() -> mysql.ParseDSN() -> cfg.FormatDSN() -> Equality Assertion.
package mylogin_test

import (
	"testing"

	"github.com/edsilegxrepo/mylogin"

	"github.com/go-sql-driver/mysql"
)

func stringPtr(s string) *string {
	return &s
}

func TestDSN(t *testing.T) {
	l := mylogin.Login{
		User:     stringPtr("dolmen"),
		Password: stringPtr("secret"),
		Host:     stringPtr("localhost"),
		Port:     stringPtr("3306"),
	}
	dsn := l.DSN()
	t.Log(dsn)
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	dsn2 := cfg.FormatDSN()
	if dsn2 != dsn {
		t.Fatal(dsn2, " != ", dsn)
	}
}
