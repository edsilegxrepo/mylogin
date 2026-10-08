//go:build windows
// +build windows

// Objective: Validate Windows-specific MySQL option file path resolution logic, including
// %APPDATA% evaluation and user profile fallback mechanisms.
//
// Core Components Tested:
//   - platformDefaultOptionFile (Windows implementation).
//
// Test Strategy:
//   - Environment Isolation: Isolate %APPDATA% manipulations using defer to restore initial environment.
//   - Custom APPDATA: Set APPDATA to t.TempDir() and assert that the resulting option path matches %APPDATA%\MySQL\.my.cnf.
//   - Unset APPDATA Fallback: Unset APPDATA and assert that fallback path generation still returns a non-empty canonical path.
//
// Functionality:
//   - Verifies canonical Windows MySQL option file directory structure.
//   - Verifies resilience against missing APPDATA environment variable.
//
// Data Flow:
//
//	APPDATA Environment -> platformDefaultOptionFile() -> String Path Equality Assertions
package mylogin

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPlatformDefaultOptionFile_Windows verifies that platformDefaultOptionFile()
// resolves to %APPDATA%\MySQL\.my.cnf when APPDATA is populated, and falls back to a valid
// user home profile path when APPDATA is unset.
func TestPlatformDefaultOptionFile_Windows(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("APPDATA", tmp)

	// 1. Verify resolution with explicit APPDATA directory
	expected := filepath.Join(tmp, "MySQL", ".my.cnf")
	if got := platformDefaultOptionFile(); got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}

	// 2. Test fallback when APPDATA is unset
	if err := os.Unsetenv("APPDATA"); err != nil {
		t.Fatalf("failed to unset APPDATA: %v", err)
	}
	gotFallback := platformDefaultOptionFile()
	if gotFallback == "" {
		t.Error("expected non-empty fallback path when APPDATA is unset")
	}
}
