//go:build windows
// +build windows

// Objective: Validate Windows-specific MySQL login file (.mylogin.cnf) path resolution logic,
// %APPDATA% evaluation, user profile fallback mechanisms, and Windows permission checks.
//
// Core Components Tested:
//   - platformDefaultFile (Windows implementation).
//   - CheckPermissions (Windows file existence validation).
//
// Test Strategy:
//   - Environment Isolation: Isolate %APPDATA% manipulations using t.Setenv to automatically restore the environment.
//   - Custom APPDATA: Set APPDATA to t.TempDir() and assert that the resulting path matches %APPDATA%\MySQL\.mylogin.cnf.
//   - Unset APPDATA Fallback: Unset APPDATA and assert that fallback path generation still returns a non-empty canonical path.
//   - File Permission Checking: Test existing file returns nil and non-existent file returns os.ErrNotExist.
//
// Functionality:
//   - Verifies canonical Windows MySQL login file directory structure.
//   - Verifies resilience against missing APPDATA environment variable.
//   - Verifies file existence validation on Windows.
//
// Data Flow:
//
//	APPDATA Environment -> platformDefaultFile() -> String Path Equality Assertions
package mylogin

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestPlatformDefaultFile_Windows verifies that platformDefaultFile()
// resolves to %APPDATA%\MySQL\.mylogin.cnf when APPDATA is populated, and falls back to a valid
// user home profile path when APPDATA is unset.
func TestPlatformDefaultFile_Windows(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("APPDATA", tmp)

	// 1. Verify resolution with explicit APPDATA directory
	expected := filepath.Join(tmp, "MySQL", ".mylogin.cnf")
	if got := platformDefaultFile(); got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}

	// 2. Test fallback when APPDATA is unset
	if err := os.Unsetenv("APPDATA"); err != nil {
		t.Fatalf("failed to unset APPDATA: %v", err)
	}
	gotFallback := platformDefaultFile()
	if gotFallback == "" {
		t.Error("expected non-empty fallback path when APPDATA is unset")
	}

	// 3. Test CheckPermissions on Windows
	existingFile := filepath.Join(tmp, "testfile.cnf")
	if err := os.WriteFile(existingFile, []byte("data"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := CheckPermissions(existingFile); err != nil {
		t.Errorf("expected nil error for existing file, got: %v", err)
	}

	nonExistentFile := filepath.Join(tmp, "nonexistent.cnf")
	if err := CheckPermissions(nonExistentFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected ErrNotExist, got: %v", err)
	}
}
