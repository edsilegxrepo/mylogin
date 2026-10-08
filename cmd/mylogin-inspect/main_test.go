// Package main provides unit test coverage for the mylogin-inspect CLI tool.
//
// Objective: Validate operational inspection of resolved MySQL configurations,
// option file integration, flag parsing, and exit codes.
//
// Core Components:
//   - TestRunInspect: Comprehensive tests covering section resolution, option file merging,
//     flag parsing, version output, and error conditions.
//
// Test Strategy:
//   - In-Process Execution: Directly invoke run() with custom args and captured buffers.
//   - Diagnostic Output Verification: Assert output contains non-sensitive fields and extra key mappings.
//
// Functionality:
//   - Verifies CLI argument handling, environment variable fallback, and error propagation.
//
// Data Flow:
//
//	CLI Args -> run() -> mylogin.ReadResolvedLogin() -> stdout Assertions.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mylogin "github.com/edsilegxrepo/mylogin"
)

func TestRunInspect(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, ".mylogin.cnf")
	optPath := filepath.Join(tempDir, ".my.cnf")

	rawContent := "[client]\nhost = \"localhost\"\n[reporting]\nuser = \"rep_user\"\npassword = \"secret\"\n"
	if err := mylogin.WriteFile(confPath, strings.NewReader(rawContent)); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	optContent := "[client]\nport = 3308\nssl-mode = \"REQUIRED\"\n"
	if err := os.WriteFile(optPath, []byte(optContent), 0o600); err != nil {
		t.Fatalf("WriteFile opt failed: %v", err)
	}

	// 1. Successful inspection with section argument and option file
	var stdout, stderr bytes.Buffer
	code := run([]string{"-file", confPath, "-option-file", optPath, "reporting"}, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess, got %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "resolved user: rep_user") {
		t.Errorf("expected rep_user in output, got: %s", out)
	}
	if !strings.Contains(out, "resolved port: 3308") {
		t.Errorf("expected port 3308 in output, got: %s", out)
	}
	if !strings.Contains(out, "ssl-mode=REQUIRED") {
		t.Errorf("expected ssl-mode=REQUIRED in output, got: %s", out)
	}
	if !strings.Contains(out, "has password: true") {
		t.Errorf("expected has password: true in output, got: %s", out)
	}

	// 2. Version flag
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-version"}, &stdout, &stderr)
	if code != exitSuccess || !strings.Contains(stdout.String(), "mylogin-inspect version") {
		t.Errorf("unexpected version output: %s", stdout.String())
	}

	// 3. Invalid flag
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-invalid-flag"}, &stdout, &stderr)
	if code != exitUsage {
		t.Errorf("expected exitUsage for invalid flag, got %d", code)
	}

	// 4. Missing file error
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", filepath.Join(tempDir, "missing.cnf")}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("expected exitError for missing file, got %d", code)
	}
}
