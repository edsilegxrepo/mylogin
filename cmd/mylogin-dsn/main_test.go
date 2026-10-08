// Package main provides unit test coverage for the mylogin-dsn CLI tool.
//
// Objective: Validate the operational functionality of the mylogin-dsn CLI command binary,
// including DSN formatting, database suffix appending, section resolution, and process exit codes.
//
// Core Components:
//   - TestRunDSN: Comprehensive test covering default section, database flag, explicit section,
//     missing sections, file errors, invalid flags, and version output.
//
// Test Strategy:
//   - Direct In-Process Invocation: Calls run() directly with mocked flag arguments and captured
//     stdout/stderr buffers to verify console output and integer exit codes.
//   - Format Assertions: Verifies proper syntax of tcp() transports, usernames, passwords, and schema paths.
//
// Functionality:
//   - Confirms correct execution flow from CLI invocation to emitted DSN strings.
//
// Data Flow:
//
//	CLI Flag Array -> run -> mylogin.ReadLogin -> FormatDSN -> stdout Buffer -> Assertions.
package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edsilegxrepo/mylogin"
)

func TestRunDSN(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, ".mylogin.cnf")

	rawContent := "[client]\nhost = \"localhost\"\nport = 3306\n[analytics]\nuser = \"analyst\"\npassword = \"pass123\"\n"
	if err := mylogin.WriteFile(confPath, strings.NewReader(rawContent)); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 1. Successful run with default section and database flag
	var stdout, stderr bytes.Buffer
	code := run([]string{"-file", confPath, "-database", "stats_db"}, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "tcp(localhost:3306)/stats_db") {
		t.Errorf("unexpected stdout: %s", stdout.String())
	}

	// 2. Successful run with explicit section
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", confPath, "analytics"}, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess, got %d", code)
	}
	if !strings.Contains(stdout.String(), "analyst:pass123") {
		t.Errorf("unexpected stdout: %s", stdout.String())
	}

	// 3. Section not found
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", confPath, "non_existent"}, &stdout, &stderr)
	if code != exitNotFound {
		t.Fatalf("expected exitNotFound, got %d", code)
	}

	// 4. File error
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", filepath.Join(tempDir, "missing.cnf")}, &stdout, &stderr)
	if code != exitFileError {
		t.Fatalf("expected exitFileError, got %d", code)
	}

	// 5. Invalid flag usage
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-unknown-flag"}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("expected exitUsage, got %d", code)
	}

	// 6. Version flag
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-version"}, &stdout, &stderr)
	if code != exitSuccess || !strings.Contains(stdout.String(), "mylogin-dsn version") {
		t.Fatalf("expected version output, got code %d, stdout: %s", code, stdout.String())
	}
}
