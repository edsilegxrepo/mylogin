// Package main provides unit test coverage for the mylogin-connect CLI tool.
//
// Objective: Validate connectivity verification logic, parameter parsing,
// dry-run validation, and process exit codes.
//
// Core Components:
//   - TestRunConnect: Comprehensive tests covering source/target resolution,
//     dry-run connector creation, flag parsing, version output, and error conditions.
//
// Test Strategy:
//   - In-Process Execution: Directly invoke run() with custom args and captured buffers.
//   - Dry-Run Execution: Verify connector creation and configuration validation without network I/O.
//
// Functionality:
//   - Verifies CLI argument handling, environment variable fallback, and error handling.
//
// Data Flow:
//
//	CLI Args -> run() -> mylogin.ReadResolvedLogin() -> Login.Connector() -> stdout Assertions.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mylogin "github.com/edsilegxrepo/mylogin"
)

func TestRunConnect(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, ".mylogin.cnf")

	rawContent := "[client]\nhost = \"localhost\"\n[source_sec]\nuser = \"src_user\"\npassword = \"secret1\"\n[target_sec]\nuser = \"tgt_user\"\npassword = \"secret2\"\n"
	if err := mylogin.WriteFile(confPath, strings.NewReader(rawContent)); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 1. Successful dry-run with explicit source and target sections
	var stdout, stderr bytes.Buffer
	code := run([]string{"-file", confPath, "-source", "source_sec", "-target", "target_sec", "-dry-run"}, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess in dry-run, got %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "source configuration valid") {
		t.Errorf("expected source configuration valid, got: %s", out)
	}
	if !strings.Contains(out, "target configuration valid") {
		t.Errorf("expected target configuration valid, got: %s", out)
	}

	// 2. Version flag
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-version"}, &stdout, &stderr)
	if code != exitSuccess || !strings.Contains(stdout.String(), "mylogin-connect version") {
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
	code = run([]string{"-file", filepath.Join(tempDir, "missing.cnf"), "-dry-run"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("expected exitError for missing file, got %d", code)
	}

	// 5. Source connector validation failure (invalid TLS)
	badTLSConf := filepath.Join(tempDir, "bad_tls.cnf")
	badContent := "[bad_source]\nssl-cert = \"/missing/cert.pem\"\n[bad_target]\nssl-cert = \"/missing/cert.pem\"\n"
	_ = mylogin.WriteFile(badTLSConf, strings.NewReader(badContent))

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", badTLSConf, "-source", "bad_source", "-dry-run"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("expected exitError for bad source TLS, got %d", code)
	}

	// 6. Target connector validation failure (invalid TLS)
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", badTLSConf, "-source", "source_sec", "-target", "bad_target", "-dry-run"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("expected exitError for bad target TLS, got %d", code)
	}

	// 7. Live ping error on unreachable port
	unreachableConf := filepath.Join(tempDir, "unreachable.cnf")
	_ = mylogin.WriteFile(unreachableConf, strings.NewReader("[unreachable]\nhost = \"127.0.0.1\"\nport = 1\n"))
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", unreachableConf, "-source", "unreachable"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("expected exitError on unreachable live ping, got %d", code)
	}

	// 8. Test environment variable fallback for default source path
	t.Setenv("MYSQL_HOST", "prod")
	t.Setenv("MYSQL_DB_BACKUP_SVC", "db")
	envConf := filepath.Join(tempDir, "env.cnf")
	_ = mylogin.WriteFile(envConf, strings.NewReader("[prod_db]\nuser = \"env_user\"\n"))
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", envConf, "-dry-run"}, &stdout, &stderr)
	if code != exitSuccess || !strings.Contains(stdout.String(), "source configuration valid") {
		t.Errorf("expected success with env var defaults, got %d: %s", code, stderr.String())
	}

	// 9. Cascade with -option-file and -global-option-file in dry-run mode
	optPath := filepath.Join(tempDir, "user.cnf")
	globalOptPath := filepath.Join(tempDir, "global.cnf")
	_ = os.WriteFile(globalOptPath, []byte("[client]\nconnect-timeout = 5\n"), 0o600)
	_ = os.WriteFile(optPath, []byte("[client]\nread-timeout = 10\n"), 0o600)

	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"-file", confPath,
		"-option-file", optPath,
		"-global-option-file", globalOptPath,
		"-source", "source_sec",
		"-target", "target_sec",
		"-dry-run",
	}, &stdout, &stderr)
	if code != exitSuccess {
		t.Errorf("expected exitSuccess with cascade flags, got %d, stderr: %s", code, stderr.String())
	}

	// 10. Target live ping error on unreachable port
	unreachableTgtConf := filepath.Join(tempDir, "unreachable_tgt.cnf")
	_ = mylogin.WriteFile(unreachableTgtConf, strings.NewReader("[src_ok]\n[unreachable_tgt]\nhost = \"127.0.0.1\"\nport = 1\n"))
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", unreachableTgtConf, "-source", "src_ok", "-target", "unreachable_tgt"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("expected exitError on unreachable target ping, got %d", code)
	}

	// 11. Malformed option file error
	malformedOpt := filepath.Join(tempDir, "malformed.cnf")
	_ = os.WriteFile(malformedOpt, []byte("[client]\ninvalid_line_without_equals\n"), 0o600)
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", confPath, "-option-file", malformedOpt, "-dry-run"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("expected exitError for malformed option file, got %d", code)
	}
}
