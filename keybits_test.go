// Package mylogin_test verifies MySQL key generation invariants.
//
// Objective: Validate empirically that MySQL's native mysql_config_editor binary
// generates 20-byte encryption keys where the 3 high bits of each byte are always cleared (< 32).
//
// Core Components:
//   - TestKeyBits: Fuzzing runner that repeatedly invokes mysql_config_editor within a bounded timeframe.
//   - testFileKeyBits: Sub-routine generating a file, decoding its key, and asserting the 5-bit constraint.
//
// Test Strategy:
//   - Property-Based Empirical Fuzzing: Iteratively generates fresh login path files using the native tool.
//   - High-Bit Invariant Assertion: Asserts each byte in key < 32 across thousands of iterations.
//   - Graceful Tool Availability Check: Skips fuzzing gracefully when mysql_config_editor is absent from PATH.
//
// Functionality:
//   - Validates the fundamental cryptographic assumption used by NewKey and cmd/mylogin-key.
//
// Data Flow:
//
//	exec.Command(mysql_config_editor) -> Write Temp .cnf -> mylogin.Decode -> Verify b < 32 -> Clean Up.
package mylogin_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/edsilegxrepo/mylogin"
)

// mysql_config_editor generates files with a key where the high 3 bits
// of each byte are always cleared. Let's check by fuzzing.
//
// See also cmd/mylogin-key
func TestKeyBits(t *testing.T) {
	mysql_config_editor, err := exec.LookPath("mysql_config_editor")
	if err != nil {
		t.Logf("mysql_config_editor not found in PATH")
		return
	}

	tempDir := t.TempDir()

	timeout := time.NewTimer(800 * time.Millisecond)
Loop:
	for i := 0; i < 100000; i++ {
		testFileKeyBits(t, mysql_config_editor, filepath.Join(tempDir, fmt.Sprintf("%08d.cnf", i)))

		select {
		case <-timeout.C:
			break Loop
		default:
		}
	}
}

func testFileKeyBits(t *testing.T, mysql_config_editor string, filename string) {
	cmd := exec.Command(mysql_config_editor, `set`, `--login-path=toto`)
	cmd.Env = append(
		os.Environ(),
		"MYSQL_TEST_LOGIN_FILE="+filename,
	)
	var err error
	cmd.Stdout, err = os.OpenFile(os.DevNull, os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatalf("%s: %s", os.DevNull, err)
	}
	cmd.Stderr = os.Stderr
	defer os.Remove(filename)

	err = cmd.Run()
	if err != nil {
		t.Fatalf("%s: %s", filename, err)
	}

	f, err := os.Open(filename)
	if err != nil {
		t.Fatalf("%s: %s", filename, err)
	}
	defer f.Close()

	file, err := mylogin.Decode(bufio.NewReader(f))
	if err != nil {
		t.Fatalf("%s: %s", filename, err)
	}
	key := file.Key()

	// Check that each byte of the key has the 3 high bits clear
	for _, b := range key {
		if b >= 32 {
			t.Errorf("%s: %X (more than 5 bits in key)", filename, key)
			return
		}
	}

	t.Logf("%s: %X (3 high bits always cleared)", filename, key)
}
