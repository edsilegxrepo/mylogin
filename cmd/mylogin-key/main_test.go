package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edsilegxrepo/myloginpath"
)

func TestPrintKey(t *testing.T) {
	// 1. Standard 5-bit key
	var normalKey mylogin.Key
	for i := range normalKey {
		normalKey[i] = byte(i % 30) // all < 32
	}
	var bufNormal bytes.Buffer
	printKey(&bufNormal, normalKey)
	outNormal := bufNormal.String()
	if len(outNormal) == 0 {
		t.Fatalf("expected non-empty output for normal key")
	}

	// 2. Key with byte >= 32 (falls back to %X\n)
	var largeKey mylogin.Key
	largeKey[0] = 50
	var bufLarge bytes.Buffer
	printKey(&bufLarge, largeKey)
	outLarge := strings.TrimSpace(bufLarge.String())
	if !strings.HasPrefix(outLarge, "32") { // 50 in hex is 0x32
		t.Errorf("expected hex dump starting with 32, got %s", outLarge)
	}
}

func TestRunMyLoginKey(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, ".mylogin.cnf")

	rawContent := "[client]\nhost = \"localhost\"\n"
	if err := mylogin.WriteFile(confPath, strings.NewReader(rawContent)); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 1. Success on valid file
	var stdout, stderr bytes.Buffer
	code := run([]string{confPath}, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess, got %d, stderr: %s", code, stderr.String())
	}
	if len(stdout.String()) == 0 {
		t.Fatalf("expected non-empty key output")
	}

	// 2. Error on missing file
	stdout.Reset()
	stderr.Reset()
	code = run([]string{filepath.Join(tempDir, "missing.cnf")}, &stdout, &stderr)
	if code != exitFileError {
		t.Fatalf("expected exitFileError, got %d", code)
	}

	// 3. Error on invalid flag
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-bad-flag"}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("expected exitUsage, got %d", code)
	}
}
