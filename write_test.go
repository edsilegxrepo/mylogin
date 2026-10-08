// Package mylogin_test validates cryptographic roundtrip determinism and MySQL compatibility.
//
// Objective: Validate complete roundtrip cryptographic fidelity and byte-for-byte binary determinism
// against canonical MySQL 8.x testdata fixtures.
//
// Core Components:
//   - TestReadWrite: Iterates over all test fixtures in testdata/ performing Decode -> Encode -> Byte Comparison.
//
// Test Strategy:
//   - Exhaustive Boundary Audit: Iterate through all 16 PKCS#7 padding boundary fixtures (padding01.cnf to padding16.cnf)
//     and diverse key configurations (0.cnf through e.cnf).
//   - Exact Byte Equality Invariant: Require 100% byte-for-byte equality between the original fixture and the re-encoded stream.
//   - Parallel Execution: Runs each fixture validation in parallel subtests to ensure thread safety and performance.
//
// Functionality:
//   - Ensures encoding logic strictly replicates the byte formatting, IV handling, and padding of official MySQL tools.
//
// Data Flow:
//
//	Disk Fixture (.cnf) -> os.ReadFile -> Decode (Decrypt & Sniff) -> Encode (Re-encrypt & Pad) -> Byte-for-byte Assertion.
package mylogin_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edsilegxrepo/mylogin"
)

// TestReadWrite verifies that every official MySQL-generated binary fixture in testdata/
// decodes and re-encodes with 100% byte-for-byte exact equality.
// This validates AES-128-ECB PKCS#7 padding across all 16 byte boundaries (padding01-16.cnf)
// and diverse 100-bit keys (0-e.cnf).
func TestReadWrite(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("failed to read testdata directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cnf") {
			continue
		}

		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join("testdata", name)
			origBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("os.ReadFile(%s) failed: %v", path, err)
			}

			content, err := mylogin.Decode(bytes.NewReader(origBytes))
			if err != nil {
				t.Fatalf("Decode(%s) failed: %v", path, err)
			}

			var out bytes.Buffer
			if err := mylogin.Encode(&out, content); err != nil {
				t.Fatalf("Encode(%s) failed: %v", path, err)
			}

			outBytes := out.Bytes()
			if !bytes.Equal(origBytes, outBytes) {
				t.Fatalf("%s: content differs: orig=%d bytes, out=%d bytes", path, len(origBytes), len(outBytes))
			}
		})
	}
}
