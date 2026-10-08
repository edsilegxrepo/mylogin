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
