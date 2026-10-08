// Command mylogin-key dumps the encryption key embedded in mylogin.cnf files.
//
// Objective: Provide an operational diagnostic utility to extract, compact, and display
// the 20-byte AES-128 encryption key embedded within .mylogin.cnf file headers.
//
// Core Components:
//   - Bit Compactor (printKey): Bit-packing algorithm compressing 20 5-bit integers (100 bits total)
//     into a 13-byte array, emitting both canonical hexadecimal and URL-safe Base64 representations.
//   - Header Reader: Decodes the initial 24-byte file header using mylogin.Decode without streaming entire payload.
//   - Batch File Processor: Processes single or multiple configuration files in sequence.
//
// Functionality:
//   - Entropy Compaction: MySQL keys only utilize 5 bits per byte (high 3 bits cleared).
//     Compacting 20 bytes * 5 bits = 100 bits into 12.5 bytes (13 bytes ceiling).
//   - Dual Encoding Emission: Emits both hex and base64 representations for key analysis and escrow.
//   - Multi-File Batching: Iterates through arbitrary target files, falling back to default login file.
//
// Data Flow:
//
//	CLI Invocation -> Parse Files -> Open File -> mylogin.Decode -> Extract Key ->
//	  [Bit-pack 100 bits] -> [Format Hex & URL-safe Base64] -> stdout.
package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/edsilegxrepo/mylogin"
)

// Process exit codes conforming to standard CLI design practices.
const (
	exitSuccess     = 0 // Key extracted and emitted successfully
	exitUsage       = 2 // Invalid command-line arguments or flags
	exitFileError   = 3 // File system I/O error or failure to read all specified files
	exitFormatError = 4 // Corrupted file, invalid header, or decryption failure
)

// printKey inspects the 20-byte key. If any byte has values >= 32, it falls back to
// raw hex printing. Otherwise, it compacts the 100 bits (20 * 5 bits) into 13 bytes
// and prints both hexadecimal and raw URL-safe Base64 encodings.
func printKey(w io.Writer, key mylogin.Key) {
	// If any byte violates the 5-bit constraint (>= 32), print raw 20-byte hex dump
	for _, b := range key {
		if b >= 32 {
			fmt.Fprintf(w, "%X\n", key)
			return
		}
	}

	// Pack 20 5-bit integers into 13 bytes (ceil(100 / 8) = 13 bytes)
	var compactKey [(len(key)*5 + 7) / 8]byte
	var j int
	var acc uint // accumulator for packing bits across byte boundaries
	var accBits uint
	for _, b := range key {
		acc = (acc << 5) | uint(b)
		accBits += 5
		for accBits >= 8 {
			accBits -= 8
			compactKey[j] = byte((acc >> accBits) & 0xFF)
			j++
		}
	}
	compactKey[j] = byte((acc << (8 - accBits)) & 0xFF)

	// Encode to unpadded URL-safe Base64
	b64 := base64.RawURLEncoding.EncodeToString(compactKey[:])[:(len(key)*5+5)/6]

	const hex = "0123456789ABCDEF"
	fmt.Fprintf(w, "%X%c %s\n",
		compactKey[:len(compactKey)-1], hex[compactKey[len(compactKey)-1]>>4],
		b64)
}

var version = "dev"

// run coordinates argument parsing, file reading, and key emission.
//
// Execution Flow:
//  1. Parse flags (-version, -V).
//  2. Collect target file paths from positional arguments (or default file).
//  3. Decode each file header and emit compacted key to stdout.
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mylogin-key", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var showVersion bool
	flags.BoolVar(&showVersion, "version", false, "display version and exit")
	flags.BoolVar(&showVersion, "V", false, "display version (short)")
	flags.Usage = func() {
		fmt.Fprintf(stderr, "Usage: mylogin-key [<file> ...]\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	if showVersion {
		fmt.Fprintf(stdout, "mylogin-key version %s\n", version)
		return exitSuccess
	}

	var filenames []string
	if flags.NArg() > 0 {
		filenames = flags.Args()
	} else {
		filenames = []string{mylogin.DefaultFile()}
	}

	hadError := false
	for _, filename := range filenames {
		cleanPath := filepath.Clean(filename)
		f, err := os.Open(cleanPath) // #nosec G304 -- CLI utility intentionally reads user-specified path
		if err != nil {
			fmt.Fprintf(stderr, "mylogin-key: cannot open %s: %v\n", filename, err)
			hadError = true
			continue
		}

		file, err := mylogin.Decode(bufio.NewReader(f))
		_ = f.Close()
		if err != nil {
			fmt.Fprintf(stderr, "mylogin-key: decode failed for %s: %v\n", filename, err)
			hadError = true
			continue
		}

		printKey(stdout, file.Key())
	}

	if hadError {
		return exitFileError
	}
	return exitSuccess
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
