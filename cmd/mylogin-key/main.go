// Command mylogin-key dumps the encryption key embedded in mylogin.cnf files.
package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/edsilegxrepo/myloginpath"
)

const (
	exitSuccess     = 0
	exitUsage       = 2
	exitFileError   = 3
	exitFormatError = 4
)

func printKey(w io.Writer, key mylogin.Key) {
	for _, b := range key {
		if b >= 32 {
			fmt.Fprintf(w, "%X\n", key)
			return
		}
	}

	var compactKey [(len(key)*5 + 7) / 8]byte
	var j int
	var acc uint // accumulator
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

	b64 := base64.RawURLEncoding.EncodeToString(compactKey[:])[:(len(key)*5+5)/6]

	const hex = "0123456789ABCDEF"
	fmt.Fprintf(w, "%X%c %s\n",
		compactKey[:len(compactKey)-1], hex[compactKey[len(compactKey)-1]>>4],
		b64)
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mylogin-key", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintf(stderr, "Usage: mylogin-key [<file> ...]\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return exitUsage
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
