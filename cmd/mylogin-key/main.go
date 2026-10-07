// Command mylogin-key dumps the encryption key embedded in mylogin.cnf files.
package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"

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
			compactKey[j] = byte(acc >> accBits)
			j++
		}
	}
	compactKey[j] = byte(acc << (8 - accBits))

	b64 := base64.RawURLEncoding.EncodeToString(compactKey[:])[:(len(key)*5+5)/6]

	const hex = "0123456789ABCDEF"
	fmt.Fprintf(w, "%X%c %s\n",
		compactKey[:len(compactKey)-1], hex[compactKey[len(compactKey)-1]>>4],
		b64)
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [<file> ...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	var filenames []string
	if flag.NArg() > 0 {
		filenames = flag.Args()
	} else {
		filenames = []string{mylogin.DefaultFile()}
	}

	hadError := false
	for _, filename := range filenames {
		f, err := os.Open(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mylogin-key: cannot open %s: %v\n", filename, err)
			hadError = true
			continue
		}

		file, err := mylogin.Decode(bufio.NewReader(f))
		f.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "mylogin-key: decode failed for %s: %v\n", filename, err)
			hadError = true
			continue
		}

		printKey(os.Stdout, file.Key())
	}

	if hadError {
		os.Exit(exitFileError)
	}
	os.Exit(exitSuccess)
}
