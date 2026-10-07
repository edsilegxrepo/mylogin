package main

import (
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
	exitNotFound    = 5
)

var version = "2.0.0"

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mylogin-dsn", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		database    string
		filename    string
		showVersion bool
	)
	flags.StringVar(&database, "database", "", "database name to append to DSN")
	flags.StringVar(&filename, "file", mylogin.DefaultFile(), "path to .mylogin.cnf")
	flags.BoolVar(&showVersion, "version", false, "display version and exit")
	flags.BoolVar(&showVersion, "V", false, "display version (short)")
	flags.Usage = func() {
		fmt.Fprintf(stderr, "Usage: mylogin-dsn [-file <path>] [-database <dbname>] [<section> ...]\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	if showVersion {
		fmt.Fprintf(stdout, "mylogin-dsn version %s\n", version)
		return exitSuccess
	}

	var sections []string
	if flags.NArg() == 0 {
		sections = []string{mylogin.DefaultSection}
	} else {
		sections = flags.Args()
	}

	login, err := mylogin.ReadLogin(filename, sections)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			fmt.Fprintf(stderr, "mylogin-dsn: file error: %v\n", err)
			return exitFileError
		}
		fmt.Fprintf(stderr, "mylogin-dsn: decryption/parse error: %v\n", err)
		return exitFormatError
	}

	if login.IsEmpty() {
		fmt.Fprintf(stderr, "mylogin-dsn: no credentials found for sections: %v\n", sections)
		return exitNotFound
	}

	fmt.Fprintln(stdout, login.FormatDSN(database))
	return exitSuccess
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
