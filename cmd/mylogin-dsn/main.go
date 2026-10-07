package main

import (
	"flag"
	"fmt"
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

func main() {
	var (
		database string
		filename string
	)
	flag.StringVar(&database, "database", "", "database name to append to DSN")
	flag.StringVar(&filename, "file", mylogin.DefaultFile(), "path to .mylogin.cnf")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-file <path>] [-database <dbname>] [<section> ...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	var sections []string
	if flag.NArg() == 0 {
		sections = []string{mylogin.DefaultSection}
	} else {
		sections = flag.Args()
	}

	login, err := mylogin.ReadLogin(filename, sections)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			fmt.Fprintf(os.Stderr, "mylogin-dsn: file error: %v\n", err)
			os.Exit(exitFileError)
		}
		fmt.Fprintf(os.Stderr, "mylogin-dsn: decryption/parse error: %v\n", err)
		os.Exit(exitFormatError)
	}

	if login.IsEmpty() {
		fmt.Fprintf(os.Stderr, "mylogin-dsn: no credentials found for sections: %v\n", sections)
		os.Exit(exitNotFound)
	}

	fmt.Println(login.FormatDSN(database))
	os.Exit(exitSuccess)
}
