// Command mylogin-dsn extracts credentials from .mylogin.cnf and formats them as a MySQL Data Source Name (DSN).
//
// Objective: Provide an operational command-line utility to convert MySQL login path configurations
// into standard go-sql-driver/mysql Data Source Names (DSN) suitable for database connection pools,
// scripting pipelines, and containerized microservice configurations.
//
// Core Components:
//   - Flag Parser: Configures options for input file, target database name, and version info.
//   - Error Handler: Categorizes filesystem and decryption errors into standard exit codes.
//   - Section Resolver: Resolves single or multiple sections (defaulting to "client") with precedence merging.
//   - DSN Formatter: Leverages mylogin.Login.FormatDSN for RFC-compliant URL escaping and socket/TCP transport selection.
//
// Functionality:
//   - DSN String Emission: Outputs standard [user[:password]@][protocol[(address)]]/[dbname][?param=value] strings.
//   - Database Selection: Appends target schema name if provided via -database flag.
//   - Multi-Section Merging: Inherits default client settings while overriding specific environment settings.
//
// Data Flow:
//
//	CLI Invocation -> Parse Flags (-file, -database, sections) -> ReadLogin ->
//	  [Decrypt & Merge Sections] -> Login.FormatDSN -> Emit DSN to stdout.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/edsilegxrepo/mylogin"
)

// Process exit codes conforming to standard CLI design practices.
const (
	exitSuccess     = 0 // DSN generated and emitted successfully
	exitUsage       = 2 // Invalid command-line arguments or flags
	exitFileError   = 3 // File system I/O error (not found, permission denied)
	exitFormatError = 4 // Corrupted file, invalid key, or decryption failure
	exitNotFound    = 5 // Requested sections not found or empty
)

var version = "dev"

// handleFileError distinguishes between file access errors and decryption/syntax errors,
// writing an informative message to stderr and returning the appropriate process exit code.
func handleFileError(cmd string, err error, stderr io.Writer) int {
	if os.IsNotExist(err) || os.IsPermission(err) {
		fmt.Fprintf(stderr, "%s: file error: %v\n", cmd, err)
		return exitFileError
	}
	fmt.Fprintf(stderr, "%s: decryption/parse error: %v\n", cmd, err)
	return exitFormatError
}

// run parses arguments, resolves configuration sections, and emits the formatted DSN.
//
// Execution Flow:
//  1. Initialize flag definitions (-database, -file, -version).
//  2. Resolve target configuration sections (defaulting to [client] if unspecified).
//  3. Decrypt and load credentials via mylogin.ReadLogin.
//  4. Check that resolved credentials are not empty.
//  5. Format and emit DSN string to stdout.
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
		return handleFileError("mylogin-dsn", err, stderr)
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
