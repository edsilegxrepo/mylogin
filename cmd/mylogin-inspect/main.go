// Command mylogin-inspect inspects resolved configuration values and cascading defaults.
//
// Objective: Diagnostic inspection utility to inspect resolved configuration values,
// cascading option file defaults, and extra parameters (including TLS options) without exposing cleartext passwords.
//
// Core Components:
//   - run: Parses flags (-file, -option-file, -version), resolves target login section, and prints redacted field inventory.
//   - deref: Safe string pointer dereferencing helper returning empty string for nil pointers.
//
// Functionality:
//   - Prints the resolved path to the active MySQL plaintext option file (mylogin.DefaultOptionFile()).
//   - Merges option file defaults with the encrypted login-path section using mylogin.ReadResolvedLogin.
//   - Displays connection parameters (user, host, port, socket, password presence) and sorted extra key-value pairs.
//
// Data Flow:
//
//	CLI Args -> Flag Parsing -> ReadResolvedLogin -> Field Extraction -> Redacted Console Output.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	mylogin "github.com/edsilegxrepo/mylogin"
)

const (
	exitSuccess = 0
	exitUsage   = 2
	exitError   = 1
)

var version = "dev"

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mylogin-inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)

	filePath := flags.String("file", mylogin.DefaultFile(), "Path to .mylogin.cnf file")
	optionPath := flags.String("option-file", mylogin.DefaultOptionFile(), "Path to plaintext .my.cnf option file")
	showVersion := flags.Bool("version", false, "Print version information and exit")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	if *showVersion {
		printFmt(stdout, "mylogin-inspect version %s\n", version)
		return exitSuccess
	}

	targetSection := "client"
	if flags.NArg() > 0 {
		targetSection = flags.Arg(0)
	} else if env := os.Getenv("MYSQL_HOST") + "_" + os.Getenv("MYSQL_DB_BACKUP_SVC"); env != "_" {
		targetSection = env
	}

	printFmt(stdout, "default option file: %s\n", *optionPath)

	login, err := mylogin.ReadResolvedLogin(*filePath, *optionPath, []string{mylogin.DefaultSection, targetSection})
	if err != nil {
		printFmt(stderr, "Get failed: %v\n", err)
		return exitError
	}

	printFmt(stdout, "resolved user: %s\n", deref(login.User))
	printFmt(stdout, "resolved host: %s\n", deref(login.Host))
	printFmt(stdout, "resolved port: %s\n", deref(login.Port))
	printFmt(stdout, "resolved socket: %s\n", deref(login.Socket))
	printFmt(stdout, "has password: %t\n", login.Password != nil && *login.Password != "")

	keys := make([]string, 0, len(login.Extra))
	for k := range login.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	printLine(stdout, "extra keys:")
	for _, k := range keys {
		printFmt(stdout, "  %s=%s\n", k, login.Extra[k])
	}
	return exitSuccess
}

func printLine(w io.Writer, a ...any) {
	_, _ = fmt.Fprintln(w, a...)
}

func printFmt(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// deref safely returns the dereferenced string or an empty string if nil.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
