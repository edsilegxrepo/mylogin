// Command mylogin-connect verifies database connectivity and authentication for configured instances.
//
// Objective: Diagnostic utility to test and verify end-to-end database connectivity and authentication
// for source and target MySQL database instances configured in encrypted login profiles and option files.
//
// Core Components:
//   - run: Parses flags (-source, -target, -source-db, -target-db, -file, -dry-run, -version),
//     resolves database configurations, and performs connectivity checks.
//
// Functionality:
//   - Resolves source section from -source flag or MYSQL_HOST + "_" + MYSQL_DB_BACKUP_SVC.
//   - Resolves target section from -target flag or DB_LOGIN_CREDS.
//   - Establishes connection handles via Login.Open(database) and executes ping tests.
//   - Supports -dry-run mode for configuration syntax and credential validation without network traffic.
//
// Data Flow:
//
//	CLI Args / Environment -> run() -> mylogin.ReadResolvedLogin() -> Login.Open() -> Ping().
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	mylogin "github.com/edsilegxrepo/mylogin"
)

const (
	exitSuccess = 0
	exitUsage   = 2
	exitError   = 1
)

var version = "dev"

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mylogin-connect", flag.ContinueOnError)
	flags.SetOutput(stderr)

	defaultSource := os.Getenv("MYSQL_HOST") + "_" + os.Getenv("MYSQL_DB_BACKUP_SVC")
	if defaultSource == "_" {
		defaultSource = "client"
	}
	defaultTarget := os.Getenv("DB_LOGIN_CREDS")

	sourcePath := flags.String("source", defaultSource, "Source login-path section name")
	targetPath := flags.String("target", defaultTarget, "Target login-path section name")
	sourceDBName := flags.String("source-db", "goanydb", "Source database schema name")
	targetDBName := flags.String("target-db", "mftcustomdb", "Target database schema name")
	filePath := flags.String("file", mylogin.DefaultFile(), "Path to .mylogin.cnf file")
	dryRun := flags.Bool("dry-run", false, "Validate configuration and driver initialization without sending network ping")
	showVersion := flags.Bool("version", false, "Print version information and exit")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	if *showVersion {
		printFmt(stdout, "mylogin-connect version %s\n", version)
		return exitSuccess
	}

	// 1. Resolve and verify source database connection
	sourceLogin, err := mylogin.ReadResolvedLogin(*filePath, mylogin.DefaultOptionFile(), []string{mylogin.DefaultSection, *sourcePath})
	if err != nil {
		printFmt(stderr, "source Get failed: %v\n", err)
		return exitError
	}

	if *dryRun {
		if _, err := sourceLogin.Connector(*sourceDBName); err != nil {
			printFmt(stderr, "source connector creation failed: %v\n", err)
			return exitError
		}
		printLine(stdout, "source configuration valid")
	} else {
		sourceDB, err := sourceLogin.Open(*sourceDBName)
		if err != nil {
			printFmt(stderr, "source Open failed: %v\n", err)
			return exitError
		}
		defer func() { _ = sourceDB.Close() }()
		if err := sourceDB.Ping(); err != nil {
			printFmt(stderr, "source Ping failed: %v\n", err)
			return exitError
		}
		printLine(stdout, "source ping ok")
	}

	// 2. Resolve and verify target database connection if configured
	if *targetPath != "" {
		targetLogin, err := mylogin.ReadResolvedLogin(*filePath, mylogin.DefaultOptionFile(), []string{mylogin.DefaultSection, *targetPath})
		if err != nil {
			printFmt(stderr, "target Get failed: %v\n", err)
			return exitError
		}

		if *dryRun {
			if _, err := targetLogin.Connector(*targetDBName); err != nil {
				printFmt(stderr, "target connector creation failed: %v\n", err)
				return exitError
			}
			printLine(stdout, "target configuration valid")
		} else {
			targetDB, err := targetLogin.Open(*targetDBName)
			if err != nil {
				printFmt(stderr, "target Open failed: %v\n", err)
				return exitError
			}
			defer func() { _ = targetDB.Close() }()
			if err := targetDB.Ping(); err != nil {
				printFmt(stderr, "target Ping failed: %v\n", err)
				return exitError
			}
			printLine(stdout, "target ping ok")
		}
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
