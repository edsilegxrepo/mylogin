// Command mylogin allows to dump the content of ~/.mylogin.cnf.
//
// Objective: Provide an operational command-line utility for inspecting, querying,
// transforming, modifying, and managing MySQL login path configuration files (.mylogin.cnf).
//
// Core Components:
//   - Subcommand Router: Dispatches set, remove/rm, and list/ls subcommands or falls back to dump/query.
//   - Output Format Engine: Polymorphic formatter interface (outputFormat) supporting replay, remove, JSON, and Go templates.
//   - Mutation Pipeline: High-level credential setters and removers using atomic Sections.WriteFile.
//   - Filter Stream Pipeline: Low-level streaming extraction of single INI sections using FilterSection.
//
// Functionality:
//   - Section Mutation: Add or update login path credentials (user, password, host, port, socket) via 'set'.
//   - Section Deletion: Remove existing login path entries via 'remove'.
//   - Section Enumeration: List all available section names via 'list'.
//   - Multi-Format Dumping: Format configurations as shell replay commands, removal scripts, JSON, or custom templates.
//   - Section Filtering: Fast streaming extraction of specific sections without parsing overhead.
//
// Data Flow:
//
//	CLI Invocation -> Argument Parsing -> Subcommand Dispatch or Format Determination ->
//	  [Read & Decrypt .mylogin.cnf] -> [AST / Stream Transform] -> [Emit to stdout / Atomic File Write].
//
// # Usage
//
//	mylogin [-file ~/.mylogin.cnf] [-replay | -remove | -json | -template=<template> | -templateln=<template>] [<section> ...]
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/edsilegxrepo/mylogin"
)

var version = "dev"

// Process exit codes conforming to standard CLI design practices.
const (
	exitSuccess     = 0 // Command completed successfully
	exitGeneral     = 1 // General runtime or execution error
	exitUsage       = 2 // Invalid command-line arguments or flags
	exitFileError   = 3 // File system I/O error (not found, permission denied)
	exitFormatError = 4 // Corrupted file, invalid key, or decryption failure
	exitNotFound    = 5 // Requested section not found in configuration
)

// outputFormat defines the interface for polymorphic CLI output formatters.
// It combines flag.Getter with custom printing and help descriptions.
type outputFormat interface {
	Help() (string, string)
	flag.Getter
	Print(w io.Writer, section *mylogin.Section) error
}

// outputFormatBool is a reusable flag.Getter implementation for boolean format toggles.
type outputFormatBool struct {
	bool
}

// IsBoolFlag informs flag.FlagSet that this flag accepts optional boolean values (-flag or -flag=true).
func (outputFormatBool) IsBoolFlag() bool {
	return true
}

// String returns the string representation of the boolean flag value.
func (f *outputFormatBool) String() string {
	return strconv.FormatBool(f.bool)
}

// Set parses a string representation into the boolean flag value.
func (f *outputFormatBool) Set(s string) error {
	ok, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	f.bool = ok
	return nil
}

// Get returns true if the flag was explicitly enabled, or nil if unset.
func (f *outputFormatBool) Get() interface{} {
	if !f.bool {
		return nil
	}
	return true
}

// formatReplay formats a configuration section into a mysql_config_editor set command.
// Note: passwords are not exported by this format for security reasons.
type formatReplay struct {
	outputFormatBool
}

func (formatReplay) Help() (string, string) {
	return "replay", "mysql_config_editor 'set' command format (note: password is not exported)"
}

// Print outputs the shell command line representing the given section.
func (formatReplay) Print(w io.Writer, section *mylogin.Section) error {
	args := []string{`mysql_config_editor`, `set`, `--skip-warn`, `-G`, section.Name}
	if section.Login.User != nil {
		args = append(args, `-u`, *section.Login.User)
	}
	if section.Login.Password != nil {
		args = append(args, `-p`)
	}
	if section.Login.Host != nil {
		args = append(args, `-h`, *section.Login.Host)
	}
	if section.Login.Port != nil {
		args = append(args, `-P`, *section.Login.Port)
	}
	if section.Login.Socket != nil {
		args = append(args, `-S`, *section.Login.Socket)
	}
	_, err := fmt.Fprintln(w, strings.Join(args, " "))
	return err
}

// formatRemove formats a configuration section into a mysql_config_editor remove command.
type formatRemove struct {
	outputFormatBool
}

func (formatRemove) Help() (string, string) {
	return "remove", "mysql_config_editor 'remove' command format"
}

// Print outputs the mysql_config_editor remove invocation for the given section.
func (formatRemove) Print(w io.Writer, section *mylogin.Section) error {
	_, err := fmt.Fprintln(w, "mysql_config_editor remove -G", section.Name)
	return err
}

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

// loginAsMap converts a Login instance into a generic map for JSON and template formatting.
func loginAsMap(login *mylogin.Login) map[string]interface{} {
	opts := login.Map()
	m := make(map[string]interface{}, len(opts))
	for k, v := range opts {
		m[k] = v
	}
	return m
}

// formatJSON emits configuration options as an indented JSON object.
type formatJSON struct {
	outputFormatBool
}

func (formatJSON) Help() (string, string) {
	return "json", "JSON format (note: section name is not exported)"
}

// Print marshals section options into pretty-printed JSON.
func (formatJSON) Print(w io.Writer, section *mylogin.Section) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(loginAsMap(&section.Login))
}

// formatTemplate executes a custom Go text/template against section options.
type formatTemplate struct {
	tmpl *template.Template
}

func (formatTemplate) Help() (string, string) {
	return "template", "text/template format (additional function: 'json')"
}

func (f *formatTemplate) String() string {
	if f.tmpl == nil {
		return ""
	}
	return "<template>"
}

// Set compiles the user-provided template string, injecting custom template helpers.
func (f *formatTemplate) Set(s string) error {
	tmpl, err := template.New("user-template").Funcs(
		template.FuncMap{
			"json": func(v interface{}) (string, error) {
				b, err := json.Marshal(v)
				if err != nil {
					return "", err
				}
				return string(b), nil
			},
		},
	).Parse(s)
	if err != nil {
		return err
	}
	(*f).tmpl = tmpl
	return nil
}

func (f *formatTemplate) Get() interface{} {
	if f.tmpl == nil {
		return nil
	}
	return f
}

// Print executes the template with a dictionary containing section options and metadata.
func (f *formatTemplate) Print(w io.Writer, section *mylogin.Section) error {
	m := loginAsMap(&section.Login)
	m["section"] = section.Name

	const sectionSuffix = "groupSuffix"
	switch {
	case strings.HasPrefix(section.Name, "mysql"):
		m[sectionSuffix] = section.Name[5:]
	case strings.HasPrefix(section.Name, "client"):
		m[sectionSuffix] = section.Name[6:]
	}

	return f.tmpl.Execute(w, m)
}

// formatTemplateLn wraps formatTemplate to guarantee an appended trailing newline.
type formatTemplateLn struct {
	formatTemplate
}

func (formatTemplateLn) Help() (string, string) {
	return "templateln", "text/template format (additional function: 'json') with trailing line break"
}

func (f *formatTemplateLn) Set(s string) error {
	return f.formatTemplate.Set(s + "\n")
}

// readPassword reads a single line from the given reader for password prompts.
func readPassword(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	if scanner.Scan() {
		return scanner.Text(), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", nil
}

// runSet implements the 'set' subcommand, creating or updating a login path entry.
//
// Workflow:
//  1. Parse flags for target file, section name, and connection parameters.
//  2. Resolve password from flag or interactive prompt.
//  3. Load existing configuration file if present.
//  4. Merge options into existing or new Section.
//  5. Persist configuration atomically with 0600 mode using Sections.WriteFile.
func runSet(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mylogin set", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var filename string
	flags.StringVar(&filename, "file", mylogin.DefaultFile(), "mylogin.cnf path")

	var loginPath string
	flags.StringVar(&loginPath, "login-path", mylogin.DefaultSection, "login path to set")
	flags.StringVar(&loginPath, "G", mylogin.DefaultSection, "login path (short)")

	var user string
	flags.StringVar(&user, "user", "", "username")
	flags.StringVar(&user, "u", "", "username (short)")

	var host string
	flags.StringVar(&host, "host", "", "hostname")
	flags.StringVar(&host, "h", "", "hostname (short)")

	var port string
	flags.StringVar(&port, "port", "", "port")
	flags.StringVar(&port, "P", "", "port (short)")

	var socket string
	flags.StringVar(&socket, "socket", "", "socket path")
	flags.StringVar(&socket, "S", "", "socket path (short)")

	var promptPassword bool
	flags.BoolVar(&promptPassword, "password", false, "prompt for password")
	flags.BoolVar(&promptPassword, "p", false, "prompt for password (short)")

	var plainPassword string
	flags.StringVar(&plainPassword, "pass", "", "password directly (non-interactive)")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	var password string
	if plainPassword != "" {
		password = plainPassword
	} else if promptPassword {
		fmt.Fprintf(stderr, "Enter password: ")
		var err error
		password, err = readPassword(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "mylogin: failed to read password: %v\n", err)
			return exitGeneral
		}
	}

	cleanPath := filepath.Clean(filename)
	var sections mylogin.Sections
	if _, err := os.Stat(cleanPath); err == nil {
		sections, err = mylogin.ReadSections(cleanPath)
		if err != nil {
			fmt.Fprintf(stderr, "mylogin: failed to read existing file: %v\n", err)
			return exitFormatError
		}
	}

	existing := sections.Login(loginPath)
	login := existing.Clone()
	if login == nil {
		login = new(mylogin.Login)
	}
	opts := map[string]string{
		"user":   user,
		"host":   host,
		"port":   port,
		"socket": socket,
	}
	for k, v := range opts {
		if v != "" {
			login.Set(k, v)
		}
	}
	if password != "" || promptPassword {
		login.SetPassword(password)
	}

	sections.Set(loginPath, *login)
	if err := sections.WriteFile(cleanPath); err != nil {
		fmt.Fprintf(stderr, "mylogin: failed to write %s: %v\n", cleanPath, err)
		return exitFileError
	}

	return exitSuccess
}

// runRemove implements the 'remove' subcommand, deleting a login path entry from the file.
func runRemove(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mylogin remove", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var filename string
	flags.StringVar(&filename, "file", mylogin.DefaultFile(), "mylogin.cnf path")

	var loginPath string
	flags.StringVar(&loginPath, "login-path", "", "login path to remove")
	flags.StringVar(&loginPath, "G", "", "login path (short)")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	if loginPath == "" && flags.NArg() > 0 {
		loginPath = flags.Arg(0)
	}
	if loginPath == "" {
		fmt.Fprintf(stderr, "mylogin: remove requires a login path name\n")
		return exitUsage
	}

	cleanPath := filepath.Clean(filename)
	sections, err := mylogin.ReadSections(cleanPath)
	if err != nil {
		fmt.Fprintf(stderr, "mylogin: failed to read %s: %v\n", cleanPath, err)
		return exitFileError
	}

	if !sections.Delete(loginPath) {
		fmt.Fprintf(stderr, "mylogin: section %q not found in %s\n", loginPath, cleanPath)
		return exitNotFound
	}

	if err := sections.WriteFile(cleanPath); err != nil {
		fmt.Fprintf(stderr, "mylogin: failed to write %s: %v\n", cleanPath, err)
		return exitFileError
	}

	return exitSuccess
}

// runList implements the 'list' subcommand, outputting all login path names present in the file.
func runList(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mylogin list", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var filename string
	flags.StringVar(&filename, "file", mylogin.DefaultFile(), "mylogin.cnf path")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	cleanPath := filepath.Clean(filename)
	sections, err := mylogin.ReadSections(cleanPath)
	if err != nil {
		fmt.Fprintf(stderr, "mylogin: failed to read %s: %v\n", cleanPath, err)
		return exitFileError
	}

	for _, name := range sections.Names() {
		fmt.Fprintln(stdout, name)
	}
	return exitSuccess
}

// run dispatches command execution using os.Stdin as default input stream.
func run(args []string, stdout, stderr io.Writer) int {
	return runWithStdin(args, os.Stdin, stdout, stderr)
}

// runWithStdin parses CLI subcommands, options, and handles file extraction and formatting.
//
// Execution Flow:
//  1. Check for subcommands ("set", "remove"/"rm", "list"/"ls") and dispatch to handler.
//  2. If no subcommand, parse general flags (-file, -version, format flags).
//  3. Validate format mutual exclusion (only one formatter allowed per invocation).
//  4. If format selected: load target sections and render using selected formatter.
//  5. If no format selected: decrypt stream and emit raw INI or stream-filter single section.
func runWithStdin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "set":
			return runSet(args[1:], stdin, stdout, stderr)
		case "remove", "rm":
			return runRemove(args[1:], stdout, stderr)
		case "list", "ls":
			return runList(args[1:], stdout, stderr)
		}
	}

	flags := flag.NewFlagSet("mylogin", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var filename string
	flags.StringVar(&filename, "file", mylogin.DefaultFile(), "mylogin.cnf path")

	formats := []outputFormat{
		&formatReplay{},
		&formatRemove{},
		&formatJSON{},
		&formatTemplate{},
		&formatTemplateLn{},
	}

	for _, fmtFlag := range formats {
		name, usage := fmtFlag.Help()
		flags.Var(fmtFlag, name, usage)
	}

	var showVersion bool
	flags.BoolVar(&showVersion, "version", false, "display version and exit")
	flags.BoolVar(&showVersion, "V", false, "display version (short)")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	if showVersion {
		fmt.Fprintf(stdout, "mylogin version %s\n", version)
		return exitSuccess
	}

	var selectedFormat outputFormat
	for _, ft := range formats {
		f := ft.Get()
		if f == nil {
			continue
		}
		if selectedFormat != nil {
			h1, _ := ft.Help()
			h2, _ := selectedFormat.Help()
			fmt.Fprintf(stderr, "mylogin: options -%s and -%s are mutually exclusive.\n", h1, h2)
			return exitUsage
		}
		selectedFormat = ft
	}

	if selectedFormat != nil {
		var targets []*mylogin.Section
		if flags.NArg() != 0 {
			for _, name := range flags.Args() {
				login, err := mylogin.ReadLogin(filename, []string{name})
				if err != nil {
					return handleFileError("mylogin", err, stderr)
				}
				if login.IsEmpty() {
					fmt.Fprintf(stderr, "mylogin: section %q does not exist\n", name)
					return exitNotFound
				}
				targets = append(targets, &mylogin.Section{Name: name, Login: *login})
			}
		} else {
			sections, err := mylogin.ReadSections(filename)
			if err != nil {
				return handleFileError("mylogin", err, stderr)
			}
			for i := range sections {
				targets = append(targets, &sections[i])
			}
		}

		for _, sec := range targets {
			if err := selectedFormat.Print(stdout, sec); err != nil {
				fmt.Fprintf(stderr, "mylogin: print error: %v\n", err)
				return exitGeneral
			}
		}
	} else {
		cleanPath := filepath.Clean(filename)
		file, err := os.Open(cleanPath) // #nosec G304 -- CLI utility intentionally reads user-specified path
		if err != nil {
			return handleFileError("mylogin", err, stderr)
		}
		defer file.Close()

		f, err := mylogin.Decode(bufio.NewReader(file))
		if err != nil {
			fmt.Fprintf(stderr, "mylogin: decode error: %v\n", err)
			return exitFormatError
		}
		rd := f.PlainText()

		if flags.NArg() > 0 {
			rd = mylogin.FilterSection(rd, flags.Arg(0))
		}

		if _, err := io.Copy(stdout, rd); err != nil {
			fmt.Fprintf(stderr, "mylogin: output error: %v\n", err)
			return exitGeneral
		}
	}

	return exitSuccess
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
