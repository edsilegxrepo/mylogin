// Command mylogin allows to dump the content of ~/.mylogin.cnf.
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
	"strconv"
	"strings"
	"text/template"

	"github.com/edsilegxrepo/myloginpath"
)

const (
	exitSuccess     = 0
	exitGeneral     = 1
	exitUsage       = 2
	exitFileError   = 3
	exitFormatError = 4
	exitNotFound    = 5
)

type outputFormat interface {
	Help() (string, string)
	flag.Getter
	Print(w io.Writer, section *mylogin.Section) error
}

type outputFormatBool struct {
	bool
}

func (outputFormatBool) IsBoolFlag() bool {
	return true
}

func (f *outputFormatBool) String() string {
	return strconv.FormatBool(f.bool)
}

func (f *outputFormatBool) Set(s string) error {
	ok, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	f.bool = ok
	return nil
}

func (f *outputFormatBool) Get() interface{} {
	if !f.bool {
		return nil
	}
	return true
}

type formatReplay struct {
	outputFormatBool
}

func (formatReplay) Help() (string, string) {
	return "replay", "mysql_config_editor 'set' command format (note: password is not exported)"
}

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

type formatRemove struct {
	outputFormatBool
}

func (formatRemove) Help() (string, string) {
	return "remove", "mysql_config_editor 'remove' command format"
}

func (formatRemove) Print(w io.Writer, section *mylogin.Section) error {
	_, err := fmt.Fprintln(w, "mysql_config_editor remove -G", section.Name)
	return err
}

func loginAsMap(login *mylogin.Login) map[string]interface{} {
	m := make(map[string]interface{})
	for _, x := range []struct {
		key   string
		value *string
	}{
		{"user", login.User},
		{"password", login.Password},
		{"host", login.Host},
		{"socket", login.Socket},
		{"port", login.Port},
	} {
		if x.value != nil {
			m[x.key] = *x.value
		}
	}
	// Include any arbitrary extra client options
	for k, v := range login.Extra {
		m[k] = v
	}
	return m
}

type formatJSON struct {
	outputFormatBool
}

func (formatJSON) Help() (string, string) {
	return "json", "JSON format (note: section name is not exported)"
}

func (formatJSON) Print(w io.Writer, section *mylogin.Section) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(loginAsMap(&section.Login))
}

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

type formatTemplateLn struct {
	formatTemplate
}

func (formatTemplateLn) Help() (string, string) {
	return "templateln", "text/template format (additional function: 'json') with trailing line break"
}

func (f *formatTemplateLn) Set(s string) error {
	return f.formatTemplate.Set(s + "\n")
}

func run(args []string, stdout, stderr io.Writer) int {
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

	if err := flags.Parse(args); err != nil {
		return exitUsage
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
		if flags.NArg() != 0 {
			for _, name := range flags.Args() {
				login, err := mylogin.ReadLogin(filename, []string{name})
				if err != nil {
					if os.IsNotExist(err) || os.IsPermission(err) {
						fmt.Fprintf(stderr, "mylogin: file error: %v\n", err)
						return exitFileError
					}
					fmt.Fprintf(stderr, "mylogin: decryption/parse error: %v\n", err)
					return exitFormatError
				}
				if login.IsEmpty() {
					fmt.Fprintf(stderr, "mylogin: section %q does not exist\n", name)
					return exitNotFound
				}

				if err := selectedFormat.Print(stdout, &mylogin.Section{Name: name, Login: *login}); err != nil {
					fmt.Fprintf(stderr, "mylogin: print error: %v\n", err)
					return exitGeneral
				}
			}
		} else {
			sections, err := mylogin.ReadSections(filename)
			if err != nil {
				if os.IsNotExist(err) || os.IsPermission(err) {
					fmt.Fprintf(stderr, "mylogin: file error: %v\n", err)
					return exitFileError
				}
				fmt.Fprintf(stderr, "mylogin: decryption/parse error: %v\n", err)
				return exitFormatError
			}

			for i := range sections {
				if err := selectedFormat.Print(stdout, &sections[i]); err != nil {
					fmt.Fprintf(stderr, "mylogin: print error: %v\n", err)
					return exitGeneral
				}
			}
		}
	} else {
		file, err := os.Open(filename)
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				fmt.Fprintf(stderr, "mylogin: file error: %v\n", err)
				return exitFileError
			}
			fmt.Fprintf(stderr, "mylogin: error: %v\n", err)
			return exitFileError
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
