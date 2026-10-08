// Package mylogin provides unit tests for internal option line parsing.
//
// Objective: Validate lexical parsing, quote stripping, and escape sequence handling
// for individual INI option lines within Login.parseLine.
//
// Core Components:
//   - TestParseLine: Table-driven validation covering bare strings, whitespace, double quotes,
//     embedded equality signs, and escaped quotes.
//
// Test Strategy:
//   - Table-Driven Testing: Iterate across a matrix of syntactically diverse line formats.
//   - Escaping Invariant: Ensure escaped double-quotes (\") are correctly converted to literal quotes (")
//     and surrounding container quotes are stripped.
//
// Functionality:
//   - Guarantees option values are accurately tokenized regardless of formatting variations.
//
// Data Flow:
//
//	Raw INI Line -> Login.parseLine -> Option Extraction & Sanitization -> Assert Field Value.
package mylogin

import "testing"

func TestParseLine(t *testing.T) {
	for _, test := range []struct {
		line string
		user string
	}{
		{`user = toto`, `toto`},
		{`user = toto titi`, `toto titi`},
		{`user = "toto"`, `toto`},
		{`user = "toto titi"`, `toto titi`},
		{`user = "toto = titi"`, `toto = titi`},
		{`user = "toto \" titi"`, `toto " titi`},
	} {
		var l Login
		err := l.parseLine(test.line)
		if err != nil {
			t.Errorf("%q: %v", test.line, err)
			continue
		}
		if *l.User != test.user {
			t.Errorf("%q: got %q, expected %q", test.line, *l.User, test.user)
		}
	}
}
