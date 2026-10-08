package mylogin

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Objective: Provide an Abstract Syntax Tree (AST) for the complete contents of
// a mylogin.cnf file, enforcing syntax validation, injection mitigation,
// deterministic ordering, and canonical INI serialization.
//
// Core Components:
//   - Section: Single named configuration block containing associated Login options.
//   - Sections: Slice of Section structs representing the ordered AST of the file.
//   - Validate: Injection defenses verifying section names and option keys.
//   - escapeValue / WriteTo: Canonical serialization matching MySQL 8.0.24+ standards.
//   - WriteFile: High-level atomic file encryption helper.
//
// Functionality:
//   - Querying: Login(name), Has(name), Names().
//   - Mutation: Set(name, login), Delete(name), Clone().
//   - Aggregation: Merge(sectionNames) performing precedence-based merging.
//   - Persistence: Format() string generator and WriteFile(filename) atomic writer.
//
// Data Flow:
//   Decrypted Stream -> Parse -> Sections AST -> Mutation/Query -> WriteTo/Format -> Encode -> Disk.

var (
	// ErrInvalidSectionName is returned when a section name contains invalid characters.
	ErrInvalidSectionName = errors.New("invalid section name: contains illegal characters (newlines or brackets)")

	// ErrInvalidOptionKey is returned when an option key contains illegal characters.
	ErrInvalidOptionKey = errors.New("invalid option key: contains illegal characters (newlines, equals, or control characters)")
)

// Section represents one section of the plaintext content of mylogin.cnf.
type Section struct {
	Name  string `json:"name"`  // Section header name, e.g. "client" or "production"
	Login Login  `json:"login"` // Structured credential options defined in this section
}

// Clone returns an independent, deep copy of the Section.
func (s *Section) Clone() Section {
	return Section{
		Name:  s.Name,
		Login: *s.Login.Clone(),
	}
}

// Validate verifies that the section name and its options do not contain injection characters.
// Rejects bracket literals, carriage returns, null bytes, and delimiter characters.
func (s *Section) Validate() error {
	trimmed := strings.TrimSpace(s.Name)
	if trimmed == "" {
		return fmt.Errorf("%w: name cannot be empty", ErrInvalidSectionName)
	}
	if strings.ContainsAny(trimmed, "[]\r\n\x00") {
		return fmt.Errorf("%w: %q", ErrInvalidSectionName, s.Name)
	}

	validateKey := func(k string) error {
		kTrimmed := strings.TrimSpace(k)
		if kTrimmed == "" || strings.ContainsAny(kTrimmed, "=\r\n\x00#;") {
			return fmt.Errorf("%w: %q", ErrInvalidOptionKey, k)
		}
		return nil
	}

	for k := range s.Login.Extra {
		if err := validateKey(k); err != nil {
			return err
		}
	}
	return nil
}

// escapeValue properly escapes quotes and backslashes for MySQL option files.
// Complies with MySQL 8.0.24+ formatting standards (enclosed in double quotes with \ and " escaped).
func escapeValue(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return `"` + r.Replace(v) + `"`
}

// WriteTo writes the section in canonical, injection-safe MySQL option file format.
// Validates syntax before emitting bytes to w.
func (s *Section) WriteTo(w io.Writer) (int64, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}

	var buf bytes.Buffer
	buf.WriteString("[" + strings.TrimSpace(s.Name) + "]\n")

	// Helper closure to write non-nil options with canonical escaping
	writeOpt := func(k string, v *string) {
		if v != nil {
			buf.WriteString(k + " = " + escapeValue(*v) + "\n")
		}
	}

	writeOpt("user", s.Login.User)
	writeOpt("password", s.Login.Password)
	writeOpt("host", s.Login.Host)
	writeOpt("port", s.Login.Port)
	writeOpt("socket", s.Login.Socket)

	// Write any additional non-standard options
	for k, v := range s.Login.Extra {
		buf.WriteString(strings.TrimSpace(k) + " = " + escapeValue(v) + "\n")
	}

	n, err := w.Write(buf.Bytes())
	return int64(n), err
}

// Sections represents the structured content of the plaintext of mylogin.cnf.
// It is an ordered slice of Section instances.
type Sections []Section

// Login returns the Login from the section with the given name, or nil if not found.
func (sections Sections) Login(section string) *Login {
	for i := range sections {
		if sections[i].Name == section {
			return &sections[i].Login
		}
	}
	return nil
}

// Has reports whether a section with the given name exists in the collection.
func (sections Sections) Has(section string) bool {
	return sections.Login(section) != nil
}

// Names returns the names of all sections in the order they appear in the file.
func (sections Sections) Names() []string {
	names := make([]string, len(sections))
	for i, s := range sections {
		names[i] = s.Name
	}
	return names
}

// Set adds or replaces the section with the given name.
// Existing sections with matching names are updated in-place; new sections are appended.
func (sections *Sections) Set(name string, login Login) {
	for i := range *sections {
		if (*sections)[i].Name == name {
			(*sections)[i].Login = *login.Clone()
			return
		}
	}
	*sections = append(*sections, Section{
		Name:  name,
		Login: *login.Clone(),
	})
}

// Delete removes the section with the given name and reports whether it existed.
func (sections *Sections) Delete(name string) bool {
	for i, s := range *sections {
		if s.Name == name {
			*sections = append((*sections)[:i], (*sections)[i+1:]...)
			return true
		}
	}
	return false
}

// Clone returns an independent, deep copy of Sections.
func (sections Sections) Clone() Sections {
	cp := make(Sections, len(sections))
	for i, s := range sections {
		cp[i] = s.Clone()
	}
	return cp
}

// Validate verifies all sections and their options against syntax injection.
func (sections Sections) Validate() error {
	for i := range sections {
		if err := sections[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// WriteTo writes all sections sequentially in canonical, injection-safe MySQL option file format.
func (sections Sections) WriteTo(w io.Writer) (int64, error) {
	var total int64
	for i := range sections {
		n, err := sections[i].WriteTo(w)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Format returns the canonical plaintext string representation of all sections.
func (sections Sections) Format() (string, error) {
	var buf bytes.Buffer
	_, err := sections.WriteTo(&buf)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// WriteFile safely and atomically encodes the sections to an encrypted file with 0600 permissions.
func (sections Sections) WriteFile(filename string) error {
	formatted, err := sections.Format()
	if err != nil {
		return err
	}
	return WriteFile(filename, strings.NewReader(formatted))
}

// Merge returns a single Login which is the result of the ordered merge
// of the sections with the given names (see Login.Merge).
// For each option, the last section that has a value takes precedence.
func (sections Sections) Merge(sectionNames []string) (login *Login) {
	for _, s := range sectionNames {
		if s == "" {
			s = DefaultSection
		}
		l := sections.Login(s)
		if l.IsEmpty() {
			continue
		}
		if login == nil {
			login = new(Login)
		}
		login.Merge(l)
	}

	return
}
