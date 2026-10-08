// Objective: Provide discovery, parsing, and extraction of system and user-level MySQL
// plaintext option files (e.g. ~/.my.cnf or %APPDATA%\MySQL\.my.cnf) to supply foundational
// [client] defaults beneath encrypted .mylogin.cnf sections.
//
// Core Components:
//   - DefaultOptionFile: Discovers the platform-appropriate option file path, respecting environment overrides.
//   - DefaultClientDefaults: Reads the [client] section from the discovered default option file.
//   - ReadClientDefaults: Safely reads and parses the [client] section from an arbitrary option file path.
//
// Functionality:
//   - Discovers default option file path via MYSQL_TEST_OPTION_FILE or OS-specific convention.
//   - Gracefully handles missing files by returning an empty Login struct with nil error (absent defaults).
//   - Reuses the shared INI parser (Parse) to extract the [client] section and discard server-specific sections.
//
// Data Flow:
//
//	Option File Path -> os.Open -> Parse(f) -> Sections.Merge(["client"]) -> *Login (Client Defaults)
package mylogin

import (
	"errors"
	"os"
	"path/filepath"
)

// DefaultOptionFile returns the path to the default MySQL plaintext option file.
// On Unix-like systems this is typically ~/.my.cnf. On Windows, this is typically
// %APPDATA%\MySQL\.my.cnf.
//
// If the environment variable MYSQL_TEST_OPTION_FILE is set
// that path is returned instead.
func DefaultOptionFile() string {
	// Check for testing or custom runtime environment override first.
	f := os.Getenv("MYSQL_TEST_OPTION_FILE")
	if len(f) != 0 {
		return f
	}
	// Fall back to operating system specific path resolution.
	return platformDefaultOptionFile()
}

// DefaultClientDefaults reads the [client] section from the default plaintext MySQL option file.
// Missing files are treated as absent defaults and return an empty Login with nil error.
func DefaultClientDefaults() (*Login, error) {
	return ReadClientDefaults(DefaultOptionFile())
}

// ReadClientDefaults reads the [client] section from a plaintext MySQL option file.
// If filename is empty or the file does not exist, it returns an empty Login and nil error.
// If the file exists but cannot be parsed, it returns an error.
func ReadClientDefaults(filename string) (*Login, error) {
	// If path is empty, treat as omitted defaults rather than opening current working directory
	if filename == "" {
		return &Login{}, nil
	}

	// Clean the path to eliminate relative segments and normalize separators.
	cleanPath := filepath.Clean(filename)
	f, err := os.Open(cleanPath) // #nosec G304 -- library intentionally reads caller-specified configuration path
	if err != nil {
		// Canonical MySQL behaviour: if the option file does not exist, proceed silently without defaults.
		if errors.Is(err, os.ErrNotExist) {
			return &Login{}, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// Parse the INI format content into AST sections.
	sections, err := Parse(f)
	if err != nil {
		return nil, err
	}

	// Extract only the default "client" group; non-client groups (e.g., [mysqld]) are omitted.
	login := sections.Merge([]string{DefaultSection})
	if login == nil {
		return &Login{}, nil
	}
	return login, nil
}
