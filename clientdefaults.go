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
	"strings"
)

// GlobalOptionFiles returns a list of discovered, accessible system-wide MySQL option files
// in canonical lookup order (e.g. /etc/my.cnf, /etc/mysql/my.cnf, /etc/my-client.cnf).
// Discovery is skipped if MYSQL_TEST_OPTION_FILE is set (hermetic test isolation) or if
// MYSQL_GLOBAL_OPTION_FILE is explicitly set to "" or "none".
// If MYSQL_GLOBAL_OPTION_FILE is set to a specific file, that file is returned if it exists.
// Permission errors on auto-discovered global files are ignored safely.
func GlobalOptionFiles() []string {
	// Hermetic test boundary: do not probe host system /etc files if test option file is active
	if testOpt := os.Getenv("MYSQL_TEST_OPTION_FILE"); len(testOpt) != 0 {
		return nil
	}

	// Explicit override check
	if explicit := os.Getenv("MYSQL_GLOBAL_OPTION_FILE"); explicit != "" {
		if strings.EqualFold(explicit, "none") || explicit == "" {
			return nil
		}
		cleanPath := filepath.Clean(explicit)
		if _, err := os.Stat(cleanPath); err == nil { // #nosec G703,G304 -- library intentionally checks caller-specified global option file path
			return []string{cleanPath}
		}
		return nil
	}

	candidates := platformGlobalOptionCandidates()
	var found []string
	seen := make(map[string]struct{})
	for _, c := range candidates {
		clean := filepath.Clean(c)
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}

		info, err := os.Stat(clean)
		if err != nil {
			// Permission or not-exist errors on global candidates are non-fatal
			continue
		}
		if !info.IsDir() {
			// Test readability without leaking open handles
			f, err := os.Open(clean) // #nosec G304
			if err == nil {
				_ = f.Close()
				found = append(found, clean)
			}
		}
	}
	return found
}

// DefaultOptionFile returns the path to the default MySQL plaintext option file.
// On Unix-like systems this is typically ~/.my.cnf. On Windows, this is typically
// %APPDATA%\MySQL\.my.cnf.
//
// If the environment variable MYSQL_TEST_OPTION_FILE or MYSQL_OPTION_FILE is set
// that path is returned instead.
func DefaultOptionFile() string {
	// Check for testing or custom runtime environment override first.
	if f := os.Getenv("MYSQL_TEST_OPTION_FILE"); len(f) != 0 {
		return f
	}
	if f := os.Getenv("MYSQL_OPTION_FILE"); len(f) != 0 {
		return f
	}
	// Fall back to operating system specific path resolution.
	return platformDefaultOptionFile()
}

// DefaultOptionFiles returns the ordered cascade of all existing plaintext option files:
// [global files..., user option file].
func DefaultOptionFiles() []string {
	files := GlobalOptionFiles()
	userFile := DefaultOptionFile()
	if userFile != "" {
		if os.Getenv("MYSQL_TEST_OPTION_FILE") != "" || os.Getenv("MYSQL_OPTION_FILE") != "" {
			files = append(files, userFile)
		} else if info, err := os.Stat(userFile); err == nil && !info.IsDir() {
			files = append(files, userFile)
		}
	}
	return files
}

// DefaultClientDefaults reads the [client] section from the default plaintext MySQL option file.
// Missing files are treated as absent defaults and return an empty Login with nil error.
func DefaultClientDefaults() (*Login, error) {
	return ReadClientDefaults(DefaultOptionFile())
}

// ReadClientDefaultsHierarchy reads and merges the [client] section across multiple option files.
// Files are processed in the order given: earlier files provide base defaults, later files override them.
// Files that do not exist or are unreadable due to permission errors are gracefully skipped.
func ReadClientDefaultsHierarchy(filenames []string) (*Login, error) {
	merged := &Login{}
	for _, filename := range filenames {
		if filename == "" {
			continue
		}
		login, err := ReadClientDefaults(filename)
		if err != nil {
			return nil, err
		}
		if login != nil && !login.IsEmpty() {
			merged.Merge(login)
		}
	}
	return merged, nil
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
		// Canonical MySQL behaviour: if the option file does not exist or has permission restrictions, proceed silently without defaults.
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
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
