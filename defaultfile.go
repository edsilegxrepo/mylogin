//go:build !windows
// +build !windows

package mylogin

import (
	"os"
	"path/filepath"
)

// Objective: Resolve the canonical filesystem path to the user's MySQL option file
// on POSIX-compliant operating systems (Linux, macOS, BSD).
//
// Core Component: platformDefaultFile.
//
// Functionality:
//   - Identifies the current user's home directory using standard library os.UserHomeDir.
//   - Falls back to the HOME environment variable if directory resolution fails.
//   - Joins the resolved home directory path with the standard hidden file name ".mylogin.cnf".
//
// Data Flow:
//
//	OS User Account / Environment ($HOME) -> Path Resolution -> Canonical Absolute Path String.
func platformDefaultFile() string {
	// Attempt standardized user home directory lookup
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".mylogin.cnf")
	}

	// Fallback to legacy environment variable expansion if UserHomeDir returns an error or empty string
	return os.ExpandEnv(`${HOME}/.mylogin.cnf`)
}
