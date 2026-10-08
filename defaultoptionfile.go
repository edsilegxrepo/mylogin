//go:build !windows
// +build !windows

package mylogin

import (
	"os"
	"path/filepath"
)

// Objective: Resolve the canonical filesystem path to the user's MySQL plaintext option file
// on Unix-like (POSIX / macOS / Linux) operating systems.
//
// Core Component: platformDefaultOptionFile.
//
// Functionality:
//   - Follows canonical MySQL CLI conventions by checking ~/.my.cnf in the user's home directory.
//   - Uses os.UserHomeDir() with a fallback expanding the $HOME environment variable.
//
// Data Flow:
//
//	User Home Directory ($HOME / os.UserHomeDir) -> filepath.Join -> ~/.my.cnf File Path.
func platformDefaultOptionFile() string {
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".my.cnf")
	}
	return os.ExpandEnv(`${HOME}/.my.cnf`)
}
