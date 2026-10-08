//go:build windows
// +build windows

package mylogin

import (
	"os"
	"path/filepath"
)

// Objective: Resolve the canonical filesystem path to the user's MySQL plaintext option file
// on Microsoft Windows operating systems.
//
// Core Component: platformDefaultOptionFile.
//
// Functionality:
//   - Follows Oracle MySQL conventions on Windows by checking %APPDATA%\MySQL\.my.cnf.
//   - Falls back to os.UserHomeDir() under AppData\Roaming\MySQL\.my.cnf.
//   - Provides a final fallback expanding the APPDATA environment variable.
//
// Data Flow:
//
//	Windows Environment (%APPDATA% / UserProfile) -> Path Composition -> Canonical File Path.
func platformDefaultOptionFile() string {
	// 1. Primary Windows resolution: %APPDATA%\MySQL\.my.cnf
	if appData := os.Getenv("APPDATA"); appData != "" {
		return filepath.Join(appData, "MySQL", ".my.cnf")
	}

	// 2. Fallback when APPDATA is unset: derive from user profile home directory
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, "AppData", "Roaming", "MySQL", ".my.cnf")
	}

	// 3. Environment expansion fallback
	return os.ExpandEnv(`${APPDATA}\MySQL\.my.cnf`)
}
