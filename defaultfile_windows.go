//go:build windows
// +build windows

package mylogin

import (
	"os"
	"path/filepath"
)

// Objective: Resolve the canonical filesystem path to the user's MySQL option file
// on Microsoft Windows operating systems.
//
// Core Component: platformDefaultFile.
//
// Functionality:
//   - Follows Oracle MySQL conventions for Windows by checking the APPDATA environment variable.
//   - Constructs the standard path %APPDATA%\MySQL\.mylogin.cnf.
//   - Falls back to os.UserHomeDir() (typically C:\Users\<User>) under the AppData\Roaming subdirectory.
//   - Provides a final fallback expanding the APPDATA environment variable.
//
// Data Flow:
//
//	Windows Environment (%APPDATA% / UserProfile) -> Path Composition -> Canonical File Path.
func platformDefaultFile() string {
	// Standard Windows location: %APPDATA%\MySQL\.mylogin.cnf
	if appData := os.Getenv("APPDATA"); appData != "" {
		return filepath.Join(appData, "MySQL", ".mylogin.cnf")
	}

	// Fallback using standard Go user home directory resolution
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, "AppData", "Roaming", "MySQL", ".mylogin.cnf")
	}

	// Final fallback via environment variable template expansion
	return os.ExpandEnv(`${APPDATA}\MySQL\.mylogin.cnf`)
}
