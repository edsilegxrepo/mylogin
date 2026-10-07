//go:build windows
// +build windows

package mylogin

import (
	"os"
	"path/filepath"
)

func platformDefaultFile() string {
	if appData := os.Getenv("APPDATA"); appData != "" {
		return filepath.Join(appData, "MySQL", ".mylogin.cnf")
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, "AppData", "Roaming", "MySQL", ".mylogin.cnf")
	}
	return os.ExpandEnv(`${APPDATA}\MySQL\.mylogin.cnf`)
}
