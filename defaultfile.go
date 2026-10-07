//go:build !windows
// +build !windows

package mylogin

import (
	"os"
	"path/filepath"
)

func platformDefaultFile() string {
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".mylogin.cnf")
	}
	return os.ExpandEnv(`${HOME}/.mylogin.cnf`)
}
