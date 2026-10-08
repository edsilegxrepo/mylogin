package mylogin_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	mylogin "github.com/edsilegxrepo/mylogin"
	_ "github.com/go-sql-driver/mysql"
)

// ExampleDefault demonstrates reading the default [client] section from ~/.mylogin.cnf.
func ExampleDefault() {
	login, err := mylogin.Default()
	if err != nil {
		log.Printf("No default login path: %v", err)
		return
	}

	// Login credentials can be used or inspected safely
	if login.User != nil && login.Host != nil {
		fmt.Printf("User: %s, Host: %s\n", *login.User, *login.Host)
	}
}

// ExampleGet demonstrates reading a specific login-path section from ~/.mylogin.cnf.
func ExampleGet() {
	// Read credentials for the "analytics" login path
	login, err := mylogin.Get("analytics")
	if err != nil {
		log.Printf("Analytics login path not found: %v", err)
		return
	}

	if login.User != nil && login.Host != nil {
		fmt.Printf("User: %s, Host: %s\n", *login.User, *login.Host)
	}
}

// ExampleLogin_Open demonstrates establishing a direct *sql.DB handle using Login.Open.
// This completely bypasses DSN string construction, preventing plaintext credentials
// from appearing in logs or error traces.
func ExampleLogin_Open() {
	login, err := mylogin.Get("client")
	if err != nil {
		log.Printf("Failed to load login path: %v", err)
		return
	}

	// Directly open *sql.DB handle to database "production_db"
	db, err := login.Open("production_db")
	if err != nil {
		log.Printf("Failed to open connection handle: %v", err)
		return
	}
	defer db.Close()
}

// ExampleLogin_Config demonstrates fine-tuning MySQL driver connection parameters
// via *mysql.Config.
func ExampleLogin_Config() {
	login, err := mylogin.Get("client")
	if err != nil {
		log.Printf("Failed to load login path: %v", err)
		return
	}

	cfg := login.Config()

	// Customize driver settings
	cfg.DBName = "app_db"
	cfg.ParseTime = true
	cfg.AllowNativePasswords = true

	fmt.Printf("Connection target: %s\n", cfg.Addr)
}

// ExampleLogin_RedactedDSN demonstrates obtaining a safe, redacted DSN suitable
// for application logging and telemetry where passwords are never exposed.
func ExampleLogin_RedactedDSN() {
	var login mylogin.Login
	login.SetUser("app_user")
	login.SetPassword("super_secret_password")
	login.SetHost("db.example.internal")
	login.SetPort("3306")

	// RedactedDSN masks the password with asterisks
	fmt.Println(login.RedactedDSN())
	// Output:
	// app_user:******@tcp(db.example.internal:3306)/
}

// ExampleSections_WriteFile demonstrates programmatically creating, modifying,
// and encrypting a ~/.mylogin.cnf file using pure Go.
func ExampleSections_WriteFile() {
	tmpDir, err := os.MkdirTemp("", "mylogin-example-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	targetFile := filepath.Join(tmpDir, ".mylogin.cnf")

	// Parse unencrypted configuration lines
	raw := `
[client]
host = "mysql.internal"
user = "app"
password = "secretpassword"

[reporting]
host = "replica.internal"
user = "analyst"
password = "reportingpassword"
`
	sections, err := mylogin.Parse(strings.NewReader(raw))
	if err != nil {
		log.Fatalf("Parse error: %v", err)
	}

	// Encrypt and write to file with restrictive 0600 permissions
	if err := sections.WriteFile(targetFile); err != nil {
		log.Fatalf("WriteFile error: %v", err)
	}

	// Verify reading back from the encrypted file
	readSections, err := mylogin.ReadSections(targetFile)
	if err != nil {
		log.Fatalf("ReadSections error: %v", err)
	}

	fmt.Println("Configured sections:", strings.Join(readSections.Names(), ", "))
	// Output:
	// Configured sections: client, reporting
}
