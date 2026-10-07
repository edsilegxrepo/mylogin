//go:build integration
// +build integration

package mylogin_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/edsilegxrepo/myloginpath"
	_ "github.com/go-sql-driver/mysql"
)

type liveServer struct {
	Socket   string
	Host     string
	Port     int
	User     string
	Password string
}

func (s *liveServer) RootDSN() string {
	if s.Socket != "" {
		return fmt.Sprintf("%s:%s@unix(%s)/", s.User, s.Password, s.Socket)
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/", s.User, s.Password, s.Host, s.Port)
}

// setupLiveMySQL starts an unmocked, real MySQL server for live integration testing.
// It prioritizes MYSQL_INTEGRATION_DSN, then local mysqld, then Docker container.
func setupLiveMySQL(t *testing.T) *liveServer {
	t.Helper()

	// 1. Existing endpoint provided via environment variable
	if customDSN := os.Getenv("MYSQL_INTEGRATION_DSN"); customDSN != "" {
		db, err := sql.Open("mysql", customDSN)
		if err == nil {
			if err = db.Ping(); err == nil {
				db.Close()
				t.Logf("Using live MySQL instance from MYSQL_INTEGRATION_DSN")
				return parseCustomDSN(t, customDSN)
			}
			db.Close()
		}
		t.Logf("MYSQL_INTEGRATION_DSN provided but ping failed: %v", err)
	}

	// 2. Try starting local mysqld in t.TempDir()
	mysqldPath, err := exec.LookPath("mysqld")
	if err != nil {
		if _, statErr := os.Stat("/sbin/mysqld"); statErr == nil {
			mysqldPath = "/sbin/mysqld"
			err = nil
		}
	}

	if err == nil {
		return startLocalMysqld(t, mysqldPath)
	}

	// 3. Try Docker container
	dockerPath, err := exec.LookPath("docker")
	if err == nil {
		return startDockerMySQL(t, dockerPath)
	}

	t.Skip("Skipping live integration tests: neither mysqld nor docker is available, and MYSQL_INTEGRATION_DSN is not set.")
	return nil
}

func parseCustomDSN(t *testing.T, dsn string) *liveServer {
	t.Helper()
	srv := &liveServer{Host: "127.0.0.1", Port: 3306, User: "root", Password: ""}
	// Basic parsing for standard integration endpoints
	if at := strings.Index(dsn, "@"); at != -1 {
		userPass := dsn[:at]
		if colon := strings.Index(userPass, ":"); colon != -1 {
			srv.User = userPass[:colon]
			srv.Password = userPass[colon+1:]
		} else {
			srv.User = userPass
		}
		rest := dsn[at+1:]
		if strings.HasPrefix(rest, "unix(") {
			end := strings.Index(rest, ")")
			if end != -1 {
				srv.Socket = rest[5:end]
			}
		} else if strings.HasPrefix(rest, "tcp(") {
			end := strings.Index(rest, ")")
			if end != -1 {
				hostPort := rest[4:end]
				if h, p, splitErr := net.SplitHostPort(hostPort); splitErr == nil {
					srv.Host = h
					if pInt, atoiErr := strconv.Atoi(p); atoiErr == nil {
						srv.Port = pInt
					}
				}
			}
		}
	}
	return srv
}

func getFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func startLocalMysqld(t *testing.T, mysqldPath string) *liveServer {
	t.Helper()
	tempDir := t.TempDir()
	datadir := filepath.Join(tempDir, "data")
	socketPath := filepath.Join(tempDir, "mysql.sock")
	pidFile := filepath.Join(tempDir, "mysqld.pid")
	port := getFreePort(t)

	// Determine basedir
	basedir := "/usr"
	if _, err := os.Stat("/usr/share/mysql"); err != nil {
		if _, pErr := os.Stat("/usr/share/percona-server"); pErr == nil {
			basedir = "/usr"
		}
	}

	// 1. Initialize data directory without defaults
	initCmd := exec.Command(mysqldPath,
		"--no-defaults",
		"--initialize-insecure",
		"--datadir="+datadir,
		"--basedir="+basedir,
	)
	var initBuf bytes.Buffer
	initCmd.Stdout = &initBuf
	initCmd.Stderr = &initBuf
	if err := initCmd.Run(); err != nil {
		t.Fatalf("mysqld --initialize-insecure failed: %v, output:\n%s", err, initBuf.String())
	}

	// 2. Start mysqld server
	ctx, cancel := context.WithCancel(context.Background())
	serverCmd := exec.CommandContext(ctx, mysqldPath,
		"--no-defaults",
		"--datadir="+datadir,
		"--basedir="+basedir,
		"--socket="+socketPath,
		"--port="+strconv.Itoa(port),
		"--bind-address=127.0.0.1",
		"--pid-file="+pidFile,
		"--mysqlx=OFF",
	)
	var srvBuf bytes.Buffer
	serverCmd.Stdout = &srvBuf
	serverCmd.Stderr = &srvBuf

	if err := serverCmd.Start(); err != nil {
		cancel()
		t.Fatalf("failed to start mysqld: %v", err)
	}

	t.Cleanup(func() {
		cancel()
		if serverCmd.Process != nil {
			_ = serverCmd.Process.Signal(os.Interrupt)
			done := make(chan error, 1)
			go func() { done <- serverCmd.Wait() }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = serverCmd.Process.Kill()
			}
		}
	})

	srv := &liveServer{
		Socket:   socketPath,
		Host:     "127.0.0.1",
		Port:     port,
		User:     "root",
		Password: "",
	}

	// 3. Wait for database readiness
	waitForReady(t, srv.RootDSN())

	// 4. Create dedicated integration test user with caching_sha2_password
	db, err := sql.Open("mysql", srv.RootDSN())
	if err != nil {
		t.Fatalf("failed to open root db connection: %v", err)
	}
	defer db.Close()

	setupSQL := []string{
		"CREATE USER IF NOT EXISTS 'e2e_user'@'%' IDENTIFIED WITH caching_sha2_password BY 'Secret!Pass2026';",
		"GRANT ALL PRIVILEGES ON *.* TO 'e2e_user'@'%';",
		"FLUSH PRIVILEGES;",
	}
	for _, q := range setupSQL {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("failed to configure e2e_user with query %q: %v", q, err)
		}
	}

	return srv
}

func startDockerMySQL(t *testing.T, dockerPath string) *liveServer {
	t.Helper()
	port := getFreePort(t)
	containerName := fmt.Sprintf("mysql-integration-%d", time.Now().UnixNano())

	runCmd := exec.Command(dockerPath, "run", "-d", "--rm",
		"--name", containerName,
		"-p", fmt.Sprintf("%d:3306", port),
		"-e", "MYSQL_ALLOW_EMPTY_PASSWORD=yes",
		"-e", "MYSQL_DATABASE=integration_db",
		"mysql:8.4",
	)
	var runBuf bytes.Buffer
	runCmd.Stdout = &runBuf
	runCmd.Stderr = &runBuf
	if err := runCmd.Run(); err != nil {
		t.Fatalf("failed to launch docker mysql: %v, output: %s", err, runBuf.String())
	}

	t.Cleanup(func() {
		_ = exec.Command(dockerPath, "kill", containerName).Run()
	})

	srv := &liveServer{
		Host:     "127.0.0.1",
		Port:     port,
		User:     "root",
		Password: "",
	}

	waitForReady(t, srv.RootDSN())
	return srv
}

func waitForReady(t *testing.T, dsn string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error

	for time.Now().Before(deadline) {
		db, err := sql.Open("mysql", dsn)
		if err == nil {
			err = db.Ping()
			db.Close()
			if err == nil {
				return
			}
			lastErr = err
		} else {
			lastErr = err
		}
		time.Sleep(300 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for live MySQL endpoint to become ready: %v", lastErr)
}

func TestLiveEndToEndWorkflow(t *testing.T) {
	srv := setupLiveMySQL(t)
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, ".mylogin.cnf")

	// 1. Programmatically assemble Sections
	var sections mylogin.Sections

	// Section [client]: default admin connection via socket / TCP
	var clientLogin mylogin.Login
	clientLogin.SetUser(srv.User).SetPassword(srv.Password)
	if srv.Socket != "" {
		clientLogin.SetSocket(srv.Socket)
	} else {
		clientLogin.SetHost(srv.Host).SetPort(strconv.Itoa(srv.Port))
	}
	sections.Set("client", clientLogin)

	// Section [app_user]: dedicated application credentials
	var appLogin mylogin.Login
	appLogin.SetUser("e2e_user").SetPassword("Secret!Pass2026")
	if srv.Socket != "" {
		appLogin.SetSocket(srv.Socket)
	} else {
		appLogin.SetHost(srv.Host).SetPort(strconv.Itoa(srv.Port))
	}
	appLogin.SetExtra("default-auth", "caching_sha2_password")
	sections.Set("app_user", appLogin)

	// 2. Safely write encrypted .mylogin.cnf
	formattedPlainText, err := sections.Format()
	if err != nil {
		t.Fatalf("sections.Format failed: %v", err)
	}
	if err := mylogin.WriteFile(confPath, strings.NewReader(formattedPlainText)); err != nil {
		t.Fatalf("mylogin.WriteFile failed: %v", err)
	}

	// Verify file permissions
	if err := mylogin.CheckPermissions(confPath); err != nil {
		t.Fatalf("CheckPermissions failed on written file: %v", err)
	}

	// 3. Read back sections and verify decryption
	readSecs, err := mylogin.ReadSections(confPath)
	if err != nil {
		t.Fatalf("ReadSections failed: %v", err)
	}
	if len(readSecs) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(readSecs))
	}
	if !readSecs.Has("client") || !readSecs.Has("app_user") {
		t.Fatalf("missing expected sections: %v", readSecs.Names())
	}

	// 4. Live connection & CRUD using decrypted DSN
	loginApp := readSecs.Login("app_user")
	dsn := loginApp.FormatDSN("")

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open failed with decrypted DSN: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("db.Ping failed with live credentials: %v", err)
	}

	// Live database and table operations
	dbName := fmt.Sprintf("live_test_%d", time.Now().UnixNano()%1000000)
	if _, err := db.Exec("CREATE DATABASE " + dbName); err != nil {
		t.Fatalf("CREATE DATABASE failed: %v", err)
	}
	defer func() {
		_, _ = db.Exec("DROP DATABASE " + dbName)
	}()

	if _, err := db.Exec("USE " + dbName); err != nil {
		t.Fatalf("USE DATABASE failed: %v", err)
	}

	// Verify direct driver connector via loginApp.Open without DSN text formatting
	dbConnector, err := loginApp.Open(dbName)
	if err != nil {
		t.Fatalf("loginApp.Open failed: %v", err)
	}
	defer dbConnector.Close()
	if err := dbConnector.Ping(); err != nil {
		t.Fatalf("dbConnector.Ping failed: %v", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(50) NOT NULL,
			email VARCHAR(100) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		) ENGINE=InnoDB;
	`); err != nil {
		t.Fatalf("CREATE TABLE failed: %v", err)
	}

	// Transaction commit test
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("tx.Begin failed: %v", err)
	}
	stmt, err := tx.Prepare("INSERT INTO users (username, email) VALUES (?, ?)")
	if err != nil {
		t.Fatalf("tx.Prepare failed: %v", err)
	}
	for i := 1; i <= 5; i++ {
		if _, err := stmt.Exec(fmt.Sprintf("user_%d", i), fmt.Sprintf("user_%d@example.com", i)); err != nil {
			t.Fatalf("stmt.Exec failed: %v", err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("tx.Commit failed: %v", err)
	}

	// Query verification
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		t.Fatalf("SELECT COUNT failed: %v", err)
	}
	if count != 5 {
		t.Fatalf("expected 5 users, got %d", count)
	}

	// Transaction rollback test
	txRollback, err := db.Begin()
	if err != nil {
		t.Fatalf("txRollback.Begin failed: %v", err)
	}
	if _, err := txRollback.Exec("INSERT INTO users (username, email) VALUES ('temp', 'temp@example.com')"); err != nil {
		t.Fatalf("txRollback.Exec failed: %v", err)
	}
	if err := txRollback.Rollback(); err != nil {
		t.Fatalf("txRollback.Rollback failed: %v", err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		t.Fatalf("SELECT COUNT post-rollback failed: %v", err)
	}
	if count != 5 {
		t.Fatalf("expected 5 users after rollback, got %d", count)
	}

	// 5. Official /bin/mysql CLI Interoperability
	mysqlBin, err := exec.LookPath("mysql")
	if err == nil {
		cmd := exec.Command(mysqlBin,
			"--no-defaults",
			"--login-path=client",
			"-e", "SELECT 'OFFICIAL_MYSQL_CLI_SUCCESS';",
		)
		cmd.Env = append(os.Environ(), "MYSQL_TEST_LOGIN_FILE="+confPath)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Errorf("Official mysql CLI failed using Go-generated login file: %v, output: %s", err, out.String())
		} else if !strings.Contains(out.String(), "OFFICIAL_MYSQL_CLI_SUCCESS") {
			t.Errorf("Official mysql CLI missing expected output: %s", out.String())
		} else {
			t.Logf("Official mysql CLI successfully authenticated with Go-generated .mylogin.cnf")
		}
	}

	// 6. Official /bin/mysql_config_editor Interoperability
	editorBin, err := exec.LookPath("mysql_config_editor")
	if err == nil {
		// A. Verify official editor can print the file generated by Go
		cmdPrint := exec.Command(editorBin, "print", "--all")
		cmdPrint.Env = append(os.Environ(), "MYSQL_TEST_LOGIN_FILE="+confPath)
		var printBuf bytes.Buffer
		cmdPrint.Stdout = &printBuf
		cmdPrint.Stderr = &printBuf
		if err := cmdPrint.Run(); err != nil {
			t.Errorf("mysql_config_editor print failed on Go-generated file: %v, output: %s", err, printBuf.String())
		} else {
			outStr := printBuf.String()
			if !strings.Contains(outStr, "[client]") || !strings.Contains(outStr, "[app_user]") {
				t.Errorf("mysql_config_editor output missing sections: %s", outStr)
			}
		}

		// B. Verify Go can read a section added by official mysql_config_editor
		cmdSet := exec.Command(editorBin, "set",
			"--login-path=from_editor",
			"--user=editor_test_user",
			"--host=127.0.0.1",
			"--port="+strconv.Itoa(srv.Port),
		)
		cmdSet.Env = append(os.Environ(), "MYSQL_TEST_LOGIN_FILE="+confPath)
		if err := cmdSet.Run(); err != nil {
			t.Errorf("mysql_config_editor set failed: %v", err)
		} else {
			updatedSecs, err := mylogin.ReadSections(confPath)
			if err != nil {
				t.Errorf("failed to read file after mysql_config_editor modification: %v", err)
			} else if !updatedSecs.Has("from_editor") {
				t.Errorf("section from_editor not found after mysql_config_editor set: %v", updatedSecs.Names())
			} else {
				edLogin := updatedSecs.Login("from_editor")
				if edLogin.User == nil || *edLogin.User != "editor_test_user" {
					t.Errorf("expected editor_test_user, got %v", edLogin.User)
				}
			}
		}
	}

	// 7. Test Section Inheritance / Merging in live connection
	var hostOnlySec mylogin.Section
	hostOnlySec.Name = "base_cluster"
	if srv.Socket != "" {
		hostOnlySec.Login.SetSocket(srv.Socket)
	} else {
		hostOnlySec.Login.SetHost(srv.Host).SetPort(strconv.Itoa(srv.Port))
	}

	var credsOnlySec mylogin.Section
	credsOnlySec.Name = "service_acct"
	credsOnlySec.Login.SetUser("e2e_user").SetPassword("Secret!Pass2026")

	allSecs := mylogin.Sections{hostOnlySec, credsOnlySec}
	mergedLogin := allSecs.Merge([]string{"base_cluster", "service_acct"})
	mergedDSN := mergedLogin.FormatDSN("")

	dbMerged, err := sql.Open("mysql", mergedDSN)
	if err != nil {
		t.Fatalf("failed to open db with merged DSN: %v", err)
	}
	defer dbMerged.Close()

	var currentUser string
	if err := dbMerged.QueryRow("SELECT CURRENT_USER()").Scan(&currentUser); err != nil {
		t.Fatalf("failed to query with merged credentials: %v", err)
	}
	if !strings.HasPrefix(currentUser, "e2e_user@") {
		t.Errorf("expected e2e_user, got %s", currentUser)
	}
}

func TestLiveCLIToolsWorkflow(t *testing.T) {
	srv := setupLiveMySQL(t)
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, ".mylogin.cnf")

	// Create configuration for live connection
	var sections mylogin.Sections
	var sec mylogin.Login
	sec.SetUser(srv.User).SetPassword(srv.Password)
	if srv.Socket != "" {
		sec.SetSocket(srv.Socket)
	} else {
		sec.SetHost(srv.Host).SetPort(strconv.Itoa(srv.Port))
	}
	sections.Set("client", sec)

	formatted, err := sections.Format()
	if err != nil {
		t.Fatalf("sections.Format failed: %v", err)
	}
	if err := mylogin.WriteFile(confPath, strings.NewReader(formatted)); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Build CLI tools into temp directory
	binDir := filepath.Join(tempDir, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatalf("failed to create binDir: %v", err)
	}

	myloginBin := filepath.Join(binDir, "mylogin")
	dsnBin := filepath.Join(binDir, "mylogin-dsn")
	keyBin := filepath.Join(binDir, "mylogin-key")

	buildCmd := exec.Command("go", "build", "-o", myloginBin, "./cmd/mylogin")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build mylogin CLI: %v, output: %s", err, string(out))
	}

	buildDSNCmd := exec.Command("go", "build", "-o", dsnBin, "./cmd/mylogin-dsn")
	if out, err := buildDSNCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build mylogin-dsn CLI: %v, output: %s", err, string(out))
	}

	buildKeyCmd := exec.Command("go", "build", "-o", keyBin, "./cmd/mylogin-key")
	if out, err := buildKeyCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build mylogin-key CLI: %v, output: %s", err, string(out))
	}

	// 1. Test mylogin-dsn CLI and connect to live MySQL with generated DSN
	dsnOutput, err := exec.Command(dsnBin, "-file", confPath, "client").Output()
	if err != nil {
		t.Fatalf("mylogin-dsn CLI failed: %v", err)
	}
	genDSN := strings.TrimSpace(string(dsnOutput))
	t.Logf("Generated DSN from CLI: %s", genDSN)

	liveDB, err := sql.Open("mysql", genDSN)
	if err != nil {
		t.Fatalf("failed to open live DB using CLI-generated DSN: %v", err)
	}
	defer liveDB.Close()

	if err := liveDB.Ping(); err != nil {
		t.Fatalf("live DB Ping failed using CLI-generated DSN: %v", err)
	}

	// 2. Test mylogin CLI with -json
	jsonOutput, err := exec.Command(myloginBin, "-file", confPath, "-json", "client").Output()
	if err != nil {
		t.Fatalf("mylogin -json failed: %v", err)
	}
	if !strings.Contains(string(jsonOutput), `"user": "`+srv.User+`"`) {
		t.Errorf("mylogin -json missing user: %s", string(jsonOutput))
	}

	// 3. Test mylogin-key CLI
	keyOutput, err := exec.Command(keyBin, confPath).Output()
	if err != nil {
		t.Fatalf("mylogin-key failed: %v", err)
	}
	if len(strings.TrimSpace(string(keyOutput))) == 0 {
		t.Fatalf("expected non-empty key output from mylogin-key")
	}
}
