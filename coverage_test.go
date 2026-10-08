// Package mylogin_test provides test coverage verification and edge-case validation.
//
// Objective: Exercise deep code coverage, nil-receiver resilience, edge cases, error branches,
// and boundary conditions across core library components.
//
// Core Components:
//   - TestCoreCoverageBoost: Fluent setters, socket handling, clone routines, validation errors, endianness detection.
//   - TestLoginRedactionAndSlog: Telemetry security, zero-leakage masking, and slog.LogValuer integration.
//   - TestLoginConnectorAndOpen: Driver-level connector instantiation and direct sql.DB handle creation.
//   - TestExtendedConfigOptionMapping: TLS mode translations, timeout parsing, and packet size limits.
//   - TestTopLevelConvenienceAndSectionsWriteFile: End-to-end atomic persistence, Load(), Default(), and Get().
//   - TestLoginSetAndMap: Nil-safety and generic map serialization.
//   - failingCoverageReader: Fault-injection mock returning io.ErrUnexpectedEOF.
//
// Test Strategy:
//   - Branch Exhaustion: Validate every branch in setters, formatters, and AST validators.
//   - Fault Injection: Simulate failing readers and impossible filesystem paths to ensure robust error handling.
//   - Endianness Simulation: Synthesize Big-Endian headers to test automatic byte-order sniffing.
//   - Security Assertion: Strictly verify that plaintext passwords never appear in redacted outputs or structured logs.
//
// Functionality:
//   - Validates data model safety, error contracts, cryptographic boundary parsing, and driver interoperability.
//
// Data Flow:
//
//	Test Fixtures -> Component Invocations -> Assertions against expected states and error types.
package mylogin_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/edsilegxrepo/mylogin"
)

func TestCoreCoverageBoost(t *testing.T) {
	// 1. Test Login Fluent Setters & Helpers
	var l mylogin.Login
	l.SetSocket("/tmp/mysql.sock").SetUser("sock_user")
	if l.Socket == nil || *l.Socket != "/tmp/mysql.sock" {
		t.Errorf("expected socket /tmp/mysql.sock, got %v", l.Socket)
	}
	if l.String() != l.DSN() {
		t.Errorf("expected String() == DSN()")
	}

	// Test FormatDSN branches
	var emptyLogin mylogin.Login
	if emptyLogin.FormatDSN("testdb") != "/testdb" {
		t.Errorf("expected /testdb, got %q", emptyLogin.FormatDSN("testdb"))
	}
	if emptyLogin.FormatDSN("") != "/" {
		t.Errorf("expected /, got %q", emptyLogin.FormatDSN(""))
	}

	// Test Socket DSN formatting
	sockDSN := l.FormatDSN("appdb")
	if !strings.Contains(sockDSN, "unix(/tmp/mysql.sock)/appdb") {
		t.Errorf("socket DSN formatted incorrectly: %s", sockDSN)
	}

	// 2. Test Login.Merge with Socket
	var target mylogin.Login
	target.Merge(&l)
	if target.Socket == nil || *target.Socket != "/tmp/mysql.sock" {
		t.Errorf("expected merged socket, got %v", target.Socket)
	}
	// Test Merge with nil other
	target.Merge(nil)

	// 3. Test Section and Sections Clone, Names, Validate
	var sections mylogin.Sections
	var sec mylogin.Section
	sec.Name = "replica"
	sec.Login.SetUser("rep").SetHost("rep.internal")
	sections = append(sections, sec)

	secClone := sec.Clone()
	if secClone.Name != "replica" || *secClone.Login.User != "rep" {
		t.Errorf("Section.Clone mismatch")
	}

	sectionsClone := sections.Clone()
	if len(sectionsClone) != 1 || sectionsClone[0].Name != "replica" {
		t.Errorf("Sections.Clone mismatch")
	}

	names := sections.Names()
	if len(names) != 1 || names[0] != "replica" {
		t.Errorf("Sections.Names mismatch: %v", names)
	}

	if err := sections.Validate(); err != nil {
		t.Errorf("expected valid sections, got: %v", err)
	}

	// Test Sections.Set replacing existing section
	var updatedLogin mylogin.Login
	updatedLogin.SetUser("rep_updated")
	sections.Set("replica", updatedLogin)
	if *sections.Login("replica").User != "rep_updated" {
		t.Errorf("Sections.Set did not replace existing section")
	}

	// Test Sections.Delete on non-existing section
	if sections.Delete("non_existent") {
		t.Errorf("expected Delete to return false for non-existent section")
	}

	// Test Section.Validate errors
	var invalidSec mylogin.Section
	invalidSec.Name = ""
	if err := invalidSec.Validate(); err == nil {
		t.Errorf("expected error for empty section name")
	}

	var invalidKeySec mylogin.Section
	invalidKeySec.Name = "valid"
	invalidKeySec.Login.SetExtra("bad=key", "val")
	if err := invalidKeySec.Validate(); err == nil {
		t.Errorf("expected error for key containing '='")
	}

	sectionsInvalid := mylogin.Sections{invalidKeySec}
	if err := sectionsInvalid.Validate(); err == nil {
		t.Errorf("expected Sections.Validate to fail on invalid section")
	}

	// 4. Test DefaultFile with environment override
	tempDir := t.TempDir()
	customPath := filepath.Join(tempDir, "custom.cnf")
	t.Setenv("MYSQL_TEST_LOGIN_FILE", customPath)
	if mylogin.DefaultFile() != customPath {
		t.Errorf("expected DefaultFile to respect MYSQL_TEST_LOGIN_FILE")
	}

	if err := os.Unsetenv("MYSQL_TEST_LOGIN_FILE"); err != nil {
		t.Fatalf("failed to unset MYSQL_TEST_LOGIN_FILE: %v", err)
	}
	defPath := mylogin.DefaultFile()
	if defPath == "" {
		t.Errorf("expected platformDefaultFile, got empty string")
	}

	// 5. Test PlainFile.ByteOrder with nil Order
	pf := mylogin.PlainFile{
		KeyVal:    mylogin.Key{},
		Order:     nil,
		PlainData: strings.NewReader(""),
	}
	if pf.ByteOrder() != binary.LittleEndian {
		t.Errorf("expected default LittleEndian when Order is nil")
	}

	// 6. Test Encode with uninitialized key
	var buf bytes.Buffer
	err := mylogin.Encode(&buf, &pf)
	if err == nil || !strings.Contains(err.Error(), "key is not initialized") {
		t.Errorf("expected ErrKeyNotInitialized, got: %v", err)
	}

	// 7. Test Decode error paths
	// Short header (< 4 bytes)
	_, err = mylogin.Decode(strings.NewReader("12"))
	if err == nil {
		t.Errorf("expected EOF or error on short header")
	}

	// Short key (< 24 bytes)
	_, err = mylogin.Decode(strings.NewReader("\x00\x00\x00\x00short"))
	if err == nil {
		t.Errorf("expected error on short key")
	}

	// 8. Test BigEndian detection in Decode
	// Header: 4 nulls + 20 key bytes + 4 chunk size bytes (BigEndian: 0x00 0x00 0x00 0x10 = 16)
	var beHeader bytes.Buffer
	beHeader.Write([]byte{0, 0, 0, 0})
	beHeader.Write(make([]byte, 20))
	beHeader.Write([]byte{0, 0, 0, 16})
	beFile, err := mylogin.Decode(&beHeader)
	if err != nil {
		t.Fatalf("Decode with BigEndian chunk size failed: %v", err)
	}
	if beFile.ByteOrder() != binary.BigEndian {
		t.Errorf("expected BigEndian detected, got %v", beFile.ByteOrder())
	}

	// 9. Test decoder.Close() and decoder.Parse()
	// Create a valid encoded file
	validPath := filepath.Join(tempDir, "valid.cnf")
	if err := mylogin.WriteFile(validPath, strings.NewReader("[client]\nhost = localhost\n")); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	f, err := os.Open(validPath)
	if err != nil {
		t.Fatalf("os.Open failed: %v", err)
	}
	defer func() { _ = f.Close() }()
	decFile, err := mylogin.Decode(f)
	if err != nil {
		_ = f.Close()
		t.Fatalf("Decode failed: %v", err)
	}

	// Test decFile.Parse() via interface assertion
	if parser, ok := decFile.(interface {
		Parse() (mylogin.Sections, error)
	}); ok {
		parsedSecs, err := parser.Parse()
		if err != nil {
			t.Fatalf("parser.Parse failed: %v", err)
		}
		if len(parsedSecs) != 1 || parsedSecs[0].Name != "client" {
			t.Errorf("expected 1 section named client, got: %v", parsedSecs)
		}
	} else {
		t.Errorf("expected decFile to implement Parse()")
	}

	// Test decFile.Close() which closes f and wipes key
	if closer, ok := decFile.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	} else {
		_ = f.Close()
	}

	// 10. Test CheckPermissions error path
	if err := mylogin.CheckPermissions(filepath.Join(tempDir, "non_existent_file")); err == nil {
		t.Errorf("expected error on non existent file in CheckPermissions")
	}
	if _, err := mylogin.ReadLogin(filepath.Join(tempDir, "non_existent_file"), nil); err == nil {
		t.Errorf("expected error in ReadLogin for non-existent file")
	}
	corruptedFile := filepath.Join(tempDir, "corrupted.cnf")
	if err := os.WriteFile(corruptedFile, []byte("short"), 0o600); err == nil {
		if _, err := mylogin.ReadSections(corruptedFile); err == nil {
			t.Errorf("expected error in ReadSections for corrupted file")
		}
	}

	// 11. Test WriteFile error branches (failing reader, invalid directory, read-only directory, directory rename target)
	badReader := &failingCoverageReader{}
	if err := mylogin.WriteFile(filepath.Join(tempDir, "bad.cnf"), badReader); err == nil {
		t.Errorf("expected WriteFile to fail with bad reader")
	}
	impossibleDirFile := filepath.Join(validPath, "cannot_create_dir.cnf")
	if err := mylogin.WriteFile(impossibleDirFile, strings.NewReader("[client]\n")); err == nil {
		t.Errorf("expected WriteFile to fail with invalid dir path")
	}
	if runtime.GOOS != "windows" {
		readOnlyDir := filepath.Join(tempDir, "readonly_dir")
		if err := os.MkdirAll(readOnlyDir, 0o500); err == nil {
			defer func() { _ = os.Chmod(readOnlyDir, 0o700) }()
			if err := mylogin.WriteFile(filepath.Join(readOnlyDir, "test.cnf"), strings.NewReader("[client]\n")); err == nil {
				t.Errorf("expected WriteFile to fail in read-only directory")
			}
		}
	}
	existingDirAsTarget := filepath.Join(tempDir, "existing_dir_target")
	if err := os.MkdirAll(existingDirAsTarget, 0o700); err == nil {
		if err := mylogin.WriteFile(existingDirAsTarget, strings.NewReader("[client]\n")); err == nil {
			t.Errorf("expected WriteFile to fail when target filename is an existing directory")
		}
	}

	// 12. Test nil Login Clone
	var nilLogin *mylogin.Login
	if nilLogin.Clone() != nil {
		t.Errorf("expected nilLogin.Clone() == nil")
	}

	// 13. Test Sections.Format & WriteTo & WriteFile with invalid section
	badSecs := mylogin.Sections{{Name: ""}}
	if _, err := badSecs.Format(); err == nil {
		t.Errorf("expected badSecs.Format() to fail")
	}
	var badBuf bytes.Buffer
	if _, err := badSecs.WriteTo(&badBuf); err == nil {
		t.Errorf("expected badSecs.WriteTo() to fail")
	}
	if err := badSecs.WriteFile(filepath.Join(tempDir, "should_fail.cnf")); err == nil {
		t.Errorf("expected badSecs.WriteFile() to fail on invalid section name")
	}

	// 14. Test Sections.Merge with multiple sections & default fallback
	var m1, m2 mylogin.Section
	m1.Name = "sec1"
	m1.Login.SetUser("user1").SetHost("host1")
	m2.Name = "sec2"
	m2.Login.SetUser("user2").SetPort("3307")
	multiSecs := mylogin.Sections{m1, m2}
	merged := multiSecs.Merge([]string{"sec1", "sec2"})
	if *merged.User != "user2" || *merged.Host != "host1" || *merged.Port != "3307" {
		t.Errorf("unexpected merged result: %+v", merged)
	}
	defaultMerged := multiSecs.Merge([]string{""})
	if !defaultMerged.IsEmpty() {
		t.Errorf("expected empty merged when default section 'client' is not present")
	}

	// 15. Test platformDefaultFile fallback when HOME is unset
	t.Setenv("HOME", "")
	_ = mylogin.DefaultFile()

	// 16. Test Login.Open error path with invalid TLS configuration
	var invalidTLSSec mylogin.Login
	invalidTLSSec.SetExtra("ssl-mode", "unregistered_tls_profile_xyz")
	if _, err := invalidTLSSec.Open(""); err == nil {
		t.Errorf("expected Open to fail with unregistered TLS config")
	}

	// 17. Test nil Login LogValue
	if val := nilLogin.LogValue(); len(val.Group()) != 0 {
		t.Errorf("expected empty group value for nil Login.LogValue()")
	}

	// 18. Test decoder.Close with an underlying io.Closer
	closable := &closableReader{Reader: bytes.NewReader(buf.Bytes())}
	decWithCloser, err := mylogin.Decode(closable)
	if err == nil {
		if closer, ok := decWithCloser.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				t.Errorf("expected clean Close: %v", err)
			}
			if !closable.closed {
				t.Errorf("expected underlying closer to be called")
			}
		}
	}

	// 19. Test decoder.Read with nil buffer
	decFile, decErr := mylogin.Decode(bytes.NewReader(buf.Bytes()))
	if decErr == nil {
		if rn, rerr := decFile.PlainText().Read(nil); rn != 0 || rerr != nil {
			t.Errorf("expected (0, nil) on Read(nil), got (%d, %v)", rn, rerr)
		}
	}

	// 20. Test filterSection.Read with nil buffer and scanner error
	filt := mylogin.FilterSection(strings.NewReader("[client]\nuser = root\n"), "client")
	if rn, rerr := filt.Read(nil); rn != 0 || rerr != nil {
		t.Errorf("expected (0, nil) on filterSection.Read(nil)")
	}
	hugeTokenReader := mylogin.FilterSection(strings.NewReader("[client]\n"+strings.Repeat("x", 70000)+"\n"), "client")
	var discardBuf [1024]byte
	for {
		if _, rerr := hugeTokenReader.Read(discardBuf[:]); rerr != nil {
			break
		}
	}
}

type closableReader struct {
	io.Reader
	closed bool
}

func (c *closableReader) Close() error {
	c.closed = true
	return nil
}

type failingCoverageReader struct{}

func (f *failingCoverageReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func TestLoginRedactionAndSlog(t *testing.T) {
	var l mylogin.Login
	l.SetUser("admin").SetPassword("SuperSecret123!").SetHost("db.example.com").SetPort("3306")

	// Verify raw DSN contains the plaintext password
	rawDSN := l.DSN()
	if !strings.Contains(rawDSN, "SuperSecret123!") {
		t.Errorf("expected DSN to contain password, got: %s", rawDSN)
	}

	// Verify RedactedDSN masks the password
	redacted := l.RedactedDSN()
	if strings.Contains(redacted, "SuperSecret123!") {
		t.Errorf("RedactedDSN leaked password: %s", redacted)
	}
	if !strings.Contains(redacted, "admin:******@") {
		t.Errorf("expected admin:******@, got: %s", redacted)
	}

	// Verify String() delegates to RedactedDSN
	if l.String() != redacted {
		t.Errorf("expected String() to equal RedactedDSN(), got: %s", l.String())
	}

	// Verify RedactedFormatDSN with custom db
	redactedDB := l.RedactedFormatDSN("shop_prod")
	if strings.Contains(redactedDB, "SuperSecret123!") || !strings.Contains(redactedDB, "/shop_prod") {
		t.Errorf("unexpected RedactedFormatDSN: %s", redactedDB)
	}

	// Test slog.LogValuer
	val := l.LogValue()
	attrs := val.Group()
	foundMasked := false
	for _, a := range attrs {
		if a.Key == "password" {
			if a.Value.String() != "******" {
				t.Errorf("expected masked password in slog, got: %s", a.Value.String())
			}
			foundMasked = true
		}
	}
	if !foundMasked {
		t.Errorf("slog LogValue did not include password attribute")
	}

	// Test nil and empty Login handling
	var nilLogin *mylogin.Login
	if nilLogin.RedactedDSN() != "/" {
		t.Errorf("expected / for nil login, got %s", nilLogin.RedactedDSN())
	}
	if nilLogin.RedactedFormatDSN("db") != "/db" {
		t.Errorf("expected /db for nil login, got %s", nilLogin.RedactedFormatDSN("db"))
	}
	if len(nilLogin.LogValue().Group()) != 0 {
		t.Errorf("expected empty group for nil login LogValue")
	}
}

func TestLoginConnectorAndOpen(t *testing.T) {
	var l mylogin.Login
	l.SetUser("app").SetPassword("pass").SetHost("localhost").SetPort("3306")

	// Test Connector
	connector, err := l.Connector("app_db")
	if err != nil {
		t.Fatalf("Connector failed: %v", err)
	}
	if connector == nil {
		t.Fatalf("expected non-nil connector")
	}

	// Test Open
	db, err := l.Open("app_db")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if db == nil {
		t.Fatalf("expected non-nil *sql.DB")
	}
	defer func() { _ = db.Close() }()
}

func TestExtendedConfigOptionMapping(t *testing.T) {
	var l mylogin.Login
	l.SetHost("localhost").SetPort("3306")
	l.SetExtra("ssl-mode", "REQUIRED")
	l.SetExtra("connect-timeout", "15")
	l.SetExtra("max-allowed-packet", "16777216")

	cfg := l.Config()
	if cfg.TLSConfig != "skip-verify" {
		t.Errorf("expected TLSConfig skip-verify for REQUIRED, got: %s", cfg.TLSConfig)
	}
	if cfg.Timeout != 15*time.Second {
		t.Errorf("expected 15s timeout, got: %v", cfg.Timeout)
	}
	if cfg.MaxAllowedPacket != 16777216 {
		t.Errorf("expected 16777216 MaxAllowedPacket, got: %d", cfg.MaxAllowedPacket)
	}

	// Test other SSL modes
	l.SetExtra("ssl-mode", "DISABLED")
	if l.Config().TLSConfig != "false" {
		t.Errorf("expected false for DISABLED")
	}
	l.SetExtra("ssl-mode", "VERIFY_CA")
	if l.Config().TLSConfig != "true" {
		t.Errorf("expected true for VERIFY_CA")
	}
	l.SetExtra("ssl-mode", "custom-tls")
	if l.Config().TLSConfig != "custom-tls" {
		t.Errorf("expected custom-tls for custom")
	}
}

func TestTopLevelConvenienceAndSectionsWriteFile(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, ".mylogin.cnf")

	t.Setenv("MYSQL_TEST_LOGIN_FILE", confPath)

	var secs mylogin.Sections
	var clientSec mylogin.Login
	clientSec.SetUser("root").SetHost("127.0.0.1").SetPort("3306")
	secs.Set("client", clientSec)

	var appSec mylogin.Login
	appSec.SetUser("app_user").SetPassword("app_pass")
	secs.Set("app", appSec)

	// Test Sections.WriteFile
	if err := secs.WriteFile(confPath); err != nil {
		t.Fatalf("Sections.WriteFile failed: %v", err)
	}

	// Test Load()
	loadedSecs, err := mylogin.Load()
	if err != nil {
		t.Fatalf("mylogin.Load failed: %v", err)
	}
	if len(loadedSecs) != 2 || !loadedSecs.Has("client") || !loadedSecs.Has("app") {
		t.Fatalf("Load mismatch: %v", loadedSecs.Names())
	}

	// Test Default()
	defLogin, err := mylogin.Default()
	if err != nil {
		t.Fatalf("mylogin.Default failed: %v", err)
	}
	if defLogin.User == nil || *defLogin.User != "root" {
		t.Errorf("expected root user in Default(), got %v", defLogin.User)
	}

	// Test Get()
	appLogin, err := mylogin.Get("app")
	if err != nil {
		t.Fatalf("mylogin.Get failed: %v", err)
	}
	if appLogin.User == nil || *appLogin.User != "app_user" || appLogin.Host == nil || *appLogin.Host != "127.0.0.1" {
		t.Errorf("expected app_user with merged host from client, got %+v", appLogin)
	}
}

func TestLoginSetAndMap(t *testing.T) {
	// 1. Nil receiver test
	var nilLogin *mylogin.Login
	if m := nilLogin.Map(); len(m) != 0 {
		t.Errorf("expected empty map for nil login, got %v", m)
	}

	// 2. Population via Set
	var l mylogin.Login
	l.Set("user", "alice")
	l.Set("password", "secret123")
	l.Set("host", "10.0.0.1")
	l.Set("port", "3307")
	l.Set("socket", "/var/run/mysqld.sock")
	l.Set("database", "shop")
	l.Set("ssl-mode", "REQUIRED")

	m := l.Map()
	if m["user"] != "alice" || m["password"] != "secret123" || m["host"] != "10.0.0.1" ||
		m["port"] != "3307" || m["socket"] != "/var/run/mysqld.sock" ||
		m["database"] != "shop" || m["ssl-mode"] != "REQUIRED" {
		t.Errorf("unexpected Map() output: %v", m)
	}
}
