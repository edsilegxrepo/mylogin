package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edsilegxrepo/mylogin"
)

func strPtr(s string) *string {
	return &s
}

func TestLoginAsMap(t *testing.T) {
	login := &mylogin.Login{
		User:     strPtr("admin"),
		Password: strPtr("secret"),
		Host:     strPtr("127.0.0.1"),
		Port:     strPtr("3306"),
		Socket:   strPtr("/tmp/mysql.sock"),
		Extra:    map[string]string{"database": "shop_db"},
	}

	m := loginAsMap(login)
	if m["user"] != "admin" || m["password"] != "secret" || m["host"] != "127.0.0.1" || m["port"] != "3306" || m["socket"] != "/tmp/mysql.sock" || m["database"] != "shop_db" {
		t.Errorf("loginAsMap mismatch: %+v", m)
	}
}

func TestFormatsPrint(t *testing.T) {
	section := &mylogin.Section{
		Name: "client_slave",
		Login: mylogin.Login{
			User:     strPtr("repl_user"),
			Password: strPtr("repl_pass"),
			Host:     strPtr("slave.internal"),
			Port:     strPtr("3307"),
			Socket:   strPtr("/var/run/mysql.sock"),
		},
	}

	// 1. Test formatJSON
	var jsonBuf bytes.Buffer
	jsonFmt := &formatJSON{}
	if name, _ := jsonFmt.Help(); name != "json" {
		t.Errorf("unexpected help name: %s", name)
	}
	if err := jsonFmt.Print(&jsonBuf, section); err != nil {
		t.Fatalf("formatJSON.Print failed: %v", err)
	}
	jsonStr := jsonBuf.String()
	if !strings.Contains(jsonStr, `"user": "repl_user"`) || !strings.Contains(jsonStr, `"host": "slave.internal"`) {
		t.Errorf("formatJSON output missing fields: %s", jsonStr)
	}

	// 2. Test formatReplay
	var replayBuf bytes.Buffer
	replayFmt := &formatReplay{}
	if name, _ := replayFmt.Help(); name != "replay" {
		t.Errorf("unexpected help name: %s", name)
	}
	if err := replayFmt.Print(&replayBuf, section); err != nil {
		t.Fatalf("formatReplay.Print failed: %v", err)
	}
	replayStr := replayBuf.String()
	expectedArgs := []string{"mysql_config_editor set --skip-warn -G client_slave", "-u repl_user", "-p", "-h slave.internal", "-P 3307", "-S /var/run/mysql.sock"}
	for _, arg := range expectedArgs {
		if !strings.Contains(replayStr, arg) {
			t.Errorf("formatReplay missing arg %q in %s", arg, replayStr)
		}
	}

	// 3. Test formatRemove
	var removeBuf bytes.Buffer
	removeFmt := &formatRemove{}
	if name, _ := removeFmt.Help(); name != "remove" {
		t.Errorf("unexpected help name: %s", name)
	}
	if err := removeFmt.Print(&removeBuf, section); err != nil {
		t.Fatalf("formatRemove.Print failed: %v", err)
	}
	if !strings.Contains(removeBuf.String(), "mysql_config_editor remove -G client_slave") {
		t.Errorf("formatRemove mismatch: %s", removeBuf.String())
	}

	// 4. Test formatTemplate with groupSuffix and json func
	tmplFmt := &formatTemplate{}
	if name, _ := tmplFmt.Help(); name != "template" {
		t.Errorf("unexpected help name: %s", name)
	}
	if tmplFmt.String() != "" {
		t.Errorf("expected empty string before Set")
	}
	if err := tmplFmt.Set("Section={{.section}} Suffix={{.groupSuffix}} User={{.user}} JSON={{json .user}}"); err != nil {
		t.Fatalf("tmplFmt.Set failed: %v", err)
	}
	if tmplFmt.Get() == nil {
		t.Errorf("expected non-nil Get() after Set")
	}
	if tmplFmt.String() != "<template>" {
		t.Errorf("expected <template>, got %s", tmplFmt.String())
	}

	var tmplBuf bytes.Buffer
	if err := tmplFmt.Print(&tmplBuf, section); err != nil {
		t.Fatalf("tmplFmt.Print failed: %v", err)
	}
	tmplStr := tmplBuf.String()
	if !strings.Contains(tmplStr, "Section=client_slave Suffix=_slave User=repl_user JSON=\"repl_user\"") {
		t.Errorf("template output mismatch: %s", tmplStr)
	}

	// 5. Test formatTemplateLn
	tmplLnFmt := &formatTemplateLn{}
	if name, _ := tmplLnFmt.Help(); name != "templateln" {
		t.Errorf("unexpected help name: %s", name)
	}
	if err := tmplLnFmt.Set("User={{.user}}"); err != nil {
		t.Fatalf("tmplLnFmt.Set failed: %v", err)
	}
	var tmplLnBuf bytes.Buffer
	if err := tmplLnFmt.Print(&tmplLnBuf, section); err != nil {
		t.Fatalf("tmplLnFmt.Print failed: %v", err)
	}
	if !strings.HasSuffix(tmplLnBuf.String(), "\n") {
		t.Errorf("expected trailing newline in formatTemplateLn output")
	}

	// 6. Test outputFormatBool methods
	bFmt := &outputFormatBool{}
	if !bFmt.IsBoolFlag() {
		t.Errorf("expected IsBoolFlag to be true")
	}
	if bFmt.Get() != nil {
		t.Errorf("expected nil Get() when bool is false")
	}
	if err := bFmt.Set("true"); err != nil {
		t.Fatalf("bFmt.Set failed: %v", err)
	}
	if bFmt.Get() != true {
		t.Errorf("expected true Get() when bool is true")
	}
	if bFmt.String() != "true" {
		t.Errorf("expected 'true', got %s", bFmt.String())
	}
	if err := bFmt.Set("invalid_bool"); err == nil {
		t.Errorf("expected error parsing invalid bool")
	}
}

func TestRunMyLogin(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, ".mylogin.cnf")

	rawContent := "[client]\nhost = \"localhost\"\nport = 3306\n[analytics]\nuser = \"analyst\"\npassword = \"pass123\"\n"
	if err := mylogin.WriteFile(confPath, strings.NewReader(rawContent)); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// 1. Successful run dumping full plaintext
	var stdout, stderr bytes.Buffer
	code := run([]string{"-file", confPath}, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "[client]") || !strings.Contains(stdout.String(), "[analytics]") {
		t.Errorf("expected dump of sections, got: %s", stdout.String())
	}

	// 2. Successful run with -json on all sections
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", confPath, "-json"}, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess with -json, got %d", code)
	}
	if !strings.Contains(stdout.String(), `"user": "analyst"`) {
		t.Errorf("expected JSON output, got: %s", stdout.String())
	}

	// 3. Successful run with -replay on specific section
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", confPath, "-replay", "analytics"}, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess with -replay, got %d", code)
	}
	if !strings.Contains(stdout.String(), "mysql_config_editor set --skip-warn -G analytics") {
		t.Errorf("expected replay output, got: %s", stdout.String())
	}

	// 4. Section not found
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", confPath, "-json", "missing_section"}, &stdout, &stderr)
	if code != exitNotFound {
		t.Fatalf("expected exitNotFound, got %d", code)
	}

	// 5. Mutually exclusive flags
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", confPath, "-json", "-replay"}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("expected exitUsage, got %d", code)
	}

	// 6. Missing file
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", filepath.Join(tempDir, "missing.cnf")}, &stdout, &stderr)
	if code != exitFileError {
		t.Fatalf("expected exitFileError, got %d", code)
	}

	// 7. Raw plain text filtered by section (no format flag, with section arg)
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", confPath, "analytics"}, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess, got %d", code)
	}
	if !strings.Contains(stdout.String(), "user = \"analyst\"") || strings.Contains(stdout.String(), "[client]") {
		t.Errorf("expected filtered raw section output, got: %s", stdout.String())
	}

	// 8. Corrupted file error branches
	corruptedPath := filepath.Join(tempDir, "corrupted.cnf")
	if err := os.WriteFile(corruptedPath, []byte("short_corrupted_header"), 0o600); err != nil {
		t.Fatalf("failed to write corrupted file: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", corruptedPath}, &stdout, &stderr)
	if code != exitFormatError {
		t.Fatalf("expected exitFormatError on raw corrupted file, got %d", code)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", corruptedPath, "-json"}, &stdout, &stderr)
	if code != exitFormatError {
		t.Fatalf("expected exitFormatError on formatted corrupted file, got %d", code)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-file", corruptedPath, "-json", "client"}, &stdout, &stderr)
	if code != exitFormatError {
		t.Fatalf("expected exitFormatError on formatted single-section corrupted file, got %d", code)
	}

	// 9. Invalid flag
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-invalid-flag-xyz"}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("expected exitUsage on invalid flag, got %d", code)
	}

	// 10. Version flag
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-V"}, &stdout, &stderr)
	if code != exitSuccess || !strings.Contains(stdout.String(), "mylogin version") {
		t.Fatalf("expected version output, got code %d, stdout: %s", code, stdout.String())
	}
}

func TestFormatTemplateInvalid(t *testing.T) {
	tmplFmt := &formatTemplate{}
	if err := tmplFmt.Set("{{.invalid unclosed template"); err == nil {
		t.Fatalf("expected error for unclosed template")
	}
}

func TestRunMyLoginSubcommands(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, ".mylogin.cnf")

	var stdout, stderr bytes.Buffer

	// 1. Test set with non-interactive pass flag
	code := runWithStdin([]string{
		"set",
		"-file", confPath,
		"-login-path", "staging",
		"-user", "deployer",
		"-host", "10.0.0.12",
		"-port", "3308",
		"-pass", "DeployPass123",
	}, nil, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess for set, got %d, stderr: %s", code, stderr.String())
	}

	// 2. Test set with password prompt via stdin
	stdout.Reset()
	stderr.Reset()
	code = runWithStdin([]string{
		"set",
		"-file", confPath,
		"-G", "prod",
		"-u", "admin",
		"-h", "10.0.0.1",
		"-p",
	}, strings.NewReader("PromptSecret456\n"), &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess for set with prompt, got %d, stderr: %s", code, stderr.String())
	}

	// 3. Test list
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"list", "-file", confPath}, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess for list, got %d, stderr: %s", code, stderr.String())
	}
	listOut := stdout.String()
	if !strings.Contains(listOut, "staging") || !strings.Contains(listOut, "prod") {
		t.Errorf("list output missing sections: %s", listOut)
	}

	// 4. Test remove
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"remove", "-file", confPath, "-G", "staging"}, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess for remove, got %d, stderr: %s", code, stderr.String())
	}

	// Verify staging is removed from list
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"list", "-file", confPath}, &stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("expected exitSuccess for list post-remove, got %d", code)
	}
	if strings.Contains(stdout.String(), "staging") {
		t.Errorf("expected staging to be removed, but still present: %s", stdout.String())
	}

	// 5. Test remove on non-existent section
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"remove", "-file", confPath, "non_existent"}, &stdout, &stderr)
	if code != exitNotFound {
		t.Fatalf("expected exitNotFound for missing section remove, got %d", code)
	}

	// 6. Test remove without section name
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"remove", "-file", confPath}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("expected exitUsage for remove without section, got %d", code)
	}

	// 7. Test invalid flag in set
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"set", "-invalid-flag"}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("expected exitUsage for set with bad flag, got %d", code)
	}

	// 8. Test list on missing file
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"list", "-file", filepath.Join(tempDir, "missing.cnf")}, &stdout, &stderr)
	if code != exitFileError {
		t.Fatalf("expected exitFileError for list on missing file, got %d", code)
	}
}
