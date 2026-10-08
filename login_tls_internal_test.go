// Objective: Comprehensive internal unit and integration test suite for TLS/mTLS translation,
// cryptographic certificate chain validation, and driver profile registration in login_tls.go.
//
// Core Components Tested:
//   - configWithTLS, applyTLS, loadRootCAs, verifyPeerCertificateAgainstRoots, Login.Connector.
//
// Test Strategy:
//   - In-Memory PKI Generation: Dynamically generate self-signed ECDSA P-256 Root CAs, valid leaf certificates,
//     and untrusted rogue certificates to perform real cryptographic validation without external network or file dependencies.
//   - Mode Permutations: Systematically test all MySQL ssl-mode values (DISABLED, REQUIRED, VERIFY_CA, VERIFY_IDENTITY, and passthrough).
//   - Cryptographic Error Injection: Test missing key/cert pairs, corrupted PEM files, nonexistent paths, and untrusted roots.
//   - Driver Connector Integration: Verify Login.Connector() successfully creates valid driver.Connector handles with active TLS profiles.
//
// Functionality:
//   - Verifies translation of MySQL SSL options to *tls.Config and driver registration.
//   - Verifies custom peer certificate chain validation.
//   - Verifies error propagation on malformed or incomplete TLS configurations.
//
// Data Flow:
//
//	generateTestPKI -> PEM artifacts -> applyTLS -> mysql.RegisterTLSConfig -> Login.Connector
package mylogin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// generateTestPKI generates an ephemeral in-memory Public Key Infrastructure for testing:
//  1. Root CA certificate and private key.
//  2. Trusted client/server leaf certificate and private key signed by the Root CA.
//  3. Untrusted rogue leaf certificate signed by an unrelated key pair.
func generateTestPKI(t *testing.T, tmpDir string) (caPEMFile, certPEMFile, keyPEMFile string, rootCert *x509.Certificate, leafDER []byte, untrustedLeafDER []byte) {
	t.Helper()

	// 1. Root CA Key and Cert
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey CA: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "MyLogin Test Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	rootCert, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}

	caPEMFile = filepath.Join(tmpDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(caPEMFile, caPEM, 0o600); err != nil {
		t.Fatalf("write ca.pem: %v", err)
	}

	// 2. Trusted Leaf Client / Server Key and Cert
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey leaf: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "db.internal",
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"db.internal", "localhost"},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate leaf: %v", err)
	}

	certPEMFile = filepath.Join(tmpDir, "client-cert.pem")
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	if err := os.WriteFile(certPEMFile, leafPEM, 0o600); err != nil {
		t.Fatalf("write client-cert.pem: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEMFile = filepath.Join(tmpDir, "client-key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPEMFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write client-key.pem: %v", err)
	}

	// 3. Untrusted Self-Signed Leaf Cert (not signed by Root CA)
	untrustedKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	untrustedTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "rogue.host"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	untrustedLeafDER, _ = x509.CreateCertificate(rand.Reader, untrustedTemplate, untrustedTemplate, &untrustedKey.PublicKey, untrustedKey)

	return caPEMFile, certPEMFile, keyPEMFile, rootCert, leafDER, untrustedLeafDER
}

// TestConfigWithTLS_NilAndEmpty verifies that nil logins, empty logins, or logins without
// extra parameters return valid default driver configurations with nil errors.
func TestConfigWithTLS_NilAndEmpty(t *testing.T) {
	var nilLogin *Login
	cfg, err := nilLogin.configWithTLS()
	if err != nil || cfg == nil {
		t.Fatalf("expected non-nil config and nil error on nil login, got cfg: %v, err: %v", cfg, err)
	}

	emptyLogin := &Login{}
	cfg, err = emptyLogin.configWithTLS()
	if err != nil || cfg == nil {
		t.Fatalf("expected non-nil config and nil error on empty login, got cfg: %v, err: %v", cfg, err)
	}

	noExtraLogin := &Login{Extra: map[string]string{}}
	cfg, err = noExtraLogin.configWithTLS()
	if err != nil || cfg == nil {
		t.Fatalf("expected non-nil config and nil error on no-extra login, got cfg: %v, err: %v", cfg, err)
	}
}

// TestApplyTLS_Modes systematically validates driver configuration and profile registration
// across all MySQL ssl-mode variations (DISABLED, empty, REQUIRED, VERIFY_CA, VERIFY_IDENTITY,
// custom passthrough, and full mutual TLS).
func TestApplyTLS_Modes(t *testing.T) {
	tmpDir := t.TempDir()
	caPEMFile, certPEMFile, keyPEMFile, _, _, _ := generateTestPKI(t, tmpDir)

	// Mode: DISABLED
	lDisabled := &Login{Extra: map[string]string{"ssl-mode": "DISABLED"}}
	cfg := mysql.NewConfig()
	if err := lDisabled.applyTLS(cfg); err != nil {
		t.Fatalf("applyTLS DISABLED failed: %v", err)
	}
	if cfg.TLSConfig != "false" {
		t.Errorf("expected TLSConfig 'false' for DISABLED, got %q", cfg.TLSConfig)
	}

	// Mode: empty string
	lEmpty := &Login{Extra: map[string]string{"ssl-mode": ""}}
	cfg = mysql.NewConfig()
	if err := lEmpty.applyTLS(cfg); err != nil {
		t.Fatalf("applyTLS empty failed: %v", err)
	}
	if cfg.TLSConfig != "false" {
		t.Errorf("expected TLSConfig 'false' for empty mode, got %q", cfg.TLSConfig)
	}

	// Mode: REQUIRED without CA
	lReq := &Login{Extra: map[string]string{"ssl-mode": "REQUIRED"}}
	cfg = mysql.NewConfig()
	if err := lReq.applyTLS(cfg); err != nil {
		t.Fatalf("applyTLS REQUIRED failed: %v", err)
	}
	if !strings.HasPrefix(cfg.TLSConfig, "mylogin_tls_") {
		t.Errorf("expected registered TLSConfig name, got %q", cfg.TLSConfig)
	}

	// Mode: REQUIRED with CA
	lReqCA := &Login{Extra: map[string]string{"ssl-mode": "REQUIRED", "ssl-ca": caPEMFile}}
	cfg = mysql.NewConfig()
	if err := lReqCA.applyTLS(cfg); err != nil {
		t.Fatalf("applyTLS REQUIRED with CA failed: %v", err)
	}
	if !strings.HasPrefix(cfg.TLSConfig, "mylogin_tls_") {
		t.Errorf("expected registered TLSConfig name, got %q", cfg.TLSConfig)
	}

	// Mode: VERIFY_CA without CA (should configure deterministic registration key)
	lVCA := &Login{Extra: map[string]string{"ssl-mode": "VERIFY_CA"}}
	cfg = mysql.NewConfig()
	if err := lVCA.applyTLS(cfg); err != nil {
		t.Fatalf("applyTLS VERIFY_CA failed: %v", err)
	}
	if !strings.HasPrefix(cfg.TLSConfig, "mylogin_tls_") {
		t.Errorf("expected registered TLSConfig name, got %q", cfg.TLSConfig)
	}
	vcaName := cfg.TLSConfig

	// Re-run applyTLS with identical settings to assert deterministic key caching
	cfg2 := mysql.NewConfig()
	if err := lVCA.applyTLS(cfg2); err != nil {
		t.Fatalf("applyTLS repeated failed: %v", err)
	}
	if cfg2.TLSConfig != vcaName {
		t.Errorf("expected deterministic cached name %q, got %q", vcaName, cfg2.TLSConfig)
	}

	// Mode: VERIFY_CA with CA
	lVCACA := &Login{Extra: map[string]string{"ssl-mode": "VERIFY_CA", "ssl-ca": caPEMFile}}
	cfg = mysql.NewConfig()
	if err := lVCACA.applyTLS(cfg); err != nil {
		t.Fatalf("applyTLS VERIFY_CA with CA failed: %v", err)
	}
	if !strings.HasPrefix(cfg.TLSConfig, "mylogin_tls_") {
		t.Errorf("expected registered TLSConfig name, got %q", cfg.TLSConfig)
	}

	// Mode: VERIFY_IDENTITY with CA
	lVIDCA := &Login{Extra: map[string]string{"ssl-mode": "VERIFY_IDENTITY", "ssl-ca": caPEMFile}}
	cfg = mysql.NewConfig()
	if err := lVIDCA.applyTLS(cfg); err != nil {
		t.Fatalf("applyTLS VERIFY_IDENTITY with CA failed: %v", err)
	}
	if !strings.HasPrefix(cfg.TLSConfig, "mylogin_tls_") {
		t.Errorf("expected registered TLSConfig name, got %q", cfg.TLSConfig)
	}

	// Mode: Custom / Unknown mode passthrough
	lCustom := &Login{Extra: map[string]string{"ssl-mode": "custom-tls-profile"}}
	cfg = mysql.NewConfig()
	if err := lCustom.applyTLS(cfg); err != nil {
		t.Fatalf("applyTLS custom failed: %v", err)
	}
	if cfg.TLSConfig != "custom-tls-profile" {
		t.Errorf("expected custom TLSConfig passthrough, got %q", cfg.TLSConfig)
	}

	// mTLS: Full client cert and key
	lMTLS := &Login{Extra: map[string]string{
		"ssl-mode": "VERIFY_IDENTITY",
		"ssl-ca":   caPEMFile,
		"ssl-cert": certPEMFile,
		"ssl-key":  keyPEMFile,
	}}
	cfg = mysql.NewConfig()
	if err := lMTLS.applyTLS(cfg); err != nil {
		t.Fatalf("applyTLS mTLS failed: %v", err)
	}
	if !strings.HasPrefix(cfg.TLSConfig, "mylogin_tls_") {
		t.Errorf("expected registered TLSConfig name, got %q", cfg.TLSConfig)
	}
}

// TestApplyTLS_ErrorBranches asserts failure and error handling across broken, partial,
// or non-existent TLS configuration parameters.
func TestApplyTLS_ErrorBranches(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Missing ssl-key when ssl-cert is present
	lMissingKey := &Login{Extra: map[string]string{"ssl-cert": "cert.pem"}}
	if err := lMissingKey.applyTLS(mysql.NewConfig()); err == nil {
		t.Error("expected error when ssl-key is missing")
	}

	// 2. Missing ssl-cert when ssl-key is present
	lMissingCert := &Login{Extra: map[string]string{"ssl-key": "key.pem"}}
	if err := lMissingCert.applyTLS(mysql.NewConfig()); err == nil {
		t.Error("expected error when ssl-cert is missing")
	}

	// 3. Non-existent cert and key files
	lNonExistent := &Login{Extra: map[string]string{
		"ssl-cert": filepath.Join(tmpDir, "missing-cert.pem"),
		"ssl-key":  filepath.Join(tmpDir, "missing-key.pem"),
	}}
	if err := lNonExistent.applyTLS(mysql.NewConfig()); err == nil {
		t.Error("expected error loading non-existent client certificate")
	}

	// 4. Non-existent CA file in VERIFY_CA
	lMissingCA := &Login{Extra: map[string]string{
		"ssl-mode": "VERIFY_CA",
		"ssl-ca":   filepath.Join(tmpDir, "nonexistent-ca.pem"),
	}}
	if err := lMissingCA.applyTLS(mysql.NewConfig()); err == nil {
		t.Error("expected error loading non-existent ssl-ca file in VERIFY_CA")
	}

	// 5. Non-existent CA file in VERIFY_IDENTITY
	lMissingCAIdent := &Login{Extra: map[string]string{
		"ssl-mode": "VERIFY_IDENTITY",
		"ssl-ca":   filepath.Join(tmpDir, "nonexistent-ca.pem"),
	}}
	if err := lMissingCAIdent.applyTLS(mysql.NewConfig()); err == nil {
		t.Error("expected error loading non-existent ssl-ca file in VERIFY_IDENTITY")
	}

	// 6. Non-existent CA file in REQUIRED
	lMissingCAReq := &Login{Extra: map[string]string{
		"ssl-mode": "REQUIRED",
		"ssl-ca":   filepath.Join(tmpDir, "nonexistent-ca.pem"),
	}}
	if err := lMissingCAReq.applyTLS(mysql.NewConfig()); err == nil {
		t.Error("expected error loading non-existent ssl-ca file in REQUIRED")
	}

	// 7. Corrupted CA file (no certificates)
	corruptCA := filepath.Join(tmpDir, "corrupt-ca.pem")
	_ = os.WriteFile(corruptCA, []byte("plain text not pem"), 0o600)
	lCorruptCA := &Login{Extra: map[string]string{
		"ssl-mode": "VERIFY_CA",
		"ssl-ca":   corruptCA,
	}}
	if err := lCorruptCA.applyTLS(mysql.NewConfig()); err == nil {
		t.Error("expected error for empty/invalid PEM ssl-ca file")
	}
}

// TestVerifyPeerCertificateAgainstRoots tests the custom peer verification closure used in
// VERIFY_CA mode, verifying valid certificates and rejecting corrupted or untrusted certificates.
func TestVerifyPeerCertificateAgainstRoots(t *testing.T) {
	tmpDir := t.TempDir()
	caPEMFile, _, _, _, leafDER, untrustedLeafDER := generateTestPKI(t, tmpDir)

	roots, err := loadRootCAs(caPEMFile)
	if err != nil {
		t.Fatalf("loadRootCAs: %v", err)
	}

	verifier := verifyPeerCertificateAgainstRoots(roots)

	// Empty certificate list
	if err := verifier([][]byte{}, nil); err == nil {
		t.Error("expected error on empty certificates list")
	}

	// Corrupted certificate bytes
	if err := verifier([][]byte{[]byte("not a valid cert")}, nil); err == nil {
		t.Error("expected error on invalid cert bytes")
	}

	// Corrupted intermediate certificate bytes
	if err := verifier([][]byte{leafDER, []byte("not a valid intermediate")}, nil); err == nil {
		t.Error("expected error on invalid intermediate cert bytes")
	}

	// Valid certificate signed by roots
	if err := verifier([][]byte{leafDER}, nil); err != nil {
		t.Errorf("expected valid leaf certificate to verify cleanly, got: %v", err)
	}

	// Untrusted certificate not signed by roots
	if err := verifier([][]byte{untrustedLeafDER}, nil); err == nil {
		t.Error("expected verification failure for untrusted certificate")
	}
}

// TestVerifyConnectionAgainstRoots tests tls.ConnectionState validation logic
// ensuring TLS session resumption certificate validation functions correctly.
func TestVerifyConnectionAgainstRoots(t *testing.T) {
	tmpDir := t.TempDir()
	_, _, _, rootCert, leafDER, untrustedLeafDER := generateTestPKI(t, tmpDir)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	verifier := verifyConnectionAgainstRoots(rootPool)

	// 1. Empty peer certificates
	if err := verifier(tls.ConnectionState{PeerCertificates: nil}); err == nil {
		t.Error("expected error for empty peer certificates")
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate leaf: %v", err)
	}

	// 2. Valid peer certificates
	if err := verifier(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leafCert}}); err != nil {
		t.Errorf("expected valid certificate to pass, got: %v", err)
	}

	// 3. Valid peer certificates with intermediate
	if err := verifier(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leafCert, rootCert}}); err != nil {
		t.Errorf("expected valid certificate with intermediate to pass, got: %v", err)
	}

	// 4. Untrusted peer certificate
	untrustedCert, err := x509.ParseCertificate(untrustedLeafDER)
	if err != nil {
		t.Fatalf("ParseCertificate untrusted: %v", err)
	}
	if err := verifier(tls.ConnectionState{PeerCertificates: []*x509.Certificate{untrustedCert}}); err == nil {
		t.Error("expected error for untrusted peer certificate")
	}
}

// TestLoginConnector_TLSIntegration tests end-to-end driver.Connector creation with full TLS/mTLS
// configurations and verifies immediate failure on broken TLS settings.
func TestLoginConnector_TLSIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	caPEMFile, certPEMFile, keyPEMFile, _, _, _ := generateTestPKI(t, tmpDir)

	login := &Login{
		Extra: map[string]string{
			"ssl-mode": "VERIFY_IDENTITY",
			"ssl-ca":   caPEMFile,
			"ssl-cert": certPEMFile,
			"ssl-key":  keyPEMFile,
		},
	}
	connector, err := login.Connector("analytics_db")
	if err != nil {
		t.Fatalf("Connector failed: %v", err)
	}
	if connector == nil {
		t.Fatal("expected non-nil connector")
	}

	// Error path: missing certificate file
	brokenLogin := &Login{
		Extra: map[string]string{
			"ssl-cert": "/missing/cert.pem",
		},
	}
	_, err = brokenLogin.Connector("testdb")
	if err == nil {
		t.Fatal("expected Connector to fail on invalid TLS settings")
	}
}
