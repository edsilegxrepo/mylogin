// Objective: Configure transport layer security (TLS) and mutual TLS (mTLS) for database
// connections initiated via Login.Connector() and Login.Open(), mapping canonical MySQL
// SSL options into Go crypto/tls configurations and registering them with go-sql-driver/mysql.
//
// Core Components:
//   - configWithTLS: Clones/generates base driver configuration and applies parsed TLS parameters.
//   - applyTLS: Translates MySQL ssl-mode/ssl-ca/ssl-cert/ssl-key settings to *tls.Config.
//   - loadRootCAs: Reads and parses PEM-encoded certificate authorities into an x509.CertPool.
//   - verifyPeerCertificateAgainstRoots: Custom verification function for VERIFY_CA mode without hostname enforcement.
//
// Functionality:
//   - Supports standard MySQL ssl-mode options: DISABLED, REQUIRED, VERIFY_CA, VERIFY_IDENTITY, or custom profiles.
//   - Automatically defaults ssl-mode to REQUIRED when TLS materials (ssl-ca, ssl-cert, ssl-key) are provided without an explicit mode.
//   - Validates mutual TLS requirements: ensures ssl-cert and ssl-key are paired together.
//   - Thread-safely generates and registers unique TLS config names with mysql.RegisterTLSConfig.
//
// Data Flow:
//
//	Login.Extra (ssl-mode, ssl-ca, etc.) -> applyTLS -> crypto/tls.Config -> mysql.RegisterTLSConfig(name) -> cfg.TLSConfig = name
package mylogin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-sql-driver/mysql"
)

// registeredTLSConfigs caches registered profile identifiers to prevent redundant registrations
// and avoid unbounded memory growth in the MySQL driver's package-level registry.
var registeredTLSConfigs sync.Map

// configWithTLS returns a mysql.Config initialized with the connection credentials and
// enriched with custom TLS settings if any SSL options are configured in Login.Extra.
func (l *Login) configWithTLS() (*mysql.Config, error) {
	cfg := l.Config()
	if l == nil || l.Extra == nil {
		return cfg, nil
	}
	if err := l.applyTLS(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseTLSVersion parses standard MySQL/TLS version strings into crypto/tls version constants.
func parseTLSVersion(v string) uint16 {
	s := strings.TrimSpace(v)
	s = strings.Trim(s, `"'`)
	switch strings.ToUpper(s) {
	case "TLSV1", "TLSV1.0":
		return tls.VersionTLS10
	case "TLSV1.1":
		return tls.VersionTLS11
	case "TLSV1.2":
		return tls.VersionTLS12
	case "TLSV1.3":
		return tls.VersionTLS13
	default:
		return 0
	}
}

// parseCipherSuites translates colon-, comma-, or space-separated cipher suite names into crypto/tls IDs.
// It checks both standard secure cipher suites and legacy/insecure cipher suites supported by Go crypto/tls.
func parseCipherSuites(ciphers string) []uint16 {
	if ciphers == "" {
		return nil
	}
	tokens := strings.FieldsFunc(ciphers, func(r rune) bool {
		return r == ':' || r == ',' || r == ' '
	})
	available := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	var ids []uint16
	for _, tok := range tokens {
		clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(tok, "-", "_"), " ", ""))
		for _, cs := range available {
			csClean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(cs.Name, "-", "_"), " ", ""))
			if clean == csClean || clean == strings.TrimPrefix(csClean, "TLS_") {
				ids = append(ids, cs.ID)
				break
			}
		}
	}
	return ids
}

// isCertFile reports whether a filename has a recognized CA certificate extension
// (.pem, .crt, .cer) or an OpenSSL c_rehash numeric hash extension (.0, .1, ...).
func isCertFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	if ext == ".pem" || ext == ".crt" || ext == ".cer" {
		return true
	}
	if len(ext) > 1 && ext[0] == '.' {
		for _, r := range ext[1:] {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// loadPEMsFromDir reads all PEM-encoded certificates from files in dir and appends them to pool.
// It recognizes .pem, .crt, .cer files as well as OpenSSL c_rehash hash symlinks (.0, .1, ...).
// It returns the count of certificates successfully appended.
func loadPEMsFromDir(dir string, pool *x509.CertPool) (int, error) {
	cleanDir := filepath.Clean(dir)
	entries, err := os.ReadDir(cleanDir) // #nosec G304 -- library intentionally reads caller-specified CA directory
	if err != nil {
		return 0, fmt.Errorf("read ssl-capath directory: %w", err)
	}
	loaded := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if isCertFile(entry.Name()) {
			certData, err := os.ReadFile(filepath.Join(cleanDir, entry.Name())) // #nosec G304
			if err == nil && pool.AppendCertsFromPEM(certData) {
				loaded++
			}
		}
	}
	return loaded, nil
}

// loadRootCADir reads all PEM-encoded certificates from files in a directory and returns an x509.CertPool.
func loadRootCADir(dir string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	loaded, err := loadPEMsFromDir(dir, pool)
	if err != nil {
		return nil, err
	}
	if loaded == 0 {
		return nil, fmt.Errorf("parse ssl-capath: no certificates loaded from %s", dir)
	}
	return pool, nil
}

// loadRootCAPool reads CA certificates from both a file (ssl-ca) and/or a directory (ssl-capath).
func loadRootCAPool(caPath, caDir string) (*x509.CertPool, error) {
	if caPath == "" && caDir == "" {
		return nil, nil
	}
	if caPath != "" && caDir == "" {
		return loadRootCAs(caPath)
	}
	if caPath == "" && caDir != "" {
		return loadRootCADir(caDir)
	}
	pool, err := loadRootCAs(caPath)
	if err != nil {
		return nil, err
	}
	if _, err := loadPEMsFromDir(caDir, pool); err != nil {
		return nil, err
	}
	return pool, nil
}

// applyTLS inspects ssl-* and tls-* options in Login.Extra, constructs the corresponding *tls.Config,
// registers it with the mysql driver under a unique key, and updates cfg.TLSConfig.
func (l *Login) applyTLS(cfg *mysql.Config) error {
	mode, hasMode := l.Extra["ssl-mode"]
	caPath, hasCA := l.Extra["ssl-ca"]
	caDir, hasCADir := l.Extra["ssl-capath"]
	certPath, hasCert := l.Extra["ssl-cert"]
	keyPath, hasKey := l.Extra["ssl-key"]
	tlsVersionStr, hasTLSVersion := l.Extra["tls-version"]
	cipherStr, hasCipher := l.Extra["ssl-cipher"]
	if !hasCipher {
		cipherStr, hasCipher = l.Extra["tls-ciphersuites"]
	}
	hasVerifyServerCert := isTruthy(l.Extra["ssl-verify-server-cert"])

	if !hasMode {
		if isTruthy(l.Extra["skip-ssl"]) {
			mode = "DISABLED"
			hasMode = true
		} else if sslVal, ok := l.Extra["ssl"]; ok {
			if !isTruthy(sslVal) {
				mode = "DISABLED"
				hasMode = true
			} else {
				mode = "REQUIRED"
				hasMode = true
			}
		}
	}

	// If no TLS options are present, leave driver default TLS settings intact.
	if !hasMode && !hasCA && !hasCADir && !hasCert && !hasKey && !hasTLSVersion && !hasCipher && !hasVerifyServerCert {
		return nil
	}

	upperMode := strings.ToUpper(mode)
	if !hasMode && hasVerifyServerCert {
		upperMode = "VERIFY_IDENTITY"
	} else if !hasMode && (hasCA || hasCADir || hasCert || hasKey || hasTLSVersion || hasCipher) {
		upperMode = "REQUIRED"
	}

	tlsCfg := &tls.Config{}
	switch upperMode {
	case "", "DISABLED":
		cfg.TLSConfig = "false"
		return nil

	case "REQUIRED":
		// Encrypted connection required, but certificate verification is skipped.
		tlsCfg.InsecureSkipVerify = true

	case "VERIFY_CA":
		// Verify the certificate chain against the trusted CA, but do not require hostname verification.
		tlsCfg.InsecureSkipVerify = true
		var roots *x509.CertPool
		if hasCA || hasCADir {
			var err error
			roots, err = loadRootCAPool(caPath, caDir)
			if err != nil {
				return err
			}
			tlsCfg.RootCAs = roots
		}
		// If roots is nil, verification validates against the host's system root CAs.
		tlsCfg.VerifyPeerCertificate = verifyPeerCertificateAgainstRoots(roots)
		tlsCfg.VerifyConnection = verifyConnectionAgainstRoots(roots)

	case "VERIFY_IDENTITY":
		// Full verification: verify certificate chain against CA and verify server hostname.
		if hasCA || hasCADir {
			roots, err := loadRootCAPool(caPath, caDir)
			if err != nil {
				return err
			}
			tlsCfg.RootCAs = roots
		}

	default:
		// Passthrough for predefined driver configurations (e.g. "true", "skip-verify", or custom driver profiles).
		cfg.TLSConfig = mode
		return nil
	}

	// In REQUIRED mode, if a custom CA was supplied, load it into RootCAs for optional server validation.
	if (hasCA || hasCADir) && upperMode == "REQUIRED" {
		roots, err := loadRootCAPool(caPath, caDir)
		if err != nil {
			return err
		}
		tlsCfg.RootCAs = roots
	}

	// Configure mutual TLS (mTLS) if client certificate or private key is specified.
	if hasCert || hasKey {
		if !hasCert || !hasKey {
			return fmt.Errorf("ssl-cert and ssl-key must both be set when either is present")
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	// Configure TLS min/max version if specified
	if hasTLSVersion && tlsVersionStr != "" {
		parts := strings.FieldsFunc(tlsVersionStr, func(r rune) bool {
			return r == ',' || r == ' '
		})
		var minVer, maxVer uint16
		for _, part := range parts {
			if v := parseTLSVersion(part); v != 0 {
				if minVer == 0 || v < minVer {
					minVer = v
				}
				if v > maxVer {
					maxVer = v
				}
			}
		}
		if minVer != 0 {
			tlsCfg.MinVersion = minVer
		}
		if maxVer != 0 {
			tlsCfg.MaxVersion = maxVer
		}
	}

	// Configure custom cipher suites if specified
	if hasCipher && cipherStr != "" {
		if ciphers := parseCipherSuites(cipherStr); len(ciphers) > 0 {
			tlsCfg.CipherSuites = ciphers
		}
	}

	// Compute deterministic registration key from configuration parameters to prevent memory leaks in driver registry.
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		upperMode, caPath, certPath, keyPath, caDir, tlsVersionStr, cipherStr)
	name := fmt.Sprintf("mylogin_tls_%x", h.Sum(nil)[:8])

	if _, loaded := registeredTLSConfigs.LoadOrStore(name, struct{}{}); !loaded {
		if err := mysql.RegisterTLSConfig(name, tlsCfg); err != nil {
			registeredTLSConfigs.Delete(name)
			return fmt.Errorf("register tls config: %w", err)
		}
	}
	cfg.TLSConfig = name
	return nil
}

// loadRootCAs reads a PEM-encoded certificate authority file and returns an x509.CertPool.
func loadRootCAs(path string) (*x509.CertPool, error) {
	cleanPath := filepath.Clean(path)
	pemData, err := os.ReadFile(cleanPath) // #nosec G304 -- library intentionally reads caller-specified CA file
	if err != nil {
		return nil, fmt.Errorf("read ssl-ca file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("parse ssl-ca file: no certificates loaded")
	}
	return pool, nil
}

// verifyPeerCertificateAgainstRoots constructs a verification closure that validates the presented
// server certificates against the root CA pool without requiring server name (hostname) matching.
func verifyPeerCertificateAgainstRoots(roots *x509.CertPool) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no server certificates presented")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		intermediates := x509.NewCertPool()
		for _, raw := range rawCerts[1:] {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return err
			}
			intermediates.AddCert(cert)
		}
		_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates})
		return err
	}
}

// verifyConnectionAgainstRoots constructs a verification closure for tls.Config.VerifyConnection,
// ensuring resumed TLS sessions cannot bypass custom certificate chain validation (CWE-295 / gosec G123).
func verifyConnectionAgainstRoots(roots *x509.CertPool) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("no server certificates presented")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		})
		return err
	}
}
