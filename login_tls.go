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

// applyTLS inspects ssl-* options in Login.Extra, constructs the corresponding *tls.Config,
// registers it with the mysql driver under a unique key, and updates cfg.TLSConfig.
func (l *Login) applyTLS(cfg *mysql.Config) error {
	mode, hasMode := l.Extra["ssl-mode"]
	caPath, hasCA := l.Extra["ssl-ca"]
	certPath, hasCert := l.Extra["ssl-cert"]
	keyPath, hasKey := l.Extra["ssl-key"]

	// If no TLS options are present, leave driver default TLS settings intact.
	if !hasMode && !hasCA && !hasCert && !hasKey {
		return nil
	}

	upperMode := strings.ToUpper(mode)
	// If certificates/keys are provided without explicit mode, default to REQUIRED.
	if !hasMode && (hasCA || hasCert || hasKey) {
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
		if hasCA {
			var err error
			roots, err = loadRootCAs(caPath)
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
		if hasCA {
			roots, err := loadRootCAs(caPath)
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
	if hasCA && upperMode == "REQUIRED" {
		roots, err := loadRootCAs(caPath)
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

	// Compute deterministic registration key from configuration parameters to prevent memory leaks in driver registry.
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s", upperMode, caPath, certPath, keyPath)
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
