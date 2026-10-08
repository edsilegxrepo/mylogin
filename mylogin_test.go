// Package mylogin provides unit tests for key lifecycle and initialization routines.
//
// Objective: Validate unit-level key lifecycle operations, zero-value detection,
// and cryptographically random key generation invariants.
//
// Core Components:
//   - TestKeyIsZero: Edge testing of IsZero with various byte positions set or cleared.
//   - TestKeyNew: Cryptographic key generation using crypto/rand with 5-bit masking assertion.
//
// Test Strategy:
//   - Zero-State Invariant: Ensure Key.IsZero returns true only when all 20 bytes are 0x00.
//   - Masking Assertion: Verify that NewKey clears the top 3 bits of each byte (byte < 32).
//
// Functionality:
//   - Ensures key management adheres strictly to MySQL format constraints and uninitialized detection.
//
// Data Flow:
//
//	crypto/rand.Read -> NewKey -> Bitmask Verification (b < 32) -> Assertions.
package mylogin

import (
	"crypto/rand"
	"testing"
)

func TestKeyIsZero(t *testing.T) {
	var key Key
	if !key.IsZero() {
		t.Fatal("should be IsZero")
	}
	key[19] = 2
	if key.IsZero() {
		t.Fatal("should not be IsZero")
	}
	key[0] = 5
	if key.IsZero() {
		t.Fatal("should not be IsZero")
	}
}

func TestKeyNew(t *testing.T) {
	key, err := NewKey(rand.Read)
	if err != nil {
		t.Fatalf("NewKey: %s", err)
	}
	t.Logf("key: %X", key)
	// IsZero() is possible, but very unlikely
	if key.IsZero() {
		t.Fatal("shouldn't be IsZero")
	}
	for i, c := range key {
		if c >= 32 {
			t.Errorf("byte #%d: %d > 31", i, c)
		}
	}
}
