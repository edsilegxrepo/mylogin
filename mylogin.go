// Package mylogin reads and writes ~/.mylogin.cnf created by mysql_config_editor.
//
// Objective: Provide high-performance, cryptographic-safe, and MySQL 8.x-compliant
// parsing, serialization, and stream transformation for MySQL login path option files (.mylogin.cnf).
//
// Core Components:
//   - Key: 20-byte key with 3 high bits cleared per byte; derived into 16-byte AES-128 key via XOR folding.
//   - Decode / decoder: Streaming AES-128-CBC decryptor handling 4-byte null header, 20-byte key, dynamic endianness, and PKCS#7 unpadding.
//   - Encode: Line-oriented AES-128-CBC encryptor writing canonical 4-byte header, key, chunk size prefixes, and PKCS#7 padded ciphertext blocks.
//   - Parse / ReadSections / ReadLogin: Tokenizer and AST constructor creating structured Sections and merged Logins.
//   - WriteFile: Atomic configuration writer with directory creation, temporary file creation, 0600 mode enforcement, and sync.
//   - CheckPermissions: Platform-aware file permission validator enforcing 0600 (owner read/write only) on Unix-like systems.
//
// Functionality:
//   - Cryptographic Key Management: Key generation with random sources, non-printable byte masking (0x1F), XOR key folding, and zeroing.
//   - Stream Decryption: Endianness sniffing (peek chunk size), streaming CBC block decryption with zero IV, and strict PKCS#7 verification.
//   - Stream Encryption: Cross-platform newline normalization (\r stripping), block alignment calculation, CBC encryption, and chunk serialization.
//   - File Resolution: DefaultFile resolution respecting MYSQL_TEST_LOGIN_FILE and OS-specific standards (%APPDATA%\MySQL on Windows, ~/.mylogin.cnf on Unix).
//
// Data Flow:
//
//	Decryption Flow:
//	  os.File / io.Reader -> [4-byte Null Header] -> [20-byte Key] -> [Byte Order Sniffing] -> [Chunk Header (Int32 Size)] -> [AES-128-CBC Decrypt (Zero IV)] -> [PKCS#7 Unpad] -> Plaintext Stream -> Scanner/Parser -> Sections.
//	Encryption Flow:
//	  Sections / Plaintext -> Scanner (per line + \n) -> [PKCS#7 Padding] -> [AES-128-CBC Encrypt (Zero IV)] -> [Int32 Chunk Size Prefix] -> Temp File (0600) -> fsync -> Atomic Rename -> Destination.
//
// Reference documentation:
//   - https://dev.mysql.com/doc/refman/8.4/en/mysql-config-editor.html
//   - https://dev.mysql.com/doc/refman/8.4/en/option-file-options.html#option_general_login-path
//
// Example:
//
//	mysql_config_editor set --login-path=foo --user=bar -p
//
// For usage examples, see the utilities in the cmd/ directory.
package mylogin

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultSection is the name of the base section used by all MySQL client tools.
// Options under this section apply globally to client connections unless overridden by a named path.
const DefaultSection = "client"

// MaxChunkSize defines the maximum chunk size allowed to prevent memory exhaustion DOS attacks.
// Standard MySQL option lines rarely exceed a few kilobytes; 16 MB provides ample headroom while capping allocation.
const MaxChunkSize = 16 * 1024 * 1024 // 16 MB

// MaxLineSize defines the maximum option line length allowed when scanning configurations.
// Supports large base64-encoded strings, certificates, or extended configuration values.
const MaxLineSize = 1024 * 1024 // 1 MB

var (
	// ErrInvalidBlockSize is returned when an encrypted block has an invalid size or alignment.
	// Sizes must be positive, block-aligned (multiples of 16 bytes), and within MaxChunkSize limits.
	ErrInvalidBlockSize = errors.New("invalid block size: must be positive, block-aligned, and within limits")

	// ErrInvalidPadding is returned when PKCS#7 padding validation fails on decrypted ciphertext.
	// This condition typically indicates file corruption, tampering, or an incorrect decryption key.
	ErrInvalidPadding = errors.New("invalid PKCS#7 padding: decrypted content is corrupted or key is incorrect")

	// ErrInsecurePermissions is returned when a .mylogin.cnf file is readable or writable by other users.
	// Enforces strict filesystem-level access controls (mode 0600) on Unix-like operating systems.
	ErrInsecurePermissions = errors.New("insecure file permissions: .mylogin.cnf must only be accessible by the owner (mode 0600)")

	// ErrKeyNotInitialized is returned when attempting to encode with an uninitialized key.
	ErrKeyNotInitialized = errors.New("key is not initialized")
)

// Key is a 20-byte key used for encryption of mylogin.cnf files.
// In MySQL's format, each byte has its 3 high bits cleared (values 0x00..0x1F).
type Key [20]byte

// IsZero reports whether the key is completely uninitialized.
// Returns true if all 20 bytes are zero.
func (k Key) IsZero() bool {
	return k[0] == 0 && k == Key{}
}

// Zero securely wipes the key material from memory.
// Overwrites all 20 bytes with zeroes to prevent leakage via heap inspections or core dumps.
func (k *Key) Zero() {
	for i := range k {
		k[i] = 0
	}
}

// cipher derives a 16-byte AES-128 key from the 20-byte key using MySQL's XOR folding algorithm,
// instantiates an AES block cipher, and wipes the intermediate folded key bytes from memory.
func (k *Key) cipher() cipher.Block {
	// 16 bytes key for AES-128
	var aesKey [16]byte
	defer func() {
		// Wipe intermediate folded key material
		for i := range aesKey {
			aesKey[i] = 0
		}
	}()

	// Apply XOR folding across the 20-byte key: aesKey[i%16] ^= key[i]
	for i := 0; i < len(k); i++ {
		aesKey[i%16] ^= k[i]
	}

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		panic(err.Error())
	}

	return block
}

// NewKey creates a new key from a source of random bytes.
// See [crypto/rand.Read] or [math/rand.Read] as possible sources.
//
// The generated key has the 3 high bits cleared so each byte is non-printable (< 32).
func NewKey(readRandom func([]byte) (int, error)) (Key, error) {
	var key Key
	_, err := readRandom(key[:])
	if err != nil {
		return Key{}, err
	}
	for i := range key {
		// Clear the 3 high bits (0x1F = 00011111b) per MySQL specification
		key[i] = key[i] & 0x1F
	}
	return key, nil
}

// DefaultFile returns the path to the default mylogin.cnf file:
//
//	Windows: %APPDATA%/MySQL/.mylogin.cnf
//	others: ~/.mylogin.cnf
//
// If the environment variable MYSQL_TEST_LOGIN_FILE is set
// that path is returned instead.
func DefaultFile() string {
	f := os.Getenv("MYSQL_TEST_LOGIN_FILE")
	if len(f) != 0 {
		return f
	}
	return platformDefaultFile()
}

// CheckPermissions verifies that the file at path has strict owner-only permissions (0600).
// On Unix platforms, it returns ErrInsecurePermissions if group or others have any access.
// This check mitigates multi-tenant local credential disclosure vulnerabilities.
func CheckPermissions(filename string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		// Check that group (bits 3-5) and other (bits 0-2) have zero permissions
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%w: current mode is %#o, expected 0600", ErrInsecurePermissions, info.Mode().Perm())
		}
	}
	return nil
}

// Default reads the resolved default [client] connection view.
// It automatically incorporates [client] defaults from the plaintext MySQL option file when present,
// then overlays [client] values from the encrypted login file.
func Default() (*Login, error) {
	return ReadResolvedLogin(DefaultFile(), DefaultOptionFile(), []string{DefaultSection})
}

// Get reads the resolved connection view for a specific login-path section.
// Merge precedence is:
// 1. plaintext option file [client]
// 2. encrypted login file [client]
// 3. encrypted login file [section]
func Get(section string) (*Login, error) {
	return ReadResolvedLogin(DefaultFile(), DefaultOptionFile(), []string{DefaultSection, section})
}

// Load reads all sections from DefaultFile().
// Returns the complete AST of sections present in the configuration file.
func Load() (Sections, error) {
	return ReadSections(DefaultFile())
}

// ReadLogin reads a mylogin.cnf file, extracts the requested sections and
// merges them to obtain a single Login (that may be empty).
// Precedence follows sectionNames order: later sections override earlier sections.
func ReadLogin(filename string, sectionNames []string) (login *Login, err error) {
	sections, err := ReadSections(filename)
	if err != nil {
		return nil, err
	}
	login = sections.Merge(sectionNames)
	return login, nil
}

// ReadResolvedLogin reads the encrypted login file and automatically applies plaintext [client]
// defaults from the provided option file when present.
// Merge precedence is:
// 1. plaintext option file [client]
// 2. encrypted login file sections in the order supplied by sectionNames
//
// Data Flow:
//
//	optionFile [client] -> *Login base -> overlay myloginFile [sectionNames...] -> *Login resolved
func ReadResolvedLogin(myloginFile, optionFile string, sectionNames []string) (*Login, error) {
	// 1. Load foundational defaults from plaintext option file (e.g., ~/.my.cnf)
	base, err := ReadClientDefaults(optionFile)
	if err != nil {
		return nil, err
	}
	if base == nil {
		base = &Login{}
	}
	resolved := base.Clone()

	// 2. Read requested sections from the encrypted .mylogin.cnf file
	login, err := ReadLogin(myloginFile, sectionNames)
	if err != nil {
		return nil, err
	}

	// 3. Overlay encrypted section values on top of plaintext defaults
	if login != nil {
		resolved.Merge(login)
	}
	return resolved, nil
}

// ReadSections reads all Sections of a mylogin.cnf file.
// The file path is cleaned, opened, decoded from AES-128-CBC, and parsed into Sections.
func ReadSections(filename string) (sections Sections, err error) {
	cleanPath := filepath.Clean(filename)
	f, err := os.Open(cleanPath) // #nosec G304 -- library intentionally reads caller-specified configuration path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	file, err := Decode(bufio.NewReader(f))
	if err != nil {
		return nil, err
	}
	return Parse(file.PlainText())
}

// Parse parses the plaintext content of a mylogin.cnf file
// and returns the structured content.
// Blank lines, leading/trailing whitespace, and comments ('#' or ';') are ignored safely.
// Option lines following section headers are parsed into the corresponding Login struct.
func Parse(rd io.Reader) (sections Sections, err error) {
	var login *Login
	scanner := bufio.NewScanner(rd)
	// Buffer up to 1 MB per line to handle long TLS certificates or base64 tokens
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, MaxLineSize)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comment lines starting with # or ;
		if len(line) == 0 || line[0] == '#' || line[0] == ';' {
			continue
		}
		// Detect section headers enclosed in square brackets: [section_name]
		if line[0] == '[' && strings.HasSuffix(line, "]") {
			secName := strings.TrimSpace(line[1 : len(line)-1])
			sections = append(sections, Section{Name: secName})
			login = &sections[len(sections)-1].Login
		} else if login != nil {
			// Parse key-value option pair within current active section
			if err = login.parseLine(line); err != nil {
				return nil, err
			}
		}
	}
	if err = scanner.Err(); err != nil {
		return nil, err
	}
	return sections, nil
}

// File is the full structure of a mylogin.cnf file.
// Represents the raw encrypted container metadata and unencrypted data accessors.
type File interface {
	// Key returns the 20-byte key used for encrypting the file.
	Key() Key
	// ByteOrder specifies the byte ordering for saving int32 chunk sizes.
	ByteOrder() binary.ByteOrder
	// PlainText returns an io.Reader streaming the decrypted content of the file.
	PlainText() io.Reader
}

// PlainFile is a concrete implementation of the File interface.
// Used primarily for encoding in-memory configuration data into encrypted form.
type PlainFile struct {
	KeyVal    Key              // 20-byte encryption key
	Order     binary.ByteOrder // Endianness for chunk length headers
	PlainData io.Reader        // Reader supplying unencrypted INI content
}

// Key returns the encryption key configured for this PlainFile.
func (f *PlainFile) Key() Key {
	return f.KeyVal
}

// ByteOrder returns the endianness configured for this PlainFile, defaulting to LittleEndian.
func (f *PlainFile) ByteOrder() binary.ByteOrder {
	if f.Order == nil {
		return binary.LittleEndian
	}
	return f.Order
}

// PlainText returns the underlying unencrypted data stream.
func (f *PlainFile) PlainText() io.Reader {
	return f.PlainData
}

// NewFile wraps key, byteOrder, and a plaintext reader into a File suitable for Encode.
func NewFile(key Key, byteOrder binary.ByteOrder, plainText io.Reader) File {
	return &PlainFile{
		KeyVal:    key,
		Order:     byteOrder,
		PlainData: plainText,
	}
}

// decoder implements streaming AES-128-CBC decryption for .mylogin.cnf files.
// It decrypts variable-length chunks sequentially on demand while verifying PKCS#7 padding.
type decoder struct {
	key       Key              // 20-byte key extracted from the 24-byte file header
	byteOrder binary.ByteOrder // Endianness detected from the first chunk size prefix
	cipher    cipher.Block     // Cached AES cipher block to avoid key expansion on every chunk

	input  io.Reader // Underlying encrypted byte stream
	closer io.Closer // Optional underlying closer if input implements io.Closer
	chunk  []byte    // Dynamic buffer allocated for ciphertext chunks
	buffer []byte    // Slice pointing to residual unconsumed decrypted bytes
}

// Key returns the 20-byte key parsed from the file header.
func (d *decoder) Key() Key {
	return d.key
}

// ByteOrder returns the detected byte ordering (LittleEndian or BigEndian).
func (d *decoder) ByteOrder() binary.ByteOrder {
	return d.byteOrder
}

// PlainText returns the decoder itself as an io.Reader.
func (d *decoder) PlainText() io.Reader {
	return d
}

// Parse convenience method parses the decoded plaintext stream into structured Sections.
func (d *decoder) Parse() (Sections, error) {
	return Parse(d)
}

// Close securely wipes memory and closes the underlying reader if it implements io.Closer.
// Ensures sensitive key material and ciphertext buffers are zeroed upon completion.
// Also releases filesystem locks by closing the underlying input stream (e.g., on Windows NTFS).
func (d *decoder) Close() error {
	// 1. Zero out cryptographic key material and ciphertext buffers
	d.key.Zero()
	for i := range d.chunk {
		d.chunk[i] = 0
	}
	d.buffer = nil

	// 2. Close explicit underlying stream handle if captured
	if d.closer != nil {
		return d.closer.Close()
	}
	// 3. Fallback closure if input implements io.Closer directly
	if closer, ok := d.input.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// Decode returns the plaintext content of a mylogin.cnf file.
// The file is encrypted with AES-128 in CBC mode with the key embedded in the file.
//
// Header Format:
//   - Bytes 0..3:  Null header (0x00, 0x00, 0x00, 0x00)
//   - Bytes 4..23: 20-byte key
//   - Bytes 24..:  Sequence of [int32 chunk_len][AES-128-CBC encrypted chunk...]
func Decode(input io.Reader) (File, error) {
	in := bufio.NewReader(input)

	// Skip first 4 null bytes
	head4 := make([]byte, 4)
	n, err := io.ReadFull(in, head4)
	if err != nil {
		return nil, err
	}
	if n != 4 {
		return nil, io.EOF
	}

	// Read 20-byte encryption key
	var key Key
	if n, err = io.ReadFull(in, key[:]); err != nil {
		return nil, err
	}
	if n != cap(key) {
		return nil, io.EOF
	}

	// Peek next 4 bytes to detect byte order from first chunk length
	chunkSize, err := in.Peek(4)
	if err != nil {
		return nil, err
	}
	var byteOrder binary.ByteOrder
	if chunkSize[0] == 0 && chunkSize[1] == 0 && (chunkSize[2] != 0 || chunkSize[3] != 0) {
		byteOrder = binary.BigEndian
	} else {
		byteOrder = binary.LittleEndian
	}

	// Pre-initialize and cache block cipher to avoid re-generating key schedule on every chunk
	blockCipher := key.cipher()

	var closer io.Closer
	if c, ok := input.(io.Closer); ok {
		closer = c
	}

	return &decoder{
		key:       key,
		input:     in,
		closer:    closer,
		byteOrder: byteOrder,
		cipher:    blockCipher,
		chunk:     make([]byte, 4096),
	}, nil
}

// Read is the PlainText reader.
// It implements io.Reader by streaming, decrypting, and PKCS#7-unpadding encrypted chunks.
func (d *decoder) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	// Return any residual decrypted data from the previous chunk
	if len(d.buffer) > 0 {
		n = copy(buf, d.buffer)
		d.buffer = d.buffer[n:]
		return n, nil
	}

	// Read next chunk length prefix (skipping empty chunks if any)
	var size int32
	for {
		if err = binary.Read(d.input, d.byteOrder, &size); err != nil {
			return 0, err
		}
		if size != 0 {
			break
		}
	}

	// Enforce security boundaries and AES 16-byte block alignment
	if size <= 0 || int(size) > MaxChunkSize || size%aes.BlockSize != 0 {
		return 0, fmt.Errorf("%w (size=%d)", ErrInvalidBlockSize, size)
	}

	// Dynamic slice allocation with capacity reuse
	if cap(d.chunk) < int(size) {
		d.chunk = make([]byte, size)
	} else {
		d.chunk = d.chunk[:size]
	}

	// Read complete encrypted block from input stream
	n, err = io.ReadFull(d.input, d.chunk)
	if err != nil {
		return 0, err
	}
	if n != int(size) {
		return 0, fmt.Errorf("invalid read size: got %d, expected %d", n, size)
	}

	// Decrypt each 16-byte block using a null IV (MySQL's block decryption convention)
	var zeroIV [aes.BlockSize]byte
	for i := 0; i < int(size); i += aes.BlockSize {
		cbc := cipher.NewCBCDecrypter(d.cipher, zeroIV[:])
		b := d.chunk[i : i+aes.BlockSize]
		cbc.CryptBlocks(b, b)
	}

	// Validate and remove PKCS#7 padding
	d.buffer = d.chunk[:size]
	padding := int(d.buffer[len(d.buffer)-1])
	if padding <= 0 || padding > aes.BlockSize || padding > len(d.buffer) {
		return 0, ErrInvalidPadding
	}
	for _, c := range d.buffer[len(d.buffer)-padding:] {
		if int(c) != padding {
			return 0, ErrInvalidPadding
		}
	}
	d.buffer = d.buffer[:len(d.buffer)-padding]

	// Deliver unpadded decrypted bytes to caller
	n = copy(buf, d.buffer)
	d.buffer = d.buffer[n:]
	return n, nil
}

// Encode writes mylogin.cnf content encrypted.
// It iterates line-by-line over the plaintext reader, pads each line with PKCS#7 up to
// an AES-128 block boundary, encrypts in CBC mode with a zero IV, and prefixes each chunk with an int32 length.
func Encode(w io.Writer, f File) (err error) {
	key := f.Key()
	if key.IsZero() {
		return ErrKeyNotInitialized
	}

	// Header: 4 null bytes + 20-byte key
	if _, err = w.Write([]byte{0, 0, 0, 0}); err != nil {
		return err
	}
	if _, err = w.Write(key[:]); err != nil {
		return err
	}

	blockCipher := key.cipher()
	scanner := bufio.NewScanner(f.PlainText())
	scanner.Split(bufio.ScanLines)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, MaxLineSize)

	byteOrder := f.ByteOrder()
	if byteOrder == nil {
		byteOrder = binary.LittleEndian
	}

	var zeroIV [aes.BlockSize]byte
	for scanner.Scan() {
		line := scanner.Bytes()
		// Strip any trailing carriage return (\r) for canonical cross-platform newline
		line = bytes.TrimRight(line, "\r")

		l := len(line) + 1 // +1 for newline delimiter
		paddedLen := ((l + aes.BlockSize) / aes.BlockSize) * aes.BlockSize
		padDiff := paddedLen - l
		if padDiff <= 0 || padDiff > aes.BlockSize {
			return errors.New("invalid padding calculation")
		}
		padCount := byte(padDiff)

		// Construct chunk with line bytes, terminating newline, and PKCS#7 padding bytes
		chunk := make([]byte, paddedLen)
		copy(chunk, line)
		chunk[len(line)] = '\n'
		for i := l; i < paddedLen; i++ {
			chunk[i] = padCount
		}

		// Encrypt 16-byte blocks using AES-128-CBC with zero IV
		for i := 0; i < paddedLen; i += aes.BlockSize {
			cbc := cipher.NewCBCEncrypter(blockCipher, zeroIV[:])
			b := chunk[i : i+aes.BlockSize]
			cbc.CryptBlocks(b, b)
		}

		if paddedLen > math.MaxInt32 {
			return errors.New("chunk size exceeds maximum int32")
		}
		// Write int32 chunk length prefix
		if err = binary.Write(w, byteOrder, int32(paddedLen)); err != nil {
			return err
		}
		// Write encrypted chunk data
		if _, err = w.Write(chunk); err != nil {
			return err
		}
	}

	return scanner.Err()
}

// WriteFile safely and atomically writes plaintext configuration to an encrypted file with 0600 permissions.
//
// Safety Guarantees:
//   - Generates a fresh cryptographically random 20-byte key using crypto/rand.
//   - Creates target directory structure with 0700 mode if missing.
//   - Employs a temporary staging file in the destination directory to ensure atomic rename capability across filesystems.
//   - Calls fsync to ensure data persistence to non-volatile storage before renaming.
//   - Enforces 0600 file permissions on both staging and final files.
//   - Ensures cleanup of temporary artifacts on any failure.
func WriteFile(filename string, plainText io.Reader) error {
	key, err := NewKey(rand.Read)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write to temporary file in the same directory for atomic rename
	tmp, err := os.CreateTemp(dir, ".mylogin-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to set temp file permissions: %w", err)
	}

	if err := Encode(tmp, NewFile(key, binary.LittleEndian, plainText)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to encode: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpName, filename); err != nil {
		return fmt.Errorf("failed to atomically rename temp file to %s: %w", filename, err)
	}

	return os.Chmod(filename, 0o600)
}
