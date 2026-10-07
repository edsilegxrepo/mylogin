// Package mylogin reads and writes ~/.mylogin.cnf created by mysql_config_editor.
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
const DefaultSection = "client"

// MaxChunkSize defines the maximum chunk size allowed to prevent memory exhaustion DOS attacks.
const MaxChunkSize = 16 * 1024 * 1024 // 16 MB

// MaxLineSize defines the maximum option line length allowed when scanning configurations.
const MaxLineSize = 1024 * 1024 // 1 MB

var (
	// ErrInvalidBlockSize is returned when an encrypted block has an invalid size or alignment.
	ErrInvalidBlockSize = errors.New("invalid block size: must be positive, block-aligned, and within limits")

	// ErrInvalidPadding is returned when PKCS#7 padding validation fails on decrypted ciphertext.
	ErrInvalidPadding = errors.New("invalid PKCS#7 padding: decrypted content is corrupted or key is incorrect")

	// ErrInsecurePermissions is returned when a .mylogin.cnf file is readable or writable by other users.
	ErrInsecurePermissions = errors.New("insecure file permissions: .mylogin.cnf must only be accessible by the owner (mode 0600)")

	// ErrKeyNotInitialized is returned when attempting to encode with an uninitialized key.
	ErrKeyNotInitialized = errors.New("key is not initialized")
)

// Key is a 20-byte key used for encryption of mylogin.cnf files.
type Key [20]byte

// IsZero reports whether the key is completely uninitialized.
func (k Key) IsZero() bool {
	return k[0] == 0 && k == Key{}
}

// Zero securely wipes the key material from memory.
func (k *Key) Zero() {
	for i := range k {
		k[i] = 0
	}
}

func (k *Key) cipher() cipher.Block {
	// 16 bytes key for AES-128
	var aesKey [16]byte
	defer func() {
		// Wipe intermediate folded key material
		for i := range aesKey {
			aesKey[i] = 0
		}
	}()

	// Apply XOR folding across the 20-byte key
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
		// Clear the 3 high bits (0x1F = 00011111b)
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
func CheckPermissions(filename string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%w: current mode is %#o, expected 0600", ErrInsecurePermissions, info.Mode().Perm())
		}
	}
	return nil
}

// Default reads and merges the default [client] section from DefaultFile().
func Default() (*Login, error) {
	return ReadLogin(DefaultFile(), []string{DefaultSection})
}

// Get reads credentials for a specific section merged with [client] from DefaultFile().
func Get(section string) (*Login, error) {
	return ReadLogin(DefaultFile(), []string{DefaultSection, section})
}

// Load reads all sections from DefaultFile().
func Load() (Sections, error) {
	return ReadSections(DefaultFile())
}

// ReadLogin reads a mylogin.cnf file, extracts the requested sections and
// merges them to obtain a single Login (that may be empty).
func ReadLogin(filename string, sectionNames []string) (login *Login, err error) {
	sections, err := ReadSections(filename)
	if err != nil {
		return nil, err
	}
	login = sections.Merge(sectionNames)
	return login, nil
}

// ReadSections reads all Sections of a mylogin.cnf file.
func ReadSections(filename string) (sections Sections, err error) {
	cleanPath := filepath.Clean(filename)
	f, err := os.Open(cleanPath) // #nosec G304 -- library intentionally reads caller-specified configuration path
	if err != nil {
		return nil, err
	}
	defer f.Close()

	file, err := Decode(bufio.NewReader(f))
	if err != nil {
		return nil, err
	}
	return Parse(file.PlainText())
}

// Parse parses the plaintext content of a mylogin.cnf file
// and returns the structured content.
// Blank lines, leading/trailing whitespace, and comments ('#' or ';') are ignored safely.
func Parse(rd io.Reader) (sections Sections, err error) {
	var login *Login
	scanner := bufio.NewScanner(rd)
	// Buffer up to 1 MB per line to handle long TLS certificates or base64 tokens
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, MaxLineSize)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && strings.HasSuffix(line, "]") {
			secName := strings.TrimSpace(line[1 : len(line)-1])
			sections = append(sections, Section{Name: secName})
			login = &sections[len(sections)-1].Login
		} else if login != nil {
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
type File interface {
	// The key used for encrypting the file
	Key() Key
	// Byte ordering for saving int32 chunk sizes
	ByteOrder() binary.ByteOrder
	// The plaintext content of the file
	PlainText() io.Reader
}

// PlainFile is a concrete implementation of the File interface.
type PlainFile struct {
	KeyVal    Key
	Order     binary.ByteOrder
	PlainData io.Reader
}

func (f *PlainFile) Key() Key {
	return f.KeyVal
}

func (f *PlainFile) ByteOrder() binary.ByteOrder {
	if f.Order == nil {
		return binary.LittleEndian
	}
	return f.Order
}

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

type decoder struct {
	key       Key
	byteOrder binary.ByteOrder
	cipher    cipher.Block // Cached AES cipher block to avoid key expansion on every chunk

	input  io.Reader
	chunk  []byte
	buffer []byte // Slice pointing to decrypted buffer
}

func (d *decoder) Key() Key {
	return d.key
}

func (d *decoder) ByteOrder() binary.ByteOrder {
	return d.byteOrder
}

func (d *decoder) PlainText() io.Reader {
	return d
}

func (d *decoder) Parse() (Sections, error) {
	return Parse(d)
}

// Close securely wipes memory and closes the underlying reader if it implements io.Closer.
func (d *decoder) Close() error {
	d.key.Zero()
	for i := range d.chunk {
		d.chunk[i] = 0
	}
	d.buffer = nil
	if closer, ok := d.input.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// Decode returns the plaintext content of a mylogin.cnf file.
// The file is encrypted with AES-128 in CBC mode with the key embedded in the file.
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

	return &decoder{
		key:       key,
		input:     in,
		byteOrder: byteOrder,
		cipher:    blockCipher,
		chunk:     make([]byte, 4096),
	}, nil
}

// Read is the PlainText reader.
func (d *decoder) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if len(d.buffer) > 0 {
		n = copy(buf, d.buffer)
		d.buffer = d.buffer[n:]
		return n, nil
	}
	var size int32
	for {
		if err = binary.Read(d.input, d.byteOrder, &size); err != nil {
			return 0, err
		}
		if size != 0 {
			break
		}
	}
	if size <= 0 || int(size) > MaxChunkSize || size%aes.BlockSize != 0 {
		return 0, fmt.Errorf("%w (size=%d)", ErrInvalidBlockSize, size)
	}

	// Dynamic slice allocation with capacity reuse
	if cap(d.chunk) < int(size) {
		d.chunk = make([]byte, size)
	} else {
		d.chunk = d.chunk[:size]
	}

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

	n = copy(buf, d.buffer)
	d.buffer = d.buffer[n:]
	return n, nil
}

// Encode writes mylogin.cnf content encrypted.
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

		l := len(line) + 1 // +1 for newline
		paddedLen := ((l + aes.BlockSize) / aes.BlockSize) * aes.BlockSize
		padDiff := paddedLen - l
		if padDiff <= 0 || padDiff > aes.BlockSize {
			return errors.New("invalid padding calculation")
		}
		padCount := byte(padDiff)

		chunk := make([]byte, paddedLen)
		copy(chunk, line)
		chunk[len(line)] = '\n'
		for i := l; i < paddedLen; i++ {
			chunk[i] = padCount
		}

		for i := 0; i < paddedLen; i += aes.BlockSize {
			cbc := cipher.NewCBCEncrypter(blockCipher, zeroIV[:])
			b := chunk[i : i+aes.BlockSize]
			cbc.CryptBlocks(b, b)
		}

		if paddedLen > math.MaxInt32 {
			return errors.New("chunk size exceeds maximum int32")
		}
		if err = binary.Write(w, byteOrder, int32(paddedLen)); err != nil {
			return err
		}
		if _, err = w.Write(chunk); err != nil {
			return err
		}
	}

	return scanner.Err()
}

// WriteFile safely and atomically writes plaintext configuration to an encrypted file with 0600 permissions.
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
