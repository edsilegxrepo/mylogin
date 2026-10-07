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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// DefaultSection is the name of the base section used by all MySQL client tools.
const DefaultSection = "client"

// Key is a key used for encryption of mylogin.cnf files.
type Key [20]byte

func (k Key) IsZero() bool {
	return k[0] == 0 && k == Key{}
}

func (k *Key) cipher() cipher.Block {
	// 16 bytes key for AES-128
	var aesKey [16]byte
	// Apply xor folding across the 20-byte key
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

// ReadLogin reads a mylogin.cnf file, extracts the requested sections and
// merges them to obtain a single Login (that may be empty).
func ReadLogin(filename string, sectionNames []string) (login *Login, err error) {
	sections, err := ReadSections(filename)
	if err != nil {
		return
	}
	login = sections.Merge(sectionNames)
	return
}

// ReadSections reads all Sections of a mylogin.cnf file.
func ReadSections(filename string) (sections Sections, err error) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()

	file, err := Decode(bufio.NewReader(f))
	if err != nil {
		return
	}
	return Parse(file.PlainText())
}

// Parse parses the plaintext content of a mylogin.cnf file
// and returns the structured content.
// Blank lines, leading/trailing whitespace, and comments ('#' or ';') are ignored safely.
func Parse(rd io.Reader) (sections Sections, err error) {
	var login *Login
	scanner := bufio.NewScanner(rd)
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

	input  io.Reader
	chunk  [256 * aes.BlockSize]byte
	buffer []byte // Slice pointing to chunk
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

// Decode is a filter that returns the plaintext content of a mylogin.cnf file.
// The file is encrypted with AES 128 CBC with the key embedded in the file.
func Decode(input io.Reader) (File, error) {
	in := bufio.NewReader(input)

	// Skip first 4 bytes
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

	// The following 4 bytes are the length of the first chunk
	// We will use them to detect the byte order
	chunkSize, err := in.Peek(4)
	if err != nil {
		return nil, err
	}
	var byteOrder binary.ByteOrder
	// Assume all chunks have size < 64K
	if chunkSize[0] == 0 && chunkSize[1] == 0 && (chunkSize[2] != 0 || chunkSize[3] != 0) {
		byteOrder = binary.BigEndian
	} else {
		byteOrder = binary.LittleEndian
	}

	return &decoder{key: key, input: in, byteOrder: byteOrder}, nil
}

// Read is the PlainText reader.
func (d *decoder) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return
	}
	if len(d.buffer) > 0 {
		n = copy(buf, d.buffer)
		d.buffer = d.buffer[n:]
		return
	}
	var size int32
	for {
		// Read a new chunk size
		if err = binary.Read(d.input, d.byteOrder, &size); err != nil {
			return 0, err
		}
		if size != 0 {
			break
		}
	}
	if size < 0 || int(size) > len(d.chunk) || size%aes.BlockSize != 0 {
		return 0, fmt.Errorf("invalid block size: %d", size)
	}
	n, err = io.ReadFull(d.input, d.chunk[:size])
	if err != nil {
		return 0, err
	}
	if n != int(size) {
		return 0, fmt.Errorf("invalid read size: got %d, expected %d", n, size)
	}

	blockCipher := d.key.cipher()

	// Each 16-bytes block is decoded with a null IV
	d.buffer = d.chunk[:size]
	for i := 0; i < int(size); i += aes.BlockSize {
		cbc := cipher.NewCBCDecrypter(blockCipher, make([]byte, aes.BlockSize))
		b := d.chunk[i : i+aes.BlockSize]
		cbc.CryptBlocks(b, b)
	}

	// Remove PKCS#7 padding
	padding := d.buffer[len(d.buffer)-1]
	if padding > 0 && padding <= aes.BlockSize && int(padding) <= len(d.buffer) {
		valid := true
		for _, c := range d.buffer[len(d.buffer)-int(padding):] {
			if c != padding {
				valid = false
				break
			}
		}
		if valid {
			d.buffer = d.buffer[:len(d.buffer)-int(padding)]
		}
	}

	n = copy(buf, d.buffer)
	d.buffer = d.buffer[n:]
	return
}

// Encode writes a mylogin.cnf content encrypted
func Encode(w io.Writer, f File) (err error) {
	key := f.Key()
	if key.IsZero() {
		return errors.New("key is not initialized")
	}

	// Header: 4 null bytes + 20-byte key
	if _, err = w.Write([]byte{0, 0, 0, 0}); err != nil {
		return
	}
	if _, err = w.Write(key[:]); err != nil {
		return
	}

	blockCipher := key.cipher()
	scanner := bufio.NewScanner(f.PlainText())
	scanner.Split(bufio.ScanLines)
	byteOrder := f.ByteOrder()
	if byteOrder == nil {
		byteOrder = binary.LittleEndian
	}

	for scanner.Scan() {
		line := scanner.Bytes()
		// Re-append newline
		l := len(line) + 1
		paddedLen := ((l + aes.BlockSize) / aes.BlockSize) * aes.BlockSize
		padCount := byte(paddedLen - l)

		chunk := make([]byte, paddedLen)
		copy(chunk, line)
		chunk[len(line)] = '\n'
		for i := l; i < paddedLen; i++ {
			chunk[i] = padCount
		}

		for i := 0; i < paddedLen; i += aes.BlockSize {
			cbc := cipher.NewCBCEncrypter(blockCipher, make([]byte, aes.BlockSize))
			b := chunk[i : i+aes.BlockSize]
			cbc.CryptBlocks(b, b)
		}

		if err = binary.Write(w, byteOrder, int32(paddedLen)); err != nil {
			return
		}
		if _, err = w.Write(chunk); err != nil {
			return
		}
	}

	return scanner.Err()
}

// WriteFile writes plaintext configuration to an encrypted file at path with 0600 permissions.
func WriteFile(filename string, plainText io.Reader) error {
	key, err := NewKey(rand.Read)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	return Encode(f, NewFile(key, binary.LittleEndian, plainText))
}
