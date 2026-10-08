package mylogin

import (
	"bufio"
	"bytes"
	"io"
)

// Objective: Provide low-overhead, stream-based filtering of decrypted INI streams,
// extracting a specific section without allocating full AST models in memory.
//
// Core Components:
//   - FilterSection: Public constructor returning an io.Reader stream filter.
//   - filterSection: Internal state machine managing line scanning and emission buffers.
//
// Functionality:
//   - Tracks INI section boundaries by scanning lines for '[' prefix and matching headers.
//   - Toggles an internal emission gate (show) on matching section headers.
//   - Streams matching section lines through an internal byte buffer to satisfy io.Reader.
//   - Implements defensive bounds checking to eliminate panics on empty or whitespace lines.
//
// Data Flow:
//   Decrypted INI Stream (io.Reader) -> bufio.Scanner -> Section Matcher -> bytes.Buffer -> Consumer.

// FilterSection reads an INI-style content and filters out any section
// except the given one. It returns an io.Reader providing only the requested section.
func FilterSection(rd io.Reader, section string) io.Reader {
	// Pre-construct the target header byte slice: e.g. "[client]"
	header := make([]byte, 1, 2+len(section))
	header[0] = '['
	header = append(header, section...)
	header = append(header, ']')

	return &filterSection{
		header:  header,
		scanner: bufio.NewScanner(rd),
	}
}

// filterSection implements io.Reader to lazily demultiplex an INI stream.
type filterSection struct {
	header  []byte         // Byte representation of the target section header, e.g. "[client]"
	show    bool           // State flag indicating whether the scanner is currently inside the target section
	scanner *bufio.Scanner // Line scanner wrapping the source plaintext stream
	buffer  bytes.Buffer   // Output buffer staging lines of the matched section for Read calls
}

// Read implements io.Reader, filling buf with bytes from the targeted section.
func (f *filterSection) Read(buf []byte) (n int, err error) {
	// Zero-length buffer read satisfies io.Reader contract immediately
	if len(buf) == 0 {
		return 0, nil
	}

	// Refill the internal line buffer if currently exhausted
	for f.buffer.Len() == 0 {
		if !f.scanner.Scan() {
			err = f.scanner.Err()
			if err == nil {
				err = io.EOF
			}
			return 0, err
		}

		line := f.scanner.Bytes()

		// Defensive bounds check to prevent panic on empty lines or blank spacing
		if len(line) > 0 && line[0] == '[' {
			// Toggle emission state: true if this header matches f.header, false if it's another section
			f.show = bytes.Equal(f.header, line)
		}

		// When inside the target section, append the line and trailing newline to the staging buffer
		if f.show {
			f.buffer.Write(line)
			f.buffer.WriteByte('\n')
		}
	}

	// Drain staged bytes from the internal buffer into caller's slice
	n, err = f.buffer.Read(buf)
	if err == io.EOF {
		err = nil // Suppress EOF while scanner may have further content to process
	}
	return n, err
}
