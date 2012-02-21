package dns
// Implement a simple scanner, return a byte stream from an io reader.

import (
	"bufio"
	"io"
	"text/scanner"
)

type scan struct {
	src *bufio.Reader
        position scanner.Position
}

func scanInit(r io.Reader) *scan {
	s := new(scan)
	s.src = bufio.NewReader(r)
	return s
}

// tokenText returns the next byte from the input
func (s *scan) tokenText() (byte, error) {
        c, err := s.src.ReadByte()
        if err != nil {
                return c, err
        }
        if c == '\n' {
                s.position.Line++
                s.position.Column = 0
        }
        s.position.Column++
        return c, nil
}
