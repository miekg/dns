package dns

// Implement a simple scanner, return a byte stream from an io reader.

import (
	"bufio"
	"io"
	"text/scanner"
)

type scan struct {
	src      *bufio.Reader
	position scanner.Position
	eof      int // have we just seen an EOF (0 no, 1 yes)
}

func scanInit(r io.Reader) *scan {
	s := new(scan)
	s.src = bufio.NewReader(r)
	s.position.Line = 1
	return s
}

// tokenText returns the next byte from the input
func (s *scan) tokenText() (byte, error) {
	c, err := s.src.ReadByte()
	if err != nil {
		return c, err
	}
	s.eof = 0
	if c == '\n' {
		s.position.Line++
		s.position.Column = 0
		s.eof = 1
	}
	s.position.Column++
	return c, nil
}
