package dns

import (
	"testing"
)

func TestFieldEmptyAOrAAAAData(t *testing.T) {
	Field(new(A), 1)
	Field(new(AAAA), 1)
}
