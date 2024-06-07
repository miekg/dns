//go:build !darwin

package dns

import (
	"path/filepath"
	"testing"
)

// tempDir creates a temporary directory for tests and returns a file path as
// a result of concatenation of said temporary directory path and provided filename.
func tempFile(t *testing.T, filename string) string {
	t.Helper()

	return filepath.Join(t.TempDir(), filename)
}
