//go:build darwin

package dns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tempDir creates a temporary directory for tests and returns a file path as
// a result of concatenation of said temporary directory path and provided filename.
// The reason for this is to work around some limitations in socket file name
// lengths on darwin.
//
// Ref:
// - https://github.com/golang/go/blob/go1.20.2/src/syscall/ztypes_darwin_arm64.go#L178
// - https://github.com/golang/go/blob/go1.20.2/src/syscall/ztypes_linux_arm64.go#L175
func tempFile(t *testing.T, filename string) string {
	t.Helper()

	dir, err := os.MkdirTemp("", strings.ReplaceAll(t.Name(), string(filepath.Separator), "-"))
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	return filepath.Join(dir, filename)
}
