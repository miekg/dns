// +build !amd64,linux

package dns

import "syscall"

const so_REUSEPORT = syscall.SO_REUSEPORT
