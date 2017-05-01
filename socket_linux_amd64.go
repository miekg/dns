// +build amd64,linux

package dns

// syscall.SO_REUSEPORT is not defined for Linux/amd64. Looking through the syscall source, almost all Linux
// archs use 0x0200, except ppc and s390.
const so_REUSEPORT = 0x0200
