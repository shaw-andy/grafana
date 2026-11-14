//go:build unix

package local

import "syscall"

// openNonBlocking keeps open from waiting on a FIFO with no writer, so the
// opened file's type can be checked before it is read.
const openNonBlocking = syscall.O_NONBLOCK
