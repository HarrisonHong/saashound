//go:build windows

package fsutil

import (
	"errors"
	"os"
	"syscall"
)

// errorSharingViolation is Win32 ERROR_SHARING_VIOLATION, which the stdlib
// syscall package does not name.
const errorSharingViolation syscall.Errno = 32

// On Windows the lock is the file handle itself: it is opened with no
// sharing, so a second open fails until the holder closes it or exits.
func openLockFile(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, errorSharingViolation) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func lockFile(*os.File) error   { return nil }
func unlockFile(*os.File) error { return nil }

// SyncDir is a no-op on Windows, where directories cannot be fsynced.
func SyncDir(string) error { return nil }
