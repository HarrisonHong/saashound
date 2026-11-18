//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows)

package fsutil

import (
	"errors"
	"os"
)

var errNoLocking = errors.New("file locking is not supported on this platform")

func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, FileMode)
}

func lockFile(*os.File) error   { return errNoLocking }
func unlockFile(*os.File) error { return nil }

// SyncDir fsyncs a directory so a create or rename inside it is durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
