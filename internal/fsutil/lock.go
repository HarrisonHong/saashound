package fsutil

import (
	"errors"
	"fmt"
	"os"
)

// ErrLocked is returned when another process holds a lock.
var ErrLocked = errors.New("locked by another process")

// Lock is an exclusive advisory lock on a file. The operating system releases
// it when the process exits for any reason, including SIGKILL, so a crashed
// run never leaves a stale lock behind.
type Lock struct {
	f *os.File
}

// TryLock takes the lock at path without waiting. It returns ErrLocked if
// another process (or another Lock in this process) holds it.
func TryLock(path string) (*Lock, error) {
	f, err := openLockFile(path)
	if err != nil {
		if errors.Is(err, ErrLocked) {
			return nil, err
		}
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		if errors.Is(err, ErrLocked) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return &Lock{f: f}, nil
}

// Unlock releases the lock.
func (l *Lock) Unlock() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := unlockFile(l.f)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

// IsLocked reports whether some process holds the lock at path, without
// taking it.
func IsLocked(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	l, err := TryLock(path)
	if err != nil {
		return errors.Is(err, ErrLocked)
	}
	_ = l.Unlock()
	return false
}
