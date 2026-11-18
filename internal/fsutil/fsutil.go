// Package fsutil holds the small set of file operations the tool's state
// depends on: private directories, fsynced and atomic writes, path
// containment and an advisory lock that the kernel releases if the process
// dies.
package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Modes for everything the tool writes under its state directory.
const (
	DirMode  os.FileMode = 0o700
	FileMode os.FileMode = 0o600
)

// MkdirPrivate creates dir (and parents) with mode 0700 and tightens the
// mode of dir itself if it already existed.
func MkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return err
	}
	return os.Chmod(dir, DirMode)
}

// WriteFileAtomic writes data to path through a temporary file in the same
// directory, fsyncs it, renames it into place and fsyncs the directory, so a
// crash leaves either the old content or the new, never a mix.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(FileMode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return SyncDir(dir)
}

// Contain joins rel onto base and refuses any result outside base: rel must
// be relative and must not climb out with "..".
func Contain(base, rel string) (string, error) {
	if rel == "" {
		return "", errors.New("empty path")
	}
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, `\`) || filepath.VolumeName(rel) != "" {
		return "", fmt.Errorf("path %q must be relative", rel)
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes its directory", rel)
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == ".." {
			return "", fmt.Errorf("path %q must not contain a .. element", rel)
		}
	}
	return filepath.Join(base, clean), nil
}
