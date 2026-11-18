package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestContain(t *testing.T) {
	base := t.TempDir()
	for _, ok := range []string{"a.jsonl", "okta/x.jsonl", "./a"} {
		p, err := Contain(base, ok)
		if err != nil {
			t.Fatalf("Contain(%q): %v", ok, err)
		}
		if rel, _ := filepath.Rel(base, p); rel == ".." || filepath.IsAbs(rel) {
			t.Fatalf("Contain(%q) = %q escapes", ok, p)
		}
	}
	for _, bad := range []string{"", "/etc/passwd", "../x", "a/../../x", "a/..", `\x`} {
		if _, err := Contain(base, bad); err == nil {
			t.Errorf("Contain(%q) accepted", bad)
		}
	}
}

func TestWriteFileAtomicAndModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "f.json")
	if err := WriteFileAtomic(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("two")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "two" {
		t.Fatalf("content %q %v", b, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != FileMode {
		t.Fatalf("file mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != DirMode {
		t.Fatalf("dir mode %v", fi.Mode().Perm())
	}
}

func TestLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	if IsLocked(p) {
		t.Fatal("missing lock reported held")
	}
	l, err := TryLock(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TryLock(p); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock = %v; want ErrLocked", err)
	}
	if !IsLocked(p) {
		t.Fatal("held lock not reported")
	}
	if err := l.Unlock(); err != nil {
		t.Fatal(err)
	}
	if IsLocked(p) {
		t.Fatal("released lock still reported held")
	}
	l2, err := TryLock(p)
	if err != nil {
		t.Fatalf("relock after unlock: %v", err)
	}
	_ = l2.Unlock()
}
