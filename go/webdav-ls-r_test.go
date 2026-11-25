package main

import (
	"os"
	"testing"
)

func TestWriteFileAtomicReplaces(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/empty_dirs.out"

	if err := writeFileAtomic(path, []byte("first\n")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeFileAtomic(path, []byte("second\n")); err != nil {
		t.Fatalf("second write: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "second\n" {
		t.Errorf("contents = %q, want %q", got, "second\n")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0644 {
		t.Errorf("permissions = %o, want 0644", perm)
	}

	// The temporary file must not survive a successful rename.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected only the target file to remain, got %v", names)
	}
}
