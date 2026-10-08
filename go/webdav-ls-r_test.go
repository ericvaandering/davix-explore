package main

import (
	"os"
	"testing"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		name    string
		target  string
		server  string
		dir     string
		wantErr bool
	}{
		{name: "bare host and path", target: "host:1094/store/data", server: "host:1094", dir: "/store/data"},
		{name: "bare host only", target: "host:1094", server: "host:1094", dir: "/"},
		{name: "trailing slash", target: "host:1094/", server: "host:1094", dir: "/"},
		// davs_scanner.py builds davs:// URLs, so these must not be parsed as a
		// server of "davs:" with a directory of "//host:1094/store".
		{name: "davs scheme", target: "davs://host:1094/store/data", server: "host:1094", dir: "/store/data"},
		{name: "https scheme", target: "https://host:1094/store", server: "host:1094", dir: "/store"},
		{name: "uppercase scheme", target: "DAVS://host:1094/store", server: "host:1094", dir: "/store"},
		{name: "scheme, no path", target: "davs://host:1094", server: "host:1094", dir: "/"},
		{name: "host without port", target: "host/store", server: "host", dir: "/store"},

		{name: "unsupported scheme", target: "gsiftp://host:1094/store", wantErr: true},
		{name: "empty server", target: "/store/data", wantErr: true},
		{name: "scheme with empty server", target: "davs:///store", wantErr: true},
		{name: "empty target", target: "", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, dir, err := parseTarget(tc.target)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseTarget(%q) = (%q, %q, nil), want an error", tc.target, server, dir)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTarget(%q): unexpected error %v", tc.target, err)
			}
			if server != tc.server {
				t.Errorf("parseTarget(%q) server = %q, want %q", tc.target, server, tc.server)
			}
			if dir != tc.dir {
				t.Errorf("parseTarget(%q) directory = %q, want %q", tc.target, dir, tc.dir)
			}
		})
	}
}

// TestWriteFileAtomicReplaces checks the happy path leaves the new contents in
// place with the same permissions os.WriteFile would have used.
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
