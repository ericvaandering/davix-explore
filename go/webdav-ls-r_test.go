package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/studio-b12/gowebdav"
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

// TestTokenManagerRefreshOn401 checks the end-to-end path: a server that
// rejects a stale bearer token with 401 and accepts the renewed one. This is
// the case the clock-only refresh could not fix -- if gfal-token's real
// lifetime is shorter than tokenLifetime, every retry reuses the dead token.
func TestTokenManagerRefreshOn401(t *testing.T) {
	const staleToken = "stale-token"
	const freshToken = "fresh-token"

	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("DAV", "1,2")
			w.WriteHeader(http.StatusOK)
			return
		}
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		seen = append(seen, auth)
		if auth != freshToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		w.Write([]byte(`<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">` +
			`<d:response><d:href>/data/</d:href><d:propstat><d:status>HTTP/1.1 200 OK</d:status>` +
			`<d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>` +
			`</d:multistatus>`))
	}))
	defer srv.Close()

	var fetches int
	tm := &tokenManager{
		token:       staleToken,
		issuedAt:    time.Now(),
		autoRefresh: true,
		fetch: func(_, _ string) (string, error) {
			fetches++
			return freshToken, nil
		},
	}

	c := gowebdav.NewClient(srv.URL, "", "")
	c.SetInterceptor(func(_ string, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+tm.Get())
	})

	// Mirror readDirWithRetry's 401 handling.
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		used := tm.Current()
		if _, err = c.ReadDir("/data"); err == nil {
			break
		}
		if gowebdav.IsErrCode(err, http.StatusUnauthorized) && tm.Refresh(used) {
			continue
		}
		break
	}
	if err != nil {
		t.Fatalf("ReadDir never succeeded: %v", err)
	}
	if fetches != 1 {
		t.Errorf("token fetches = %d, want 1", fetches)
	}
	if len(seen) < 2 || seen[0] != staleToken || seen[len(seen)-1] != freshToken {
		t.Errorf("tokens presented = %v, want the stale one then the fresh one", seen)
	}
}

// TestTokenManagerRefreshCollapsesConcurrent checks that workers racing on the
// same expired token produce one gfal-token call, not one per worker.
func TestTokenManagerRefreshCollapsesConcurrent(t *testing.T) {
	var fetches atomic.Int64
	tm := &tokenManager{
		token:       "stale",
		issuedAt:    time.Now(),
		autoRefresh: true,
		fetch: func(_, _ string) (string, error) {
			fetches.Add(1)
			time.Sleep(10 * time.Millisecond) // widen the race window
			return "fresh", nil
		},
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !tm.Refresh("stale") {
				t.Error("Refresh reported no new token")
			}
		}()
	}
	wg.Wait()

	if got := fetches.Load(); got != 1 {
		t.Errorf("gfal-token invocations = %d, want 1 (a stampede was not collapsed)", got)
	}
	if tm.Current() != "fresh" {
		t.Errorf("token = %q, want %q", tm.Current(), "fresh")
	}
}

// TestTokenManagerFailedRefreshDoesNotStorm covers the regression where a
// token past tokenLifetime whose refresh keeps failing re-ran gfal-token on
// every single request for the rest of the scan.
func TestTokenManagerFailedRefreshDoesNotStorm(t *testing.T) {
	var fetches int
	tm := &tokenManager{
		token:       "old",
		issuedAt:    time.Now().Add(-2 * tokenLifetime), // already expired
		autoRefresh: true,
		fetch: func(_, _ string) (string, error) {
			fetches++
			return "", fmt.Errorf("gfal-token unavailable")
		},
	}

	for i := 0; i < 50; i++ {
		if got := tm.Get(); got != "old" {
			t.Fatalf("Get() = %q, want the existing token kept", got)
		}
	}
	if fetches != 1 {
		t.Errorf("gfal-token invocations = %d, want 1 across 50 calls", fetches)
	}
}

// TestTokenManagerNoRefreshWhenTokenSupplied checks that an explicit --token
// is never replaced: there is no gfal-token to re-run.
func TestTokenManagerNoRefreshWhenTokenSupplied(t *testing.T) {
	tm := &tokenManager{token: "supplied", autoRefresh: false}
	if tm.Refresh("supplied") {
		t.Error("Refresh reported success with auto-refresh disabled")
	}
	if tm.Current() != "supplied" {
		t.Errorf("token = %q, want it unchanged", tm.Current())
	}
}
