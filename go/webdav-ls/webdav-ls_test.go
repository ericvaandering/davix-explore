package main

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The exit code and the stdout format are this tool's entire contract, so the
// tests drive the built binary rather than calling into it: a test that
// inspected internals could pass while the program still exited with the wrong
// status or printed to the wrong stream.

var testBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "webdav-ls-build")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mktemp:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	testBinary = filepath.Join(dir, "webdav-ls")
	build := exec.Command("go", "build", "-o", testBinary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building webdav-ls: %v\n%s", err, out)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

type result struct {
	code   int
	stdout string
	stderr string
}

// run invokes the binary against the test server. The tool always speaks
// https, so the server is a TLS one and its certificate is trusted through
// SSL_CERT_FILE rather than by relaxing verification in the tool.
func run(t *testing.T, srv *testServer, dir string, args ...string) result {
	t.Helper()

	cmd := exec.Command(testBinary, append(args, srv.host+dir)...)
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+srv.certFile)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	err := cmd.Run()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("running %s: %v", testBinary, err)
		}
	}
	return result{cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()}
}

// testServer is an https server whose certificate the tool will accept.
type testServer struct {
	host     string // host:port, as the tool takes on the command line
	certFile string
}

func serve(t *testing.T, h http.Handler) *testServer {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	certFile := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: srv.Certificate().Raw,
	})
	if err := os.WriteFile(certFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return &testServer{host: strings.TrimPrefix(srv.URL, "https://"), certFile: certFile}
}

// entry renders one <response> element of a PROPFIND reply.
func entry(href string, isDir bool, size int64) string {
	resourceType, length := "", fmt.Sprint(size)
	if isDir {
		resourceType, length = "<d:collection/>", "0"
	}
	return `<d:response><d:href>` + href + `</d:href><d:propstat>` +
		`<d:status>HTTP/1.1 200 OK</d:status><d:prop>` +
		`<d:resourcetype>` + resourceType + `</d:resourcetype>` +
		`<d:getcontentlength>` + length + `</d:getcontentlength>` +
		`<d:getlastmodified>Mon, 06 Jan 2025 15:04:05 GMT</d:getlastmodified>` +
		`</d:prop></d:propstat></d:response>`
}

// listing renders a Depth:1 reply: the collection itself first, then children.
func listing(self string, children ...string) string {
	return `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">` +
		entry(self, true, 0) + strings.Join(children, "") + `</d:multistatus>`
}

// propfindHandler serves body for any PROPFIND.
func propfindHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		fmt.Fprint(w, body)
	})
}

// TestListingFormatMatchesRecursive pins the stdout layout. davs_scanner.py
// parses it positionally with line.split() into six fields, so a change here
// silently breaks the caller.
func TestListingFormatMatchesRecursive(t *testing.T) {
	srv := serve(t, propfindHandler(listing("/store/data/",
		entry("/store/data/file.root", false, 12345),
		entry("/store/data/subdir/", true, 0),
	)))

	got := run(t, srv, "/store/data", "--token", "tok")
	if got.code != 0 {
		t.Fatalf("exit code = %d (stderr: %s)", got.code, got.stderr)
	}

	lines := strings.Split(strings.TrimRight(got.stdout, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stdout lines = %d, want 2:\n%s", len(lines), got.stdout)
	}

	// Field layout, as the scanner reads it: drwx, zero, size, cdate, ctime, path.
	for _, tc := range []struct {
		line       string
		wantKind   string
		wantSize   string
		wantPath   string
		wantFields int
	}{
		{lines[0], "-rwxrwxrwx", "12345", "/store/data/file.root", 6},
		{lines[1], "drwxrwxrwx", "0", "/store/data/subdir/", 6},
	} {
		fields := strings.Fields(tc.line)
		if len(fields) != tc.wantFields {
			t.Errorf("line %q split into %d fields, want %d", tc.line, len(fields), tc.wantFields)
			continue
		}
		if fields[0] != tc.wantKind {
			t.Errorf("kind = %q, want %q", fields[0], tc.wantKind)
		}
		if fields[1] != "0" {
			t.Errorf("second field = %q, want the literal %q", fields[1], "0")
		}
		if fields[2] != tc.wantSize {
			t.Errorf("size = %q, want %q", fields[2], tc.wantSize)
		}
		if fields[5] != tc.wantPath {
			t.Errorf("path = %q, want %q", fields[5], tc.wantPath)
		}
	}
}

// A successful run must say nothing on stderr: the caller reads stdout and the
// exit code, and diagnostics would have to be filtered back out.
func TestSilentOnSuccess(t *testing.T) {
	srv := serve(t, propfindHandler(listing("/store/data/",
		entry("/store/data/file.root", false, 1),
	)))

	got := run(t, srv, "/store/data", "--token", "tok")
	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0", got.code)
	}
	if got.stderr != "" {
		t.Errorf("stderr = %q, want it empty on success", got.stderr)
	}
}

// An empty directory exists. It must exit 0 with no output at all -- not be
// confused with a missing one.
func TestEmptyDirectoryExitsZeroWithNoOutput(t *testing.T) {
	srv := serve(t, propfindHandler(listing("/store/empty/")))

	got := run(t, srv, "/store/empty", "--token", "tok")
	if got.code != 0 {
		t.Errorf("exit code = %d, want 0 for an existing empty directory", got.code)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want it empty", got.stdout)
	}
	if got.stderr != "" {
		t.Errorf("stderr = %q, want it empty", got.stderr)
	}
}

func TestMissingDirectoryExitsNonZero(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	got := run(t, srv, "/store/gone", "--token", "tok")
	if got.code == 0 {
		t.Error("exit code = 0, want non-zero for a directory that does not exist")
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want it empty when there is nothing to list", got.stdout)
	}
	if got.stderr == "" {
		t.Error("stderr is empty, want the reason the listing failed")
	}
}

// gowebdav reports a path that exists but is not a collection as 405. That is
// not the directory that was asked about.
func TestFileTargetExitsNonZero(t *testing.T) {
	srv := serve(t, propfindHandler(
		`<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">`+
			entry("/store/file.root", false, 10)+`</d:multistatus>`))

	got := run(t, srv, "/store/file.root", "--token", "tok")
	if got.code == 0 {
		t.Error("exit code = 0, want non-zero for a file")
	}
}

// A refusal is not an answer about existence, and must not be reported as one.
func TestRefusedRequestIsDistinctFromMissing(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	got := run(t, srv, "/store/data", "--token", "tok")
	if got.code != 2 {
		t.Errorf("exit code = %d, want 2 when the server refuses", got.code)
	}
}

func TestBadUsageExitsTwo(t *testing.T) {
	cmd := exec.Command(testBinary)
	cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 2 {
		t.Errorf("exit code = %d, want 2 with no target", code)
	}
}

// The listing must address the directory itself, not the server root -- the
// distinction that made webdav-ls-r fail against some storage elements.
func TestListingAddressesTheDirectory(t *testing.T) {
	var paths []string
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		fmt.Fprint(w, listing("/store/data/"))
	}))

	run(t, srv, "/store/data", "--token", "tok")
	if len(paths) == 0 {
		t.Fatal("no request reached the server")
	}
	// gowebdav replays the first request once as auth negotiation, so the count
	// is 2 rather than 1. What matters is that every request addresses the
	// directory -- none is an OPTIONS preflight against the server root.
	for _, p := range paths {
		if p != "/store/data/" {
			t.Errorf("request path = %q, want %q", p, "/store/data/")
		}
	}
}

// Depth:1 lists the directory's immediate children only.
func TestListingIsNotRecursive(t *testing.T) {
	var depths []string
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		depths = append(depths, r.Header.Get("Depth"))
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		fmt.Fprint(w, listing("/store/data/", entry("/store/data/subdir/", true, 0)))
	}))

	got := run(t, srv, "/store/data", "--token", "tok")
	// gowebdav replays the first request once as auth negotiation; two listings
	// of the same directory, not a descent into the subdirectory.
	if len(depths) > 2 {
		t.Fatalf("requests = %d, want at most 2: the subdirectory must not be descended into", len(depths))
	}
	for _, d := range depths {
		if d != "1" {
			t.Errorf("Depth = %q, want %q", d, "1")
		}
	}
	if n := strings.Count(strings.TrimRight(got.stdout, "\n"), "\n") + 1; n != 1 {
		t.Errorf("stdout lines = %d, want 1", n)
	}
}
