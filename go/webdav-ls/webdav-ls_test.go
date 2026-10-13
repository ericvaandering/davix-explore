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

// The exit code is this tool's entire output, so the tests drive the built
// binary rather than calling into it: a test that inspected internals could
// pass while the program still exited with the wrong status.

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

// run invokes the binary against the test server, returning its exit code and
// stdout. The tool always speaks https, so the server is a TLS one and its
// certificate is trusted through SSL_CERT_FILE rather than by relaxing
// verification in the tool.
func run(t *testing.T, srv *testServer, dir string, args ...string) (int, string) {
	t.Helper()

	cmd := exec.Command(testBinary, append(args, srv.host+dir)...)
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+srv.certFile)
	var stdout strings.Builder
	cmd.Stdout = &stdout

	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, stdout.String()
	case errorAs(err, &exitErr):
		return exitErr.ExitCode(), stdout.String()
	default:
		t.Fatalf("running %s: %v", testBinary, err)
		return -1, ""
	}
}

func errorAs(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
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

// multistatus renders a PROPFIND reply describing path as a collection or a
// plain file.
func multistatus(path string, isDir bool) string {
	resourceType := ""
	if isDir {
		resourceType = "<d:collection/>"
	}
	return `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">` +
		`<d:response><d:href>` + path + `</d:href><d:propstat>` +
		`<d:status>HTTP/1.1 200 OK</d:status>` +
		`<d:prop><d:displayname>x</d:displayname>` +
		`<d:resourcetype>` + resourceType + `</d:resourcetype>` +
		`<d:getcontentlength>0</d:getcontentlength></d:prop>` +
		`</d:propstat></d:response></d:multistatus>`
}

func TestExitsZeroWhenDirectoryExists(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("DAV", "1,2")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		fmt.Fprint(w, multistatus("/store/data/", true))
	}))

	code, stdout := run(t, srv, "/store/data", "--token", "tok")
	if code != 0 {
		t.Errorf("exit code = %d, want 0 for a directory that exists", code)
	}
	// Callers test the status, so stdout must stay clean.
	if stdout != "" {
		t.Errorf("stdout = %q, want it empty", stdout)
	}
}

func TestExitsOneWhenDirectoryMissing(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	code, _ := run(t, srv, "/store/gone", "--token", "tok")
	if code != 1 {
		t.Errorf("exit code = %d, want 1 for a 404", code)
	}
}

// A file is not the directory that was asked about.
func TestExitsOneWhenTargetIsAFile(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		fmt.Fprint(w, multistatus("/store/file.root", false))
	}))

	code, _ := run(t, srv, "/store/file.root", "--token", "tok")
	if code != 1 {
		t.Errorf("exit code = %d, want 1 for a file", code)
	}
}

// A refusal is not an answer: 403 must not be reported as "does not exist".
func TestExitsTwoWhenServerRefuses(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	code, _ := run(t, srv, "/store/data", "--token", "tok")
	if code != 2 {
		t.Errorf("exit code = %d, want 2 when the server refuses", code)
	}
}

func TestExitsTwoOnBadUsage(t *testing.T) {
	cmd := exec.Command(testBinary)
	if err := cmd.Run(); err == nil {
		t.Fatal("running with no target succeeded, want exit 2")
	} else if code := cmd.ProcessState.ExitCode(); code != 2 {
		t.Errorf("exit code = %d, want 2 with no target", code)
	}
}

// The preflight must not decide the answer on its own: a server that rejects
// OPTIONS on the directory can still answer the PROPFIND, and the tool is
// supposed to report what PROPFIND found.
func TestPreflightFailureDoesNotMaskExistence(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		fmt.Fprint(w, multistatus("/store/data/", true))
	}))

	code, _ := run(t, srv, "/store/data", "--token", "tok")
	if code != 0 {
		t.Errorf("exit code = %d, want 0: a 405 on OPTIONS should not hide an existing directory", code)
	}
}

// The OPTIONS preflight must address the directory, not the server root -- the
// distinction that made webdav-ls-r fail against some storage elements.
func TestPreflightAddressesTheDirectory(t *testing.T) {
	var optionsPath string
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			optionsPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		fmt.Fprint(w, multistatus("/store/data/", true))
	}))

	run(t, srv, "/store/data", "--token", "tok")
	if optionsPath != "/store/data/" {
		t.Errorf("OPTIONS path = %q, want %q", optionsPath, "/store/data/")
	}
}

// --quiet exists so a caller can use the exit code without the diagnostics.
func TestQuietSuppressesStderr(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	cmd := exec.Command(testBinary, "--quiet", "--token", "tok", srv.host+"/store/gone")
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+srv.certFile)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	cmd.Run()

	if cmd.ProcessState.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1", cmd.ProcessState.ExitCode())
	}
	if stderr.String() != "" {
		t.Errorf("stderr = %q, want it empty under --quiet", stderr.String())
	}
}
