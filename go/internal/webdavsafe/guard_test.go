package webdavsafe_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"davix-explore/internal/webdavsafe"

	"github.com/studio-b12/gowebdav"
)

const multistatusHeader = `<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
 <d:response><d:href>/data/</d:href><d:propstat><d:status>HTTP/1.1 200 OK</d:status>
  <d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>`

// A directory holding one large file.
const populated = multistatusHeader + `
 <d:response><d:href>/data/precious.root</d:href><d:propstat><d:status>HTTP/1.1 200 OK</d:status>
  <d:prop><d:resourcetype/><d:getcontentlength>9000000000</d:getcontentlength></d:prop></d:propstat></d:response>
</d:multistatus>`

// A genuinely empty directory: the self entry only, and nothing else.
const empty = multistatusHeader + `
</d:multistatus>`

func newClient(t *testing.T, url string, guard bool) *gowebdav.Client {
	t.Helper()
	c := gowebdav.NewClient(url, "", "")
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = 2 * time.Second
	if guard {
		c.SetTransport(webdavsafe.NewTransport(tr))
	} else {
		c.SetTransport(tr)
	}
	c.SetTimeout(3 * time.Second)
	return c
}

// serve returns a WebDAV server that replies to PROPFIND with the given body,
// optionally cutting the connection partway through.
func serve(t *testing.T, body string, truncate bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		if truncate {
			w.Header().Set("Content-Length", "100000")
		}
		w.WriteHeader(http.StatusMultiStatus)
		if truncate {
			w.Write([]byte(body[:180]))
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestTruncatedListingIsNotEmpty is the regression test for the data-loss path:
// without the guard, a populated directory whose listing is cut short reports
// zero entries and no error, which webdav-rm reads as permission to DELETE.
func TestTruncatedListingIsNotEmpty(t *testing.T) {
	srv := serve(t, populated, true)

	// Document the underlying library behaviour this package exists to correct.
	entries, err := newClient(t, srv.URL, false).ReadDir("/data")
	if err == nil && len(entries) == 0 {
		t.Log("confirmed: unguarded gowebdav reports a truncated listing as an empty directory")
	} else {
		t.Logf("unguarded behaviour changed: entries=%d err=%v", len(entries), err)
	}

	entries, err = newClient(t, srv.URL, true).ReadDir("/data")
	if err == nil {
		t.Fatalf("guarded ReadDir returned nil error on a truncated listing (entries=%d); "+
			"a caller would delete a populated directory", len(entries))
	}
	if len(entries) != 0 {
		t.Errorf("expected no entries alongside the error, got %d", len(entries))
	}
}

// TestEmptyDirectoryStillReportsEmpty guards against the opposite failure: if
// the validator rejected real empty directories, webdav-rm would never delete
// anything and webdav-ls-r would report none.
func TestEmptyDirectoryStillReportsEmpty(t *testing.T) {
	srv := serve(t, empty, false)

	entries, err := newClient(t, srv.URL, true).ReadDir("/data")
	if err != nil {
		t.Fatalf("guarded ReadDir on a genuinely empty directory: unexpected error %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries for an empty directory, got %d", len(entries))
	}
}

// TestPopulatedListingUnchanged checks the guard is transparent on healthy
// responses -- same entries, sizes and directory flags as the bare transport.
func TestPopulatedListingUnchanged(t *testing.T) {
	srv := serve(t, populated, false)

	entries, err := newClient(t, srv.URL, true).ReadDir("/data")
	if err != nil {
		t.Fatalf("guarded ReadDir on a healthy listing: unexpected error %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if got := entries[0].Name(); got != "precious.root" {
		t.Errorf("name: got %q, want %q", got, "precious.root")
	}
	if got := entries[0].Size(); got != 9000000000 {
		t.Errorf("size: got %d, want %d", got, int64(9000000000))
	}
	if entries[0].IsDir() {
		t.Error("expected a regular file, got a directory")
	}
}

// TestNonXMLBodyRejected covers a proxy or auth portal returning HTML with a
// 207, which would otherwise parse to zero entries.
func TestNonXMLBodyRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusMultiStatus)
		w.Write([]byte("<html><body>Gateway error</body></html>"))
	}))
	t.Cleanup(srv.Close)

	entries, err := newClient(t, srv.URL, true).ReadDir("/data")
	if err == nil {
		t.Fatalf("expected an error for a non-multistatus body, got entries=%d", len(entries))
	}
	if !errors.Is(err, webdavsafe.ErrTruncatedListing) {
		t.Logf("error did not wrap ErrTruncatedListing through gowebdav: %v", err)
	}
}
