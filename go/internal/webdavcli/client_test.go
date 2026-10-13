package webdavcli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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
			server, dir, err := ParseTarget(tc.target)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseTarget(%q) = (%q, %q, nil), want an error", tc.target, server, dir)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q): unexpected error %v", tc.target, err)
			}
			if server != tc.server {
				t.Errorf("ParseTarget(%q) server = %q, want %q", tc.target, server, tc.server)
			}
			if dir != tc.dir {
				t.Errorf("ParseTarget(%q) directory = %q, want %q", tc.target, dir, tc.dir)
			}
		})
	}
}

// TestWriteFileAtomicReplaces checks the happy path leaves the new contents in
// place with the same permissions os.WriteFile would have used.

// TestTokenManagerRefreshOn401 checks the end-to-end path: a server that
// rejects a stale bearer token with 401 and accepts the renewed one. This is
// the case the clock-only refresh could not fix -- if gfal-token's real
// lifetime is shorter than TokenLifetime, every retry reuses the dead token.
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
	tm := NewTestTokenManager(staleToken, true, func(_, _ string) (string, error) {
		fetches++
		return freshToken, nil
	})

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
	tm := &TokenManager{
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
// token past TokenLifetime whose refresh keeps failing re-ran gfal-token on
// every single request for the rest of the scan.
func TestTokenManagerFailedRefreshDoesNotStorm(t *testing.T) {
	var fetches int
	tm := &TokenManager{
		token:       "old",
		issuedAt:    time.Now().Add(-2 * TokenLifetime), // already expired
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
	tm := &TokenManager{token: "supplied", autoRefresh: false}
	if tm.Refresh("supplied") {
		t.Error("Refresh reported success with auto-refresh disabled")
	}
	if tm.Current() != "supplied" {
		t.Errorf("token = %q, want it unchanged", tm.Current())
	}
}

// TestHeaderRecorderDumpRedactsCredentials checks that a failed Connect can be
// diagnosed from the dump without the dump itself becoming a credential leak:
// the bearer token and both cookie headers must be abbreviated, while the
// status, the Www-Authenticate challenge and ordinary headers survive intact.
func TestHeaderRecorderDumpRedactsCredentials(t *testing.T) {
	const token = "eyJhbGciOiJSUzI1NiJ9.PAYLOADPAYLOADPAYLOAD.SIGNATURE"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Www-Authenticate", `Bearer realm="storage", error="invalid_token"`)
		w.Header().Set("Set-Cookie", "session=SUPERSECRETCOOKIEVALUE12345; Path=/")
		w.Header().Set("X-Served-By", "proxy-07")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := gowebdav.NewClient(srv.URL, "", "")
	rec := NewHeaderRecorder(http.DefaultTransport)
	c.SetTransport(rec)
	c.SetInterceptor(func(_ string, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Cookie", "sess=ANOTHERSECRETVALUE9999")
	})

	if err := c.Connect(); err == nil {
		t.Fatal("Connect() succeeded against a 401 server, want an error")
	}

	var sb strings.Builder
	rec.Dump(&sb)
	out := sb.String()

	for _, secret := range []string{token, "SUPERSECRETCOOKIEVALUE12345", "ANOTHERSECRETVALUE9999"} {
		if strings.Contains(out, secret) {
			t.Errorf("dump leaked a secret in:\n%s", out)
		}
	}
	// The scheme and the token's ends stay: they distinguish "sent the wrong
	// token" from "sent no token at all".
	for _, want := range []string{"401", "Bearer eyJhbG", "invalid_token", "X-Served-By: proxy-07"} {
		if !strings.Contains(out, want) {
			t.Errorf("dump omitted diagnostic %q in:\n%s", want, out)
		}
	}
}

// TestHeaderRecorderStopDropsCapture checks that stop() both frees the
// captured headers and prevents the scan's own requests from being recorded.
func TestHeaderRecorderStopDropsCapture(t *testing.T) {
	rec := NewHeaderRecorder(http.DefaultTransport)
	rec.method = "OPTIONS"
	rec.reqHdr = http.Header{"Authorization": []string{"Bearer secret"}}

	rec.Stop()
	if rec.reqHdr != nil || rec.respHdr != nil {
		t.Error("stop() left captured headers in memory")
	}

	r, err := http.NewRequest("PROPFIND", "https://example.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer AFTERSTOP")
	rec.RoundTrip(r) // The host does not resolve; only the recording matters.
	if rec.reqHdr != nil {
		t.Error("RoundTrip recorded a request after stop()")
	}
}

// TestRedactHeaderValue pins the per-header policy, including the headers that
// must NOT be redacted -- a challenge and an ordinary header are the usual
// diagnosis for a site-specific connection failure.
func TestRedactHeaderValue(t *testing.T) {
	const long = "0123456789abcdefghijklmnopqrstuvwxyz"
	cases := []struct {
		name, header, value, want string
	}{
		{"bearer keeps scheme", "Authorization", "Bearer " + long, "Bearer 012345...uvwxyz <redacted, 36 chars>"},
		{"short token hides ends", "Authorization", "Bearer abc", "Bearer <redacted, 3 chars>"},
		{"no scheme", "Authorization", long, "012345...uvwxyz <redacted, 36 chars>"},
		{"cookie redacted whole", "Cookie", "a=" + long, "a=0123...uvwxyz <redacted, 38 chars>"},
		{"proxy auth", "Proxy-Authorization", "Basic " + long, "Basic 012345...uvwxyz <redacted, 36 chars>"},
		{"challenge kept", "Www-Authenticate", `Bearer realm="x", error="expired_token"`, `Bearer realm="x", error="expired_token"`},
		{"ordinary header kept", "X-Served-By", "proxy-07", "proxy-07"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactHeaderValue(tc.header, tc.value); got != tc.want {
				t.Errorf("RedactHeaderValue(%q, %q) = %q, want %q", tc.header, tc.value, got, tc.want)
			}
		})
	}
}

// TestPreflightTargetsScanDirectory covers the case that motivated replacing
// gowebdav's Connect(): a server that 404s on OPTIONS "/" while serving the
// scan directory. Connect() would reject such a target outright.
func TestPreflightTargetsScanDirectory(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("DAV", "1,2")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	// The helper always speaks https, so point it at the test server directly.
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		return http.DefaultTransport.RoundTrip(r)
	})

	if err := Preflight(rt, time.Minute, host, "/store/data", "tok"); err != nil {
		t.Fatalf("preflight on the scan directory: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 {
		t.Fatalf("requests = %v, want exactly one", paths)
	}
	// Trailing slash: gowebdav addresses collections that way, and a server
	// that redirects to add one would drop the Authorization header.
	if paths[0] != "/store/data/" {
		t.Errorf("OPTIONS path = %q, want %q -- not the server root", paths[0], "/store/data/")
	}
}

// TestPreflightReportsHTTPError checks that a rejected preflight fails with the
// status and the path, rather than being mistaken for success.
func TestPreflightReportsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		return http.DefaultTransport.RoundTrip(r)
	})

	err := Preflight(rt, time.Minute, host, "/store/data", "tok")
	if err == nil {
		t.Fatal("preflight succeeded against a 403, want an error")
	}
	for _, want := range []string{"403", "/store/data/"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q omits %q", err, want)
		}
	}
}

// TestPreflightSendsAuthorization checks the token reaches the preflight: it is
// built by hand rather than going through the client's interceptor.
func TestPreflightSendsAuthorization(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		return http.DefaultTransport.RoundTrip(r)
	})

	if err := Preflight(rt, time.Minute, host, "/store", "tok123"); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer tok123" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer tok123")
	}
}

// TestPreflightEscapesPath checks a directory with characters that must be
// escaped is not sent raw, which would produce a malformed request.
func TestPreflightEscapesPath(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		return http.DefaultTransport.RoundTrip(r)
	})

	if err := Preflight(rt, time.Minute, host, "/store/a b", "tok"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, " ") {
		t.Errorf("escaped path = %q, want the space escaped", got)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
