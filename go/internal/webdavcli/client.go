// Package webdavcli holds the pieces the WebDAV command-line tools share:
// target parsing, bearer-token management, a redacting header recorder for
// diagnosing connection failures, and the OPTIONS preflight.
//
// It exists so webdav-ls-r (recursive scan) and webdav-ls (existence check)
// agree on how a target is addressed and how a token is obtained. They are
// separate main packages, so the code cannot simply be shared between files.
package webdavcli

import (
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/studio-b12/gowebdav"
)

// TokenLifetime is how long a token is assumed good for. It is a guess -- the
// real lifetime is set by the issuer -- so it only drives proactive renewal; an
// actual 401 refreshes the token regardless.
const TokenLifetime = 30 * time.Minute

// MaxTokenRefreshes bounds how many times one listing may renew its token
// before giving up, since a renewal does not consume a retry attempt.
const MaxTokenRefreshes = 2

// tokenCommand is the helper that mints a bearer token.
const tokenCommand = "/consistency/cms_consistency/site_cmp3/get_oidc_token.py"

// ParseTarget splits a target into its host:port and absolute directory.
//
// The surrounding tooling speaks davs:// URLs -- davs_scanner.py builds them
// that way -- so accept a scheme and strip it rather than letting
// strings.Cut("davs://host/path", "/") produce a host of "davs:" and a
// directory of "//host/path". Everything is addressed over https regardless.
func ParseTarget(target string) (serverPort, directory string, err error) {
	if i := strings.Index(target, "://"); i >= 0 {
		switch scheme := strings.ToLower(target[:i]); scheme {
		case "davs", "https", "dav", "http", "webdav":
			target = target[i+3:]
		default:
			return "", "", fmt.Errorf("unsupported scheme %q in %q", scheme, target)
		}
	}

	serverPort, dirPath, found := strings.Cut(target, "/")
	if serverPort == "" {
		return "", "", fmt.Errorf("missing server:port in %q", target)
	}
	directory = "/"
	if found {
		directory += dirPath
	}
	return serverPort, directory, nil
}

// URL builds the https URL for a directory, escaped and with a trailing slash.
//
// Match how gowebdav addresses a collection: escaped per path segment, with a
// trailing slash. Some servers redirect a collection requested without one,
// which would cost a round trip and drop the Authorization header.
func URL(serverPort, directory string) string {
	return "https://" + serverPort + gowebdav.PathEscape(gowebdav.FixSlashes(directory))
}

// TokenManager holds the current bearer token and, when auto-refresh is on,
// re-fetches it.
//
// Refresh is driven by the server rather than by the clock. Nothing tells us
// how long the token is actually good for -- TokenLifetime is only a guess --
// so a token that expires early would otherwise produce 401s that the retry
// loop burns its whole budget on without ever fixing. Refresh lets a caller
// that sees a 401 replace the token and try again; the TokenLifetime timer
// stays as a proactive backstop so a long scan usually renews before the
// server rejects anything.
type TokenManager struct {
	mu          sync.Mutex
	serverPort  string
	directory   string
	token       string
	issuedAt    time.Time
	autoRefresh bool

	// fetch obtains a fresh token. Nil means FetchToken; tests substitute it.
	fetch func(serverPort, directory string) (string, error)
}

// NewTokenManager returns a manager for the given target. An empty token is
// fetched immediately and renewed as needed; a supplied one is used as-is and
// never replaced, since there is nothing to re-run.
func NewTokenManager(serverPort, directory, token string) (*TokenManager, error) {
	tm := &TokenManager{serverPort: serverPort, directory: directory}
	if token != "" {
		tm.token = token
		return tm, nil
	}
	fetched, err := FetchToken(serverPort, directory)
	if err != nil {
		return nil, err
	}
	tm.token, tm.issuedAt, tm.autoRefresh = fetched, time.Now(), true
	return tm, nil
}

// NewTestTokenManager returns a manager with a substituted fetch function.
func NewTestTokenManager(token string, autoRefresh bool, fetch func(serverPort, directory string) (string, error)) *TokenManager {
	return &TokenManager{token: token, issuedAt: time.Now(), autoRefresh: autoRefresh, fetch: fetch}
}

// FetchToken mints a bearer token for the given target.
func FetchToken(serverPort, directory string) (string, error) {
	fmt.Fprintln(os.Stderr, "Getting token for https://"+serverPort+directory)
	out, err := exec.Command(tokenCommand,
		"--scope", "storage.read:/ offline_access",
		"--issuer", "def",
		"--audience", "https://"+serverPort+directory).Output()
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(out))
	fmt.Fprintln(os.Stderr, "Got token "+Abbreviate(token))
	return token, nil
}

// Get returns the current token, proactively renewing it once it reaches
// TokenLifetime.
func (tm *TokenManager) Get() string {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.autoRefresh && time.Since(tm.issuedAt) >= TokenLifetime {
		tm.refreshLocked(tm.token)
	}
	return tm.token
}

// Current returns the token without considering a renewal, so a caller can
// record which token a request used and pass it to Refresh on a 401.
func (tm *TokenManager) Current() string {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.token
}

// Refresh re-fetches the token after the server rejected one, and reports
// whether the caller should retry. stale is the token the caller used; if it
// no longer matches, another goroutine already refreshed and the caller can
// retry immediately rather than fetching again.
//
// Returns false when auto-refresh is off (the token was supplied, so there is
// nothing to re-fetch) or when the fetch failed.
func (tm *TokenManager) Refresh(stale string) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if !tm.autoRefresh {
		return false
	}
	if tm.token != stale {
		return true
	}
	return tm.refreshLocked(stale)
}

// refreshLocked re-fetches the token. tm.mu must be held.
//
// Holding the lock across the fetch serialises every worker behind one
// subprocess, which is deliberate: it collapses a refresh stampede into a
// single invocation instead of one per in-flight request.
func (tm *TokenManager) refreshLocked(stale string) bool {
	// Record the attempt even when it fails. Otherwise a token past
	// TokenLifetime whose refresh keeps failing re-execs the helper on every
	// single request, under this lock, for the rest of the scan.
	tm.issuedAt = time.Now()

	fetch := tm.fetch
	if fetch == nil {
		fetch = FetchToken
	}
	newToken, err := fetch(tm.serverPort, tm.directory)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Warning: failed to refresh token, keeping existing one:", err)
		return false
	}
	tm.token = newToken
	return newToken != stale
}

// HeaderRecorder wraps a RoundTripper and keeps the headers of the most recent
// exchange until Stop is called.
//
// A failed request reports only a status code or a bare transport error, which
// does not separate a token the server rejected from one it never saw: a
// redirect to another host drops the Authorization header, and a proxy or load
// balancer can answer in place of the storage element. Recording the exchange
// lets a failure show what was actually sent and returned.
type HeaderRecorder struct {
	rt http.RoundTripper

	mu      sync.Mutex
	stopped bool
	method  string
	url     string
	reqHdr  http.Header
	status  string
	respHdr http.Header
}

// NewHeaderRecorder returns a recorder delegating to rt. A nil rt uses
// http.DefaultTransport.
func NewHeaderRecorder(rt http.RoundTripper) *HeaderRecorder {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &HeaderRecorder{rt: rt}
}

func (hr *HeaderRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := hr.rt.RoundTrip(r)

	hr.mu.Lock()
	defer hr.mu.Unlock()
	if hr.stopped {
		return resp, err
	}
	hr.method, hr.url, hr.reqHdr = r.Method, r.URL.String(), r.Header.Clone()
	hr.status, hr.respHdr = "", nil
	if resp != nil {
		hr.status, hr.respHdr = resp.Status, resp.Header.Clone()
	}
	return resp, err
}

// Stop ends recording and drops what was captured, so a long run does not
// clone two header maps per request.
func (hr *HeaderRecorder) Stop() {
	hr.mu.Lock()
	defer hr.mu.Unlock()
	hr.stopped = true
	hr.reqHdr, hr.respHdr = nil, nil
}

// Dump writes the recorded exchange with credentials abbreviated.
func (hr *HeaderRecorder) Dump(w io.Writer) {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	if hr.method == "" {
		fmt.Fprintln(w, "No request reached the transport.")
		return
	}
	fmt.Fprintf(w, "Request: %s %s\n", hr.method, hr.url)
	writeHeaders(w, hr.reqHdr)
	if hr.respHdr == nil {
		fmt.Fprintln(w, "Response: none, the request failed before the server answered.")
		return
	}
	fmt.Fprintf(w, "Response: %s\n", hr.status)
	writeHeaders(w, hr.respHdr)
}

func writeHeaders(w io.Writer, h http.Header) {
	for _, name := range slices.Sorted(maps.Keys(h)) {
		for _, v := range h[name] {
			fmt.Fprintf(w, "  %s: %s\n", name, RedactHeaderValue(name, v))
		}
	}
}

// sensitiveHeaders maps a canonical header name to whether its value starts
// with an auth scheme that should survive redaction. Www-Authenticate is
// deliberately absent: a challenge is not a credential, and its realm and
// error description are usually the whole diagnosis.
var sensitiveHeaders = map[string]bool{
	"Authorization":       true,
	"Proxy-Authorization": true,
	"Cookie":              false,
	"Set-Cookie":          false,
}

// RedactHeaderValue abbreviates a credential-bearing header value, leaving
// every other header untouched.
func RedactHeaderValue(name, value string) string {
	keepScheme, sensitive := sensitiveHeaders[name]
	if !sensitive {
		return value
	}
	// The scheme ("Bearer", "Basic") is part of the diagnosis and is not itself
	// a secret. Cookies have no scheme and may contain spaces, so splitting
	// their value would expose the first name=value pair.
	if keepScheme {
		if scheme, rest, found := strings.Cut(value, " "); found {
			return scheme + " " + Abbreviate(rest)
		}
	}
	return Abbreviate(value)
}

// Abbreviate renders a secret as its first and last few characters plus its
// length -- enough to tell two tokens apart, or to spot a truncated or empty
// one, without putting a usable credential in the log.
func Abbreviate(s string) string {
	if len(s) <= 20 {
		return fmt.Sprintf("<redacted, %d chars>", len(s))
	}
	return fmt.Sprintf("%s...%s <redacted, %d chars>", s[:6], s[len(s)-6:], len(s))
}

// Preflight issues an OPTIONS request against the directory about to be used
// and reports whether the server accepted it.
//
// It replaces gowebdav's Connect(), which hardcodes OPTIONS on the server root
// ("/"). That root is not necessarily a WebDAV collection, or even a path the
// storage element serves: some return 404 there while serving the target
// directory perfectly well, so Connect() rejects a target that would have
// worked. Asking about the path we actually intend to read tests the thing we
// care about, and a failure names that path.
func Preflight(rt http.RoundTripper, timeout time.Duration, serverPort, directory, token string) error {
	url := URL(serverPort, directory)

	req, err := http.NewRequest("OPTIONS", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// gowebdav sends Depth on its own OPTIONS; keep it so this request differs
	// from the one that already works against other servers only in its path.
	req.Header.Set("Depth", "0")

	client := &http.Client{
		Transport: rt,
		Timeout:   timeout,
		// Report a redirect rather than following it, as gowebdav does. Go drops
		// the Authorization header across hosts, so a followed redirect would
		// surface as a confusing 401 instead of the 3xx that explains it.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("OPTIONS %s: %s", url, resp.Status)
	}
	return nil
}

// NewTransport builds the HTTP transport the tools share.
//
// gowebdav's default client has no timeouts at all, so a hung connection parks
// a goroutine forever. Bound each stage separately: responseTimeout catches a
// server that stops responding, while the caller's SetTimeout caps the whole
// request. maxConns raises MaxIdleConnsPerHost, whose default of 2 would make
// most workers reconnect on every listing.
func NewTransport(responseTimeout time.Duration, maxConns int) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = responseTimeout
	if maxConns > 0 {
		transport.MaxIdleConnsPerHost = maxConns
	}
	return transport
}
