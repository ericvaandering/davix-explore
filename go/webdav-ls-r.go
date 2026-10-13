package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cms-consistency/internal/webdavsafe"

	"github.com/studio-b12/gowebdav"
)

type summary struct {
	Files            int64 `json:"files"`
	Bytes            int64 `json:"bytes"`
	Directories      int64 `json:"directories"`
	EmptyDirectories int64 `json:"empty_directories"`
}

// tokenLifetime is how long a gfal-token token is assumed good for. It is a
// guess -- the real lifetime is set by the issuer -- so it only drives
// proactive renewal; an actual 401 refreshes the token regardless.
const tokenLifetime = 30 * time.Minute

// maxTokenRefreshes bounds how many times one listing may renew its token
// before giving up, since a renewal does not consume a retry attempt.
const maxTokenRefreshes = 2

// parseTarget splits a scan target into its host:port and absolute directory.
//
// The surrounding tooling speaks davs:// URLs -- davs_scanner.py builds them
// that way -- so accept a scheme and strip it rather than letting
// strings.Cut("davs://host/path", "/") produce a host of "davs:" and a
// directory of "//host/path". Everything is addressed over https regardless.
func parseTarget(target string) (serverPort, directory string, err error) {
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

// writeFileAtomic writes data to a temporary file in the same directory and
// renames it into place, so a reader never observes a partly-written file and
// a failed write leaves the previous contents intact.
func writeFileAtomic(name string, data []byte) error {
	dir := filepath.Dir(name)
	f, err := os.CreateTemp(dir, filepath.Base(name)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // No-op once the rename below succeeds.

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	// Match os.WriteFile's 0644 rather than CreateTemp's 0600.
	if err := f.Chmod(0644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}

// tokenManager holds the current bearer token and, when autoRefresh is set,
// re-fetches it via gfal-token.
//
// Refresh is driven by the server rather than by the clock. Nothing tells us
// how long gfal-token's token is actually good for -- tokenLifetime is only a
// guess -- so a token that expires early would otherwise produce 401s that the
// retry loop burns its whole budget on without ever fixing. Refresh() lets a
// caller that sees a 401 replace the token and try again; the tokenLifetime
// timer stays as a proactive backstop so a long scan usually renews before the
// server rejects anything.
type tokenManager struct {
	mu          sync.Mutex
	serverPort  string
	directory   string
	token       string
	issuedAt    time.Time
	autoRefresh bool

	// fetch obtains a fresh token. Nil means fetchToken; tests substitute it.
	fetch func(serverPort, directory string) (string, error)
}

func fetchToken(serverPort, directory string) (string, error) {
	fmt.Fprintln(os.Stderr, "Getting token for "+"https://"+serverPort+directory)
	out, err := exec.Command("/consistency/cms_consistency/site_cmp3/get_oidc_token.py",  "--scope", "storage.read:/ offline_access", "--issuer", "def",
	"--audience", "https://"+serverPort+directory).Output()
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(out))
	if len(token) > 20 {
		fmt.Fprintf(os.Stderr, "Got token %s...%s\n", token[:6], token[len(token)-6:])
	} else {
		fmt.Fprintf(os.Stderr, "Got token of length %d\n", len(token))
	}
	return token, nil
}

// Get returns the current token, proactively renewing it once it reaches
// tokenLifetime.
func (tm *tokenManager) Get() string {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.autoRefresh && time.Since(tm.issuedAt) >= tokenLifetime {
		tm.refreshLocked(tm.token)
	}
	return tm.token
}

// Current returns the token without considering a renewal, so a caller can
// record which token a request used and pass it to Refresh on a 401.
func (tm *tokenManager) Current() string {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.token
}

// Refresh re-fetches the token after the server rejected one, and reports
// whether the caller should retry. stale is the token the caller used; if it
// no longer matches, another goroutine already refreshed and the caller can
// retry immediately rather than fetching again.
//
// Returns false when auto-refresh is off (the token came from --token, so
// there is nothing to re-fetch) or when gfal-token failed.
func (tm *tokenManager) Refresh(stale string) bool {
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
// Holding the lock across gfal-token serialises every worker behind one fetch,
// which is deliberate: it collapses a refresh stampede into a single
// subprocess instead of one per in-flight request.
func (tm *tokenManager) refreshLocked(stale string) bool {
	// Record the attempt even when it fails. Otherwise a token past
	// tokenLifetime whose refresh keeps failing re-execs gfal-token on every
	// single request, under this lock, for the rest of the scan.
	tm.issuedAt = time.Now()

	fetch := tm.fetch
	if fetch == nil {
		fetch = fetchToken
	}
	newToken, err := fetch(tm.serverPort, tm.directory)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Warning: failed to refresh token, keeping existing one:", err)
		return false
	}
	tm.token = newToken
	return newToken != stale
}

func main() {
	var token string
	flag.StringVar(&token, "token", "", "Bearer token for Authorization header")
	flag.StringVar(&token, "t", "", "Bearer token for Authorization header (shorthand)")

	var numWorkers int
	flag.IntVar(&numWorkers, "workers", 8, "Number of concurrent scanner goroutines")
	flag.IntVar(&numWorkers, "w", 8, "Number of concurrent scanner goroutines (shorthand)")

	var retries int
	flag.IntVar(&retries, "retries", 3, "Number of retry attempts per directory before aborting")
	flag.IntVar(&retries, "r", 3, "Number of retry attempts per directory before aborting (shorthand)")

	var timeout time.Duration
	flag.DurationVar(&timeout, "timeout", 5*time.Minute, "Overall time limit for a single PROPFIND, including reading the response (0 disables)")

	var responseTimeout time.Duration
	flag.DurationVar(&responseTimeout, "response-timeout", 60*time.Second, "Time limit for the server to send response headers (0 disables)")

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: webdav-ls-r [--token TOKEN] [--workers N] [--retries N] [--timeout D] [--response-timeout D] server:port/directory")
		os.Exit(2)
	}

	// Reject counts that would make the scan silently wrong rather than slow:
	// a negative retry budget skips the listing loop entirely, and a worker
	// pool of zero leaves nothing to drain the job queue.
	if retries < 0 {
		fmt.Fprintf(os.Stderr, "Invalid --retries %d: must be zero or greater\n", retries)
		os.Exit(2)
	}
	if numWorkers < 1 {
		fmt.Fprintf(os.Stderr, "Invalid --workers %d: must be at least 1\n", numWorkers)
		os.Exit(2)
	}

	serverPort, directory, err := parseTarget(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid target:", err)
		os.Exit(2)
	}

	// 1. Initialize the client
	c := gowebdav.NewClient("davs://"+serverPort, "", "")

	// gowebdav's default client has no timeouts at all, so a hung connection
	// parks a worker goroutine forever. Bound each stage separately: the
	// transport catches a server that stops responding, while SetTimeout caps
	// the whole request. Keep the overall cap generous -- it covers reading the
	// response body too, and a PROPFIND on a large directory is legitimately slow.
	// webdavsafe.Transport additionally rejects truncated listings, which would
	// otherwise be recorded as empty directories in empty_dirs.out.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = responseTimeout
	if numWorkers > 0 {
		// Default is 2, which would make most workers reconnect on every listing.
		transport.MaxIdleConnsPerHost = numWorkers
	}
	c.SetTransport(webdavsafe.NewTransport(transport))
	c.SetTimeout(timeout)

	// 2. Set up the bearer token, auto-fetching it via gfal-token if not supplied.
	tm := &tokenManager{serverPort: serverPort, directory: directory}
	if token == "" {
		fetched, err := fetchToken(serverPort, directory)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to obtain token via gfal-token:", err)
			os.Exit(1)
		}
		tm.token, tm.issuedAt, tm.autoRefresh = fetched, time.Now(), true
	} else {
		tm.token = token
	}

	c.SetInterceptor(func(method string, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+tm.Get())
	})

	// 3. Connect. Diagnostics go to stderr: stdout carries the listing, which
	// davs_scanner.py parses positionally with line.split().
	if err := c.Connect(); err != nil {
		fmt.Fprintln(os.Stderr, "Connection failed:", err)
		os.Exit(1)
	}

	// 4. Recursively scan the tree with a pool of worker goroutines.
	ctx, cancel := context.WithCancelCause(context.Background())
	jobs := make(chan string, 100)
	var wg sync.WaitGroup
	var printMu sync.Mutex
	var emptyDirsMu sync.Mutex
	var emptyDirs []string
	var numFiles, numBytes, numDirs atomic.Int64

	// readDirWithRetry must never return (nil, nil): the caller reads an empty
	// listing with no error as "this directory is empty" and writes the path to
	// empty_dirs.out, which is the input to webdav-rm. Every exit from this
	// function therefore carries either entries or a non-nil error.
	readDirWithRetry := func(path string) ([]os.FileInfo, error) {
		var lastErr error
		// Token renewals do not consume a retry attempt, so bound them
		// separately: a server that keeps rejecting freshly issued tokens
		// would otherwise loop forever.
		tokenRefreshes := 0
		for attempt := 0; attempt <= retries; attempt++ {
			if attempt > 0 {
				fmt.Fprintf(os.Stderr, "Warning: retrying %q (attempt %d of %d) after error: %v\n", path, attempt, retries, lastErr)
				time.Sleep(500 * time.Millisecond)
			}

			// Note which token this attempt will use, so a 401 refreshes that
			// token rather than one a concurrent worker already replaced.
			used := tm.Current()

			entries, err := c.ReadDir(path)
			if err == nil {
				return entries, nil
			}
			lastErr = err

			// A 401 means the token expired, which no amount of retrying
			// fixes. Renew it and retry without spending an attempt: the
			// request was never really tried with a valid credential.
			if gowebdav.IsErrCode(err, http.StatusUnauthorized) {
				if tokenRefreshes < maxTokenRefreshes && tm.Refresh(used) {
					tokenRefreshes++
					fmt.Fprintf(os.Stderr, "Notice: refreshed token after 401 on %q, retrying\n", path)
					attempt--
					continue
				}
				// Either we could not get a new token or the server keeps
				// rejecting fresh ones; further retries will not help.
				break
			}
		}
		if lastErr == nil {
			// Unreachable while retries >= 0 is enforced at startup, but the
			// consequence of falling through with a nil error is a wrongly
			// deleted directory, so fail closed instead of trusting that.
			lastErr = fmt.Errorf("no listing attempt was made for %q (retries=%d)", path, retries)
		}
		fmt.Fprintf(os.Stderr, "Warning: exhausted %d retries on %q, last error: %v\n", retries, path, lastErr)
		return nil, lastErr
	}

	worker := func() {
		for path := range jobs {
			if ctx.Err() != nil {
				wg.Done()
				continue
			}

			entries, err := readDirWithRetry(path)
			if err != nil {
				cancel(fmt.Errorf("giving up on %q after %d retries: %w", path, retries, err))
				wg.Done()
				continue
			}

			if len(entries) == 0 {
				emptyDirsMu.Lock()
				emptyDirs = append(emptyDirs, path)
				emptyDirsMu.Unlock()
			}

			printMu.Lock()
			for _, e := range entries {
				kind := "-rwxrwxrwx" // Make it look like a regular file by default
				if e.IsDir() {
					kind = "drwxrwxrwx" // Make it look like a directory
				}
				fmt.Printf("%-10s 0 %12d  %s  %s\n", kind, e.Size(), e.ModTime().Format("2006-01-02 15:04:05"), e.(gowebdav.File).Path())
			}
			printMu.Unlock()

			for _, e := range entries {
				if e.IsDir() {
					numDirs.Add(1)
				} else {
					numFiles.Add(1)
					numBytes.Add(e.Size())
				}
			}

			for _, e := range entries {
				if e.IsDir() {
					wg.Add(1)
					go func(childPath string) { jobs <- childPath }(e.(gowebdav.File).Path())
				}
			}

			wg.Done()
		}
	}

	for i := 0; i < numWorkers; i++ {
		go worker()
	}

	wg.Add(1)
	jobs <- directory

	wg.Wait()
	close(jobs)

	// An aborted scan has only walked part of the tree, so its results describe
	// nothing in particular. Leave the previous run's files in place rather
	// than replacing them with a truncated list that still looks authoritative
	// -- empty_dirs.out is the input to webdav-rm.
	if cause := context.Cause(ctx); cause != nil {
		fmt.Fprintln(os.Stderr, "Scan aborted:", cause)
		fmt.Fprintln(os.Stderr, "Results are incomplete; empty_dirs.out and ls_summary.json were left unchanged.")
		os.Exit(1)
	}

	failed := false

	if err := writeFileAtomic("empty_dirs.out", []byte(strings.Join(emptyDirs, "\n")+"\n")); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to write empty_dirs.out:", err)
		failed = true
	}

	s := summary{
		Files:            numFiles.Load(),
		Bytes:            numBytes.Load(),
		Directories:      numDirs.Load(),
		EmptyDirectories: int64(len(emptyDirs)),
	}
	if data, err := json.MarshalIndent(s, "", "  "); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to marshal summary:", err)
		failed = true
	} else if err := writeFileAtomic("ls_summary.json", data); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to write ls_summary.json:", err)
		failed = true
	}

	if failed {
		os.Exit(1)
	}
}
