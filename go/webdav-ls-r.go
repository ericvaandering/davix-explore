package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cms-consistency/internal/webdavcli"
	"cms-consistency/internal/webdavsafe"

	"github.com/studio-b12/gowebdav"
)

type summary struct {
	Files            int64 `json:"files"`
	Bytes            int64 `json:"bytes"`
	Directories      int64 `json:"directories"`
	EmptyDirectories int64 `json:"empty_directories"`
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

	// Defaults to the historical name so existing callers are unaffected.
	var emptyDirsFile string
	flag.StringVar(&emptyDirsFile, "empty-dirs", "empty_dirs.out", "File to write the list of empty directories into")
	flag.StringVar(&emptyDirsFile, "e", "empty_dirs.out", "File to write the list of empty directories into (shorthand)")

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: webdav-ls-r [--token TOKEN] [--workers N] [--retries N] [--timeout D] [--response-timeout D] [--empty-dirs FILE] server:port/directory")
		os.Exit(2)
	}

	// An empty name would send the list to a file literally named "", losing it
	// silently. Reject it rather than guess what was meant.
	if emptyDirsFile == "" {
		fmt.Fprintln(os.Stderr, "Invalid --empty-dirs: must name a file")
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

	serverPort, directory, err := webdavcli.ParseTarget(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid target:", err)
		os.Exit(2)
	}

	// 1. Initialize the client
	c := gowebdav.NewClient("https://"+serverPort, "", "")

	// Keep the overall cap generous -- it covers reading the response body too,
	// and a PROPFIND on a large directory is legitimately slow.
	// webdavsafe.Transport additionally rejects truncated listings, which would
	// otherwise be recorded as empty directories in the --empty-dirs file. The
	// recorder is outermost, so it sees the request as it goes on the wire --
	// after the interceptor has added the Authorization header.
	recorder := webdavcli.NewHeaderRecorder(
		webdavsafe.NewTransport(webdavcli.NewTransport(responseTimeout, numWorkers)))
	c.SetTransport(recorder)
	c.SetTimeout(timeout)

	// 2. Set up the bearer token, auto-fetching it if not supplied.
	tm, err := webdavcli.NewTokenManager(serverPort, directory, token)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to obtain token:", err)
		os.Exit(1)
	}

	c.SetInterceptor(func(method string, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+tm.Get())
	})

	// 3. Preflight the scan directory. Diagnostics go to stderr: stdout carries
	// the listing, which davs_scanner.py parses positionally with line.split().
	if err := webdavcli.Preflight(recorder, timeout, serverPort, directory, tm.Get()); err != nil {
		fmt.Fprintln(os.Stderr, "Connection failed:", err)
		recorder.Dump(os.Stderr)
		os.Exit(1)
	}
	// The scan is the hot path and every listing would otherwise clone two
	// header maps per request.
	recorder.Stop()

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
	// the empty-directory list, which is the input to webdav-rm. Every exit from
	// this function therefore carries either entries or a non-nil error.
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
				if tokenRefreshes < webdavcli.MaxTokenRefreshes && tm.Refresh(used) {
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
	// -- the empty-directory list is the input to webdav-rm.
	if cause := context.Cause(ctx); cause != nil {
		fmt.Fprintln(os.Stderr, "Scan aborted:", cause)
		fmt.Fprintf(os.Stderr, "Results are incomplete; %s and ls_summary.json were left unchanged.\n", emptyDirsFile)
		os.Exit(1)
	}

	failed := false

	if err := writeFileAtomic(emptyDirsFile, []byte(strings.Join(emptyDirs, "\n")+"\n")); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", emptyDirsFile, err)
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
