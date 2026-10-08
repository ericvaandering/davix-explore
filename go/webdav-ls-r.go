package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"davix-explore/internal/webdavsafe"

	"github.com/studio-b12/gowebdav"
)

type summary struct {
	Files            int64 `json:"files"`
	Bytes            int64 `json:"bytes"`
	Directories      int64 `json:"directories"`
	EmptyDirectories int64 `json:"empty_directories"`
}

const tokenLifetime = 30 * time.Minute

// tokenManager holds the current bearer token and, when autoRefresh is set,
// re-fetches it via gfal-token once it turns tokenLifetime old.
type tokenManager struct {
	mu          sync.Mutex
	serverPort  string
	directory   string
	token       string
	issuedAt    time.Time
	autoRefresh bool
}

func fetchToken(serverPort, directory string) (string, error) {
	fmt.Fprintln(os.Stderr, "Getting token for "+"https://"+serverPort+directory)
	out, err := exec.Command("gfal-token", "https://"+serverPort+directory).Output()
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

func (tm *tokenManager) Get() string {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.autoRefresh && time.Since(tm.issuedAt) >= tokenLifetime {
		if newToken, err := fetchToken(tm.serverPort, tm.directory); err != nil {
			fmt.Fprintln(os.Stderr, "Warning: failed to refresh token, keeping existing one:", err)
		} else {
			tm.token, tm.issuedAt = newToken, time.Now()
		}
	}
	return tm.token
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
		return
	}

	serverPort, dirPath, found := strings.Cut(flag.Arg(0), "/")
	directory := "/"
	if found {
		directory += dirPath
	}

	// 1. Initialize the client
	c := gowebdav.NewClient("https://"+serverPort, "", "")

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
			return
		}
		tm.token, tm.issuedAt, tm.autoRefresh = fetched, time.Now(), true
	} else {
		tm.token = token
	}

	c.SetInterceptor(func(method string, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+tm.Get())
	})

	// 3. Connect
	err := c.Connect()
	if err != nil {
		fmt.Println("Connection failed:", err)
		return
	}

	// 4. Recursively scan the tree with a pool of worker goroutines.
	ctx, cancel := context.WithCancelCause(context.Background())
	jobs := make(chan string, 100)
	var wg sync.WaitGroup
	var printMu sync.Mutex
	var emptyDirsMu sync.Mutex
	var emptyDirs []string
	var numFiles, numBytes, numDirs atomic.Int64

	readDirWithRetry := func(path string) ([]os.FileInfo, error) {
		var lastErr error
		for attempt := 0; attempt <= retries; attempt++ {
			if attempt > 0 {
				fmt.Fprintf(os.Stderr, "Warning: retrying %q (attempt %d of %d) after error: %v\n", path, attempt, retries, lastErr)
				time.Sleep(500 * time.Millisecond)
			}
			entries, err := c.ReadDir(path)
			if err == nil {
				return entries, nil
			}
			lastErr = err
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

	if err := os.WriteFile("empty_dirs.out", []byte(strings.Join(emptyDirs, "\n")+"\n"), 0644); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to write empty_dirs.out:", err)
	}

	s := summary{
		Files:            numFiles.Load(),
		Bytes:            numBytes.Load(),
		Directories:      numDirs.Load(),
		EmptyDirectories: int64(len(emptyDirs)),
	}
	if data, err := json.MarshalIndent(s, "", "  "); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to marshal summary:", err)
	} else if err := os.WriteFile("ls_summary.json", data, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to write ls_summary.json:", err)
	}

	if cause := context.Cause(ctx); cause != nil {
		fmt.Fprintln(os.Stderr, "Scan aborted:", cause)
		os.Exit(1)
	}
}
