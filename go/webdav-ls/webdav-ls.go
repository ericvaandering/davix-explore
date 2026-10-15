// webdav-ls lists one WebDAV directory.
//
// It is the non-recursive counterpart to webdav-ls-r and writes the same
// stdout format, so the same parser handles both -- davs_scanner.py splits each
// line positionally with line.split().
//
// stdout carries the listing and nothing else. stderr stays silent unless the
// directory could not be listed, so a caller can read the exit code without
// filtering diagnostics out of a successful run.
//
// Exit codes:
//
//	0  the directory exists; its entries, if any, are on stdout
//	1  it does not exist, or is not a directory
//	2  the question could not be answered -- bad usage, no token, or the
//	   server was unreachable or refused the request
//
// An empty directory exits 0 with no output: it exists, it just has nothing in
// it. Separating 1 from 2 matters because "this directory is gone" and "I could
// not tell" look the same in a listing but mean opposite things to a caller
// deciding whether to act on the answer.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"cms-consistency/internal/webdavcli"
	"cms-consistency/internal/webdavsafe"

	"github.com/studio-b12/gowebdav"
)

const (
	exitExists       = 0
	exitMissing      = 1
	exitUndetermined = 2
)

func main() {
	var token string
	flag.StringVar(&token, "token", "", "Bearer token for Authorization header")
	flag.StringVar(&token, "t", "", "Bearer token for Authorization header (shorthand)")

	var timeout time.Duration
	flag.DurationVar(&timeout, "timeout", 5*time.Minute, "Overall time limit for the listing, including reading the response (0 disables)")

	var responseTimeout time.Duration
	flag.DurationVar(&responseTimeout, "response-timeout", 60*time.Second, "Time limit for the server to send response headers (0 disables)")

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: webdav-ls [--token TOKEN] [--timeout D] [--response-timeout D] server:port/directory")
		os.Exit(exitUndetermined)
	}

	serverPort, directory, err := webdavcli.ParseTarget(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid target:", err)
		os.Exit(exitUndetermined)
	}

	// A successful run says nothing on stderr, so silence the token helper's
	// own progress chatter. Failures still surface: the error is returned.
	webdavcli.LogOutput = nil
	tm, err := webdavcli.NewTokenManager(serverPort, directory, token)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to obtain token:", err)
		os.Exit(exitUndetermined)
	}

	// No OPTIONS preflight. webdav-ls-r needs one to fail fast before spawning
	// workers, but here the PROPFIND below is the only request -- it answers
	// existence directly, and asking twice would just add a round trip and
	// another way for a healthy directory to be reported as missing.
	c := gowebdav.NewClient("https://"+serverPort, "", "")
	c.SetTransport(webdavsafe.NewTransport(webdavcli.NewTransport(responseTimeout, 1)))
	c.SetTimeout(timeout)
	c.SetInterceptor(func(_ string, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+tm.Get())
	})

	entries, err := readDir(c, tm, directory)
	if err != nil {
		// 404 is a plain answer: it is not there. 405 is gowebdav's report that
		// the path exists but is not a collection, which is not the directory
		// that was asked about either.
		if gowebdav.IsErrNotFound(err) || gowebdav.IsErrCode(err, http.StatusMethodNotAllowed) {
			fmt.Fprintf(os.Stderr, "No such directory: %s\n", webdavcli.URL(serverPort, directory))
			os.Exit(exitMissing)
		}
		fmt.Fprintln(os.Stderr, "Could not list the directory:", err)
		os.Exit(exitUndetermined)
	}

	// Same layout as webdav-ls-r: mode, a literal 0, size, date, time, path.
	for _, e := range entries {
		kind := "-rwxrwxrwx" // Make it look like a regular file by default
		if e.IsDir() {
			kind = "drwxrwxrwx" // Make it look like a directory
		}
		fmt.Printf("%-10s 0 %12d  %s  %s\n", kind, e.Size(), e.ModTime().Format("2006-01-02 15:04:05"), e.(gowebdav.File).Path())
	}

	os.Exit(exitExists)
}

// readDir lists the directory, renewing the token once if the server rejects
// it. A 401 means the token expired, which retrying alone never fixes.
func readDir(c *gowebdav.Client, tm *webdavcli.TokenManager, directory string) ([]os.FileInfo, error) {
	used := tm.Current()
	entries, err := c.ReadDir(directory)
	if err != nil && gowebdav.IsErrCode(err, http.StatusUnauthorized) && tm.Refresh(used) {
		entries, err = c.ReadDir(directory)
	}
	return entries, err
}
