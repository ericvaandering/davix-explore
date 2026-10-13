// webdav-ls reports whether a single WebDAV directory exists.
//
// It is the non-recursive counterpart to webdav-ls-r: no listing, no output on
// success, just an exit code. Nothing is printed to stdout, so a caller can
// test a target without parsing anything.
//
// Exit codes:
//
//	0  the directory exists
//	1  it does not exist (404), or is not a directory
//	2  the question could not be answered -- bad usage, no token, or the
//	   server was unreachable or refused the request
//
// Separating 1 from 2 matters: "this directory is gone" and "I could not tell"
// look the same in a listing but mean opposite things to a caller deciding
// whether to act on the answer.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"cms-consistency/internal/webdavcli"
	"cms-consistency/internal/webdavsafe"

	"github.com/studio-b12/gowebdav"
)

// Exit codes. Anything other than exists/missing is "could not determine".
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
	flag.DurationVar(&timeout, "timeout", time.Minute, "Overall time limit for a single request, including reading the response (0 disables)")

	var responseTimeout time.Duration
	flag.DurationVar(&responseTimeout, "response-timeout", 30*time.Second, "Time limit for the server to send response headers (0 disables)")

	var quiet bool
	flag.BoolVar(&quiet, "quiet", false, "Suppress diagnostics on stderr; report only through the exit code")
	flag.BoolVar(&quiet, "q", false, "Suppress diagnostics on stderr (shorthand)")

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: webdav-ls [--token TOKEN] [--timeout D] [--response-timeout D] [--quiet] server:port/directory")
		os.Exit(exitUndetermined)
	}

	// Diagnostics go to stderr and stdout is left empty, so a caller can read
	// the exit code without parsing anything.
	errOut := io.Discard
	if !quiet {
		errOut = os.Stderr
	}

	serverPort, directory, err := webdavcli.ParseTarget(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(errOut, "Invalid target:", err)
		os.Exit(exitUndetermined)
	}

	tm, err := webdavcli.NewTokenManager(serverPort, directory, token)
	if err != nil {
		fmt.Fprintln(errOut, "Failed to obtain token:", err)
		os.Exit(exitUndetermined)
	}

	recorder := webdavcli.NewHeaderRecorder(
		webdavsafe.NewTransport(webdavcli.NewTransport(responseTimeout, 1)))

	// Preflight the directory itself rather than the server root: some storage
	// elements return 404 on "/" while serving the target perfectly well, so
	// asking about the root would report a healthy directory as missing.
	//
	// A rejected preflight is not an answer about existence -- the OPTIONS may
	// have been refused for reasons of its own -- so fall through to the
	// PROPFIND rather than concluding anything, and keep the recording in case
	// that fails too.
	preflightErr := webdavcli.Preflight(recorder, timeout, serverPort, directory, tm.Get())

	c := gowebdav.NewClient("https://"+serverPort, "", "")
	c.SetTransport(recorder)
	c.SetTimeout(timeout)
	c.SetInterceptor(func(_ string, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+tm.Get())
	})

	info, err := stat(c, tm, directory)
	if err != nil {
		if gowebdav.IsErrNotFound(err) {
			fmt.Fprintf(errOut, "Does not exist: %s\n", webdavcli.URL(serverPort, directory))
			os.Exit(exitMissing)
		}
		fmt.Fprintln(errOut, "Could not determine whether it exists:", err)
		if preflightErr != nil {
			fmt.Fprintln(errOut, "The OPTIONS preflight also failed:", preflightErr)
		}
		recorder.Dump(errOut)
		os.Exit(exitUndetermined)
	}

	// A file where a directory was expected is not the thing asked about.
	if !info.IsDir() {
		fmt.Fprintf(errOut, "Exists but is not a directory: %s\n", webdavcli.URL(serverPort, directory))
		os.Exit(exitMissing)
	}

	fmt.Fprintf(errOut, "Exists: %s\n", webdavcli.URL(serverPort, directory))
	os.Exit(exitExists)
}

// stat looks the directory up, renewing the token once if the server rejects
// it. A 401 means the token expired, which retrying alone never fixes.
func stat(c *gowebdav.Client, tm *webdavcli.TokenManager, directory string) (os.FileInfo, error) {
	used := tm.Current()
	info, err := c.Stat(directory)
	if err != nil && gowebdav.IsErrCode(err, http.StatusUnauthorized) && tm.Refresh(used) {
		info, err = c.Stat(directory)
	}
	return info, err
}
