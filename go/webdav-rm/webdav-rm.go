package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/studio-b12/gowebdav"
)

func main() {
	var server string
	flag.StringVar(&server, "server", "", "Server:port to connect to")
	flag.StringVar(&server, "s", "", "Server:port to connect to (shorthand)")

	var token string
	flag.StringVar(&token, "token", "", "Bearer token for Authorization header")
	flag.StringVar(&token, "t", "", "Bearer token for Authorization header (shorthand)")

	var numWorkers int
	flag.IntVar(&numWorkers, "workers", 8, "Number of concurrent scanner goroutines")
	flag.IntVar(&numWorkers, "w", 8, "Number of concurrent scanner goroutines (shorthand)")

	var filePath string
	flag.StringVar(&filePath, "file", "", "File containing paths to remove, one per line")
	flag.StringVar(&filePath, "f", "", "File containing paths to remove, one per line (shorthand)")

	var limit int
	flag.IntVar(&limit, "limit", -1, "Maximum number of deletions to perform (-1 for no limit)")
	flag.IntVar(&limit, "n", -1, "Maximum number of deletions to perform (shorthand, -1 for no limit)")

	var dryRun bool
	flag.BoolVar(&dryRun, "dry-run", false, "Print what would be removed without actually deleting anything")

	flag.Parse()

	if server == "" {
		fmt.Println("Missing required server: use --server or -s")
		return
	}

	if token == "" {
		fmt.Println("Missing required token: use --token or -t")
		return
	}

	// 1. Initialize the client
	c := gowebdav.NewClient("https://"+server, "", "")

	// 2. Set custom request headers
	// c.SetHeader("Depth", "infinity")
	c.SetHeader("Authorization", "Bearer "+token)

	// 3. Connect
	err := c.Connect()
	if err != nil {
		fmt.Println("Connection failed:", err)
		return
	}

	if filePath == "" {
		return
	}

	// 4. Read the paths to remove and delete them with a pool of worker goroutines.
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read", filePath, ":", err)
		os.Exit(1)
	}

	jobs := make(chan string, 100)
	var wg sync.WaitGroup
	var printMu sync.Mutex
	var numRemoved, numSkipped, numFailed atomic.Int64

	worker := func() {
		for path := range jobs {
			entries, err := c.ReadDir(path)
			if err != nil {
				numFailed.Add(1)
				printMu.Lock()
				fmt.Fprintf(os.Stderr, "Skipping %q: failed to list: %v\n", path, err)
				printMu.Unlock()
				wg.Done()
				continue
			}
			if len(entries) > 0 {
				numSkipped.Add(1)
				printMu.Lock()
				fmt.Fprintf(os.Stderr, "Skipping %q: not empty (%d entries)\n", path, len(entries))
				printMu.Unlock()
				wg.Done()
				continue
			}

			if dryRun {
				numRemoved.Add(1)
				printMu.Lock()
				fmt.Println("Would remove:", path)
				printMu.Unlock()
				wg.Done()
				continue
			}

			err = c.Remove(path)

			printMu.Lock()
			if err != nil {
				numFailed.Add(1)
				var statusErr gowebdav.StatusError
				if errors.As(err, &statusErr) {
					fmt.Fprintf(os.Stderr, "Failed to remove %q: server returned HTTP status %d\n", path, statusErr.Status)
				} else {
					fmt.Fprintf(os.Stderr, "Failed to remove %q: %v\n", path, err)
				}
			} else {
				numRemoved.Add(1)
				fmt.Println("Removed:", path)
			}
			printMu.Unlock()

			wg.Done()
		}
	}

	for i := 0; i < numWorkers; i++ {
		go worker()
	}

	submitted := 0
	for _, line := range strings.Split(string(data), "\n") {
		path := strings.TrimSpace(line)
		if path == "" {
			continue
		}
		if limit >= 0 && submitted >= limit {
			break
		}
		submitted++
		wg.Add(1)
		jobs <- path
	}

	close(jobs)
	wg.Wait()

	removedLabel := "removed"
	if dryRun {
		removedLabel = "would remove"
	}
	fmt.Printf("\n%s: %d, skipped (not empty): %d, failed: %d\n",
		removedLabel, numRemoved.Load(), numSkipped.Load(), numFailed.Load())

	if numFailed.Load() > 0 {
		os.Exit(1)
	}
}