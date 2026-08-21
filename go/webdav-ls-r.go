package main

import (
	"flag"
	"fmt"

	"github.com/studio-b12/gowebdav"
)

func main() {
	var token string
	flag.StringVar(&token, "token", "", "Bearer token for Authorization header")
	flag.StringVar(&token, "t", "", "Bearer token for Authorization header (shorthand)")
	flag.Parse()

	if token == "" {
		fmt.Println("Missing required token: use --token or -t")
		return
	}

	// 1. Initialize the client
	c := gowebdav.NewClient("https://webdav.example.com", "user", "password")

	// 2. Set custom request headers
	c.SetHeader("Depth", "infinity")
	c.SetHeader("Authorization", "Bearer "+token)

	// 3. Connect and execute operations
	err := c.Connect()
	if err != nil {
		fmt.Println("Connection failed:", err)
		return
	}

	// Your headers will be sent automatically with this call
	files, _ := c.ReadDir("/")
	fmt.Println(files)
}
