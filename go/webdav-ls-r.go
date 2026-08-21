package main

import (
	"fmt"

	"github.com/studio-b12/gowebdav"
)

func main() {
	// 1. Initialize the client
	c := gowebdav.NewClient("https://webdav.example.com", "user", "password")

	// 2. Set custom request headers
	c.SetHeader("Depth", "infinity")
	c.SetHeader("Authorization", "Bearer your_token_here")

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
