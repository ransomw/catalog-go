package main

import (
	"net/http"
	"fmt"
	"os"

	"sand/go-catalog/server"
)

func main() {
	s, err := server.NewServer()
	if err != nil {
		fmt.Println("server init error")
		fmt.Println(err)
		os.Exit(1)
	}
	r := server.InitRouter(s)
	fmt.Println("serving on 3003...")
	http.ListenAndServe(":3003", r)
}
