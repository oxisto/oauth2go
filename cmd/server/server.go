package main

import (
	"fmt"
	"log"

	"github.com/oxisto/oauth2go"
)

func main() {
	port := 8080

	srv := oauth2go.NewServer(fmt.Sprintf(":%d", port))

	log.Printf("Creating new OAuth 2.0 server on :%d", port)

	log.Fatal(srv.ListenAndServe())
}
