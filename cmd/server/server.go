package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"

	oauth2 "github.com/oxisto/oauth2go"
	"github.com/oxisto/oauth2go/login"
)

func main() {
	port := 8080

	password := generatePassword()

	log.Printf("Creating new user admin with password %s", password)

	srv := oauth2.NewServer(fmt.Sprintf(":%d", port), login.WithLoginPage(login.WithUser("admin", password)))

	log.Printf("Creating new OAuth 2.0 server on :%d", port)

	log.Fatal(srv.ListenAndServe())
}

func generatePassword() string {
	b := make([]byte, 32)

	rand.Read(b)

	return base64.StdEncoding.EncodeToString(b)
}
