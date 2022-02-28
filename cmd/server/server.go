package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	oauth2 "github.com/oxisto/oauth2go"
	"github.com/oxisto/oauth2go/login"
)

var port = flag.Int("port", 8080, "the default port")
var redirectURI = flag.String("redirect-uri", "http://localhost", "the default redirect URI")
var srv *oauth2.AuthorizationServer
var ctx func(net.Listener) context.Context = nil

func main() {
	flag.Parse()

	userPassword := oauth2.GenerateSecret()
	clientPassword := oauth2.GenerateSecret()

	log.Printf(`Creating new user "admin" with password %s`, userPassword)
	log.Printf(`Creating new confidential client "client" with password %s`, clientPassword)
	log.Printf(`Creating new public client "public"`)

	srv = oauth2.NewServer(
		fmt.Sprintf(":%d", *port),
		oauth2.WithClient("client", clientPassword, *redirectURI),
		oauth2.WithClient("public", "", *redirectURI),
		login.WithLoginPage(login.WithUser("admin", userPassword)),
	)
	srv.BaseContext = ctx

	log.Printf("Starting new OAuth 2.0 server on :%d", *port)

	log.Fatal(srv.ListenAndServe())
}
