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

var port = flag.Int("port", 8000, "the default port")
var publicURL = flag.String("public-url", "http://localhost:8000", "the default public facing URL. Will be used in server metadata")
var redirectURI = flag.String("redirect-uri", "http://localhost", "the default redirect URI")

var clientSecret = flag.String("client-secret", "", "a client secret. If not specified, one will be generated")
var userPassword = flag.String("user-password", "", "a user password. If not specified, one will be generated")

var srv *oauth2.AuthorizationServer
var ctx func(net.Listener) context.Context = nil

func main() {
	flag.Parse()

	if *clientSecret == "" {
		*clientSecret = oauth2.GenerateSecret()
	}

	if *userPassword == "" {
		*userPassword = oauth2.GenerateSecret()
	}

	log.Printf(`Creating new user "admin" with password %s`, *userPassword)
	log.Printf(`Creating new confidential client "client" with password %s`, *clientSecret)
	log.Printf(`Creating new public client "public"`)

	srv = oauth2.NewServer(
		fmt.Sprintf(":%d", *port),
		oauth2.WithClient("client", *clientSecret, *redirectURI),
		oauth2.WithClient("public", "", *redirectURI),
		oauth2.WithPublicURL(*publicURL),
		login.WithLoginPage(login.WithUser("admin", *userPassword)),
		oauth2.WithAllowedOrigins("*"),
	)
	srv.BaseContext = ctx

	log.Printf("Starting new OAuth 2.0 server on :%d", *port)

	log.Fatal(srv.ListenAndServe())
}
