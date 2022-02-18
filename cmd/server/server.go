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
var srv *oauth2.AuthorizationServer
var readyToServe chan bool
var ctx = func(net.Listener) context.Context {
	return context.Background()
}

func main() {
	flag.Parse()

	password := login.GeneratePassword()

	log.Printf("Creating new user admin with password %s", password)

	srv = oauth2.NewServer(fmt.Sprintf(":%d", *port), login.WithLoginPage(login.WithUser("admin", password)))
	srv.BaseContext = ctx

	log.Printf("Creating new OAuth 2.0 server on :%d", *port)

	go func() { readyToServe <- true }()

	log.Fatal(srv.ListenAndServe())
}
