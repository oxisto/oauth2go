package oauth2_test

import (
	"fmt"

	oauth2 "github.com/oxisto/oauth2go"
	"github.com/oxisto/oauth2go/login"
)

// ExampleLoginPage sets up an OAuth 2.0 authorization server with an integrated
// login page (acting as an authentication server).
func ExampleAuthorizationServer() {
	var srv *oauth2.AuthorizationServer
	var port = 8000

	srv = oauth2.NewServer(fmt.Sprintf(":%d", port),
		login.WithLoginPage(login.WithUser("admin", "admin")),
	)

	fmt.Printf("Creating new OAuth 2.0 server on %d", port)
	// Output: Creating new OAuth 2.0 server on 8000

	go srv.ListenAndServe()
	defer srv.Close()
}
