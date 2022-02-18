package login_test

import (
	"testing"

	oauth2 "github.com/oxisto/oauth2go"
	"github.com/oxisto/oauth2go/login"
)

func TestIntegration(t *testing.T) {
	srv := oauth2.NewServer(":0", login.WithLoginPage(login.WithUser("admin", "admin")))
	go srv.ListenAndServe()
	defer srv.Close()
}
