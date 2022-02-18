package oauth2_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	oauth2 "github.com/oxisto/oauth2go"
	"golang.org/x/oauth2/clientcredentials"
)

func TestIntegration(t *testing.T) {
	srv := oauth2.NewServer(":0", oauth2.WithClient("client", "secret"))
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		t.Errorf("Error while listening key: %v", err)
	}

	go srv.Serve(ln)
	defer srv.Close()

	config := clientcredentials.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		TokenURL:     fmt.Sprintf("http://localhost:%d/token", ln.Addr().(*net.TCPAddr).Port),
	}

	token, err := config.Token(context.Background())
	if err != nil {
		t.Errorf("Error while retrieving a token: %v", err)
	}

	log.Printf("Token: %s", token.AccessToken)

	jwtoken, err := jwt.ParseWithClaims(token.AccessToken, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		return srv.PublicKey(), nil
	})
	if err != nil {
		t.Errorf("Error while retrieving a token: %v", err)
	}

	log.Printf("JWT: %+v", jwtoken)
}
