package oauth2go

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"net"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2/clientcredentials"
)

func Test_server_handleToken(t *testing.T) {
	type fields struct {
		Server     http.Server
		clients    []*client
		users      []*user
		signingKey *ecdsa.PrivateKey
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &server{
				Server:     tt.fields.Server,
				clients:    tt.fields.clients,
				users:      tt.fields.users,
				signingKey: tt.fields.signingKey,
			}
			srv.handleToken(tt.args.w, tt.args.r)
		})
	}
}

func TestIntegration(t *testing.T) {
	srv := NewServer(":0", WithUser("admin", "admin"), WithClient("client", "secret"))
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
		return &srv.signingKey.PublicKey, nil
	})
	if err != nil {
		t.Errorf("Error while retrieving a token: %v", err)
	}

	log.Printf("JWT: %+v", jwtoken)
}
