package oauth2

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2/clientcredentials"
)

func TestAuthorizationServer_handleToken(t *testing.T) {
	type fields struct {
		Server     http.Server
		clients    []*Client
		signingKey *ecdsa.PrivateKey
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantBody string
	}{
		{
			name: "unsupported grant",
			args: args{
				r: &http.Request{
					Method: "POST",
				},
			},
			wantBody: `{"error": "unsupported_grant_type"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()

			srv := &AuthorizationServer{
				Server:     tt.fields.Server,
				clients:    tt.fields.clients,
				signingKey: tt.fields.signingKey,
			}
			srv.handleToken(rr, tt.args.r)

			gotBody := strings.Trim(rr.Body.String(), "\n")
			if gotBody != tt.wantBody {
				t.Errorf("AuthorizationServer.handleToken() body = %v, wantBody %v", gotBody, tt.wantBody)
			}
		})
	}
}

func TestIntegration(t *testing.T) {
	srv := NewServer(":0", WithClient("client", "secret"))
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

func TestAuthorizationServer_retrieveClient(t *testing.T) {
	type fields struct {
		Server     http.Server
		clients    []*Client
		signingKey *ecdsa.PrivateKey
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Client
		wantErr bool
	}{
		{
			name: "Missing authorization",
			args: args{
				r: &http.Request{},
			},
			wantErr: true,
		},
		{
			name: "No base64 basic authorization",
			args: args{
				r: &http.Request{
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"Basic nothing"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Wrong basic authorization",
			args: args{
				r: &http.Request{
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"Basic bm90aGluZw=="},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid client credentials",
			args: args{
				r: &http.Request{
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"Basic Y2xpZW50Om5vdHNlY3JldA=="},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Valid client credentials",
			fields: fields{
				clients: []*Client{
					{
						clientID:     "client",
						clientSecret: "secret",
					},
				},
			},
			args: args{
				r: &http.Request{
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"Basic Y2xpZW50OnNlY3JldA=="},
					},
				},
			},
			want: &Client{
				clientID:     "client",
				clientSecret: "secret",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &AuthorizationServer{
				Server:     tt.fields.Server,
				clients:    tt.fields.clients,
				signingKey: tt.fields.signingKey,
			}
			got, err := srv.retrieveClient(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthorizationServer.retrieveClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AuthorizationServer.retrieveClient() = %v, want %v", got, tt.want)
			}
		})
	}
}
