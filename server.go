package oauth2go

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

type server struct {
	http.Server

	// our clients
	clients []*client

	// our users
	users []*user

	// our signing key
	signingKey *ecdsa.PrivateKey
}

type user struct {
	name     string
	password string
}

type client struct {
	clientID     string
	clientSecret string
}

// JSONWebKey is a JSON Web Key that only supports elliptic curve keys for now.
type JSONWebKey struct {
	Kid string `json:"kid"`

	Kty string `json:"kty"`

	X string `json:"x"`

	Y string `json:"y"`
}

type ServerOption func(srv *server)

func WithUser(name string, password string) ServerOption {
	return func(srv *server) {
		srv.users = append(srv.users, &user{
			name:     name,
			password: password,
		})
	}
}

func WithClient(clientID string, clientSecret string) ServerOption {
	return func(srv *server) {
		srv.clients = append(srv.clients, &client{
			clientID:     clientID,
			clientSecret: clientSecret,
		})
	}
}

func NewServer(addr string, opts ...ServerOption) *server {
	mux := http.NewServeMux()

	srv := &server{
		Server: http.Server{
			Handler: mux,
			Addr:    addr,
		},
		clients: []*client{},
		users:   []*user{},
	}

	for _, o := range opts {
		o(srv)
	}

	// Create a new private key
	srv.signingKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	mux.HandleFunc("/token", srv.handleToken)
	mux.HandleFunc("/.well-known/jwks.json", srv.handleJWKS)

	return srv
}

func (srv *server) handleToken(w http.ResponseWriter, r *http.Request) {
	var err error

	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	if err = r.ParseForm(); err != nil {
		w.WriteHeader(500)
	}

	grantType := r.PostForm.Get("grant_type")

	switch grantType {
	case "client_credentials":
		srv.doClientCredentialsFlow(w, r)
	default:
		writeError(w, 400, "unsupported_grant_type")
		return
	}
}

// doClientCredentialsFlow implements the Client Credentials Grant
// flow (see https://datatracker.ietf.org/doc/html/rfc6749#section-4.4).
func (srv *server) doClientCredentialsFlow(w http.ResponseWriter, r *http.Request) {
	var (
		err    error
		token  oauth2.Token
		client *client
		expiry time.Time
	)

	// Retrieve the client
	if client, err = srv.retrieveClient(r); err != nil {
		w.Header().Set("WWW-Authenticate", "Basic")
		writeError(w, 401, "invalid_client")
		return
	}

	expiry = time.Now().Add(time.Hour * 24)

	// Create a new JWT
	t := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Subject:   client.clientID,
		ExpiresAt: jwt.NewNumericDate(expiry),
	})
	t.Header["kid"] = 1

	token.TokenType = "Bearer"
	token.Expiry = expiry
	if token.AccessToken, err = t.SignedString(srv.signingKey); err != nil {
		writeError(w, 500, "error while creating JWT")
	}

	writeJSON(w, &token)
}

func (srv *server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method not allowed")
		return
	}

	var keySet = struct {
		Keys []JSONWebKey `json:"keys"`
	}{
		Keys: []JSONWebKey{
			{
				Kid: "1",
				Kty: "EC",
				X:   base64.RawURLEncoding.EncodeToString(srv.signingKey.X.Bytes()),
				Y:   base64.RawURLEncoding.EncodeToString(srv.signingKey.X.Bytes()),
			},
		},
	}

	writeJSON(w, &keySet)
}

func (srv *server) retrieveClient(r *http.Request) (*client, error) {
	var (
		idx           int
		b             []byte
		authorization string
		basic         string
		clientID      string
		clientSecret  string
	)

	authorization = r.Header.Get("authorization")
	idx = strings.Index(authorization, "Basic ")
	if idx == -1 {
		return nil, errors.New("invalid authentication scheme")
	}

	b, err := base64.StdEncoding.DecodeString(authorization[idx+6:])
	if err != nil {
		return nil, fmt.Errorf("could not decode basic authentication: %w", err)
	}

	basic = string(b)
	idx = strings.Index(basic, ":")
	if idx == -1 {
		return nil, errors.New("misformed basic authentication")
	}

	clientID = basic[0:idx]
	clientSecret = basic[idx+1:]

	// Look for a matching client
	for _, c := range srv.clients {
		if c.clientID == clientID && c.clientSecret == clientSecret {
			return c, nil
		}
	}

	return nil, errors.New("no matching client")
}

func writeError(w http.ResponseWriter, statusCode int, error string) {
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(statusCode)
	w.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, error)))
}

func writeJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(value); err != nil {
		writeError(w, 500, "could not encode JSON")
		return
	}
}
