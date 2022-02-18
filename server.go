package oauth2

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

// AuthorizationServer is an OAuth 2.0 authorization server
type AuthorizationServer struct {
	http.Server

	// our clients
	clients []*Client

	// our signing key
	signingKey *ecdsa.PrivateKey
}

type AuthorizationServerOption func(srv *AuthorizationServer)

func WithClient(clientID string, clientSecret string) AuthorizationServerOption {
	return func(srv *AuthorizationServer) {
		srv.clients = append(srv.clients, &Client{
			clientID:     clientID,
			clientSecret: clientSecret,
		})
	}
}

func NewServer(addr string, opts ...AuthorizationServerOption) *AuthorizationServer {
	mux := http.NewServeMux()

	srv := &AuthorizationServer{
		Server: http.Server{
			Handler: mux,
			Addr:    addr,
		},
		clients: []*Client{},
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

// PublicKey returns the public key of the signing key of this authorization server.
func (srv *AuthorizationServer) PublicKey() *ecdsa.PublicKey {
	return &srv.signingKey.PublicKey
}

func (srv *AuthorizationServer) handleToken(w http.ResponseWriter, r *http.Request) {
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
		Error(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}
}

// doClientCredentialsFlow implements the Client Credentials Grant
// flow (see https://datatracker.ietf.org/doc/html/rfc6749#section-4.4).
func (srv *AuthorizationServer) doClientCredentialsFlow(w http.ResponseWriter, r *http.Request) {
	var (
		err    error
		token  oauth2.Token
		client *Client
		expiry time.Time
	)

	// Retrieve the client
	if client, err = srv.retrieveClient(r); err != nil {
		w.Header().Set("WWW-Authenticate", "Basic")
		Error(w, "invalid_client", http.StatusUnauthorized)
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
		http.Error(w, "error while creating JWT", http.StatusInternalServerError)
		return
	}

	writeJSON(w, &token)
}

func (srv *AuthorizationServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var keySet = JSONWebKeySet{
		Keys: []JSONWebKey{
			{
				Kid: "1",
				Kty: "EC",
				X:   base64.RawURLEncoding.EncodeToString(srv.signingKey.X.Bytes()),
				Y:   base64.RawURLEncoding.EncodeToString(srv.signingKey.Y.Bytes()),
			},
		},
	}

	writeJSON(w, &keySet)
}

func (srv *AuthorizationServer) retrieveClient(r *http.Request) (*Client, error) {
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

func Error(w http.ResponseWriter, error string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")

	http.Error(w, fmt.Sprintf(`{"error": "%s"}`, error), statusCode)
}

func writeJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(value); err != nil {
		Error(w, "could not encode JSON", http.StatusInternalServerError)
		return
	}
}
