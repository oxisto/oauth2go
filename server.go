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
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

var (
	ErrClientNotFound             = errors.New("client not found")
	ErrInvalidBasicAuthentication = errors.New("invalid or missing basic authentication")
)

const (
	ErrorInvalidClient = "invalid_client"
	ErrorInvalidGrant  = "invalid_grant"
)

// AuthorizationServer is an OAuth 2.0 authorization server
type AuthorizationServer struct {
	http.Server

	// our clients
	clients []*Client

	// our signing key
	signingKey *ecdsa.PrivateKey

	// our codes and their expiry time
	codes map[string]time.Time
}

type AuthorizationServerOption func(srv *AuthorizationServer)

type CodeIssuer interface {
	IssueCode() string
	ValidateCode(code string) bool
}

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
		codes:   make(map[string]time.Time),
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
	case "authorization_code":
		srv.doAuthorizationCodeFlow(w, r)
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
	client, err = srv.retrieveClient(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Basic")
		Error(w, ErrorInvalidClient, http.StatusUnauthorized)
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

// doAuthorizationCodeFlow implements the Authorization Code Grant
// flow (see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1).
func (srv *AuthorizationServer) doAuthorizationCodeFlow(w http.ResponseWriter, r *http.Request) {
	var (
		err    error
		code   string
		token  oauth2.Token
		client *Client
		expiry time.Time
	)

	// Retrieve the client
	client, err = srv.retrieveClient(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Basic")
		Error(w, ErrorInvalidClient, http.StatusUnauthorized)
		return
	}

	// Retrieve the code
	code = r.FormValue("code")
	if !srv.ValidateCode(code) {
		Error(w, ErrorInvalidGrant, http.StatusBadRequest)
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

	t = jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Subject: client.clientID,
	})
	t.Header["kid"] = 1

	if token.RefreshToken, err = t.SignedString(srv.signingKey); err != nil {
		http.Error(w, "error while creating JWT", http.StatusInternalServerError)
		return
	}

	writeJSON(w, &token)
}

func (srv *AuthorizationServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	var (
		publicKey *ecdsa.PublicKey
		keySet    *JSONWebKeySet
	)

	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	publicKey = srv.PublicKey()

	keySet = &JSONWebKeySet{
		Keys: []JSONWebKey{
			{
				Kid: "1",
				Kty: "EC",
				X:   base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
				Y:   base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
			},
		},
	}

	writeJSON(w, keySet)
}

func (srv *AuthorizationServer) retrieveClient(r *http.Request) (*Client, error) {
	var (
		ok           bool
		clientID     string
		clientSecret string
	)

	clientID, clientSecret, ok = r.BasicAuth()

	if !ok {
		return nil, ErrInvalidBasicAuthentication
	}

	// Look for a matching client
	for _, c := range srv.clients {
		if c.clientID == clientID && c.clientSecret == clientSecret {
			return c, nil
		}
	}

	return nil, ErrClientNotFound
}

// IssueCode implements CodeIssuer.
func (srv *AuthorizationServer) IssueCode() (code string) {
	code = GenerateSecret()

	srv.codes[code] = time.Now().Add(10 * time.Minute)

	return code
}

// ValidateCode implements CodeIssuer. It checks if the code exists and is
// not expired. If the code exists, it will be invalidated after this call.
func (srv *AuthorizationServer) ValidateCode(code string) bool {
	var (
		expiry time.Time
		ok     bool
	)

	expiry, ok = srv.codes[code]
	if !ok {
		return false
	}

	if expiry.Before(time.Now()) {
		return false
	}

	// Invalidate it
	delete(srv.codes, code)

	return true
}

func Error(w http.ResponseWriter, error string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")

	http.Error(w, fmt.Sprintf(`{"error": "%s"}`, error), statusCode)
}

func RedirectError(w http.ResponseWriter, r *http.Request, redirectURI string, error string) {
	params := url.Values{}
	params.Add("error", error)

	http.Redirect(w, r, fmt.Sprintf("%s?%s", redirectURI, params.Encode()), http.StatusFound)
}

func writeJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(value); err != nil {
		Error(w, "could not encode JSON", http.StatusInternalServerError)
		return
	}
}

func GenerateSecret() string {
	b := make([]byte, 32)

	rand.Read(b)

	return base64.RawStdEncoding.EncodeToString(b)
}
