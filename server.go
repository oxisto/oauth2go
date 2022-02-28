package oauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	ErrorInvalidRequest = "invalid_request"
	ErrorInvalidClient  = "invalid_client"
	ErrorInvalidGrant   = "invalid_grant"
)

type codeInfo struct {
	expiry    time.Time
	challenge string
}

// AuthorizationServer is an OAuth 2.0 authorization server
type AuthorizationServer struct {
	http.Server

	// our clients
	clients []*Client

	// our signing keys
	signingKeys []*ecdsa.PrivateKey

	// our codes and their expiry time and challenge
	codes map[string]*codeInfo
}

type AuthorizationServerOption func(srv *AuthorizationServer)

type CodeIssuer interface {
	IssueCode(challenge string) string
	ValidateCode(verifier string, code string) bool
}

func WithClient(
	clientID string,
	clientSecret string,
	redirectURI string,
) AuthorizationServerOption {
	return func(srv *AuthorizationServer) {
		srv.clients = append(srv.clients, &Client{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURI:  redirectURI,
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
		codes:   make(map[string]*codeInfo),
	}

	for _, o := range opts {
		o(srv)
	}

	// Create a new private key
	var signingKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	srv.signingKeys = []*ecdsa.PrivateKey{signingKey}

	mux.HandleFunc("/token", srv.handleToken)
	mux.HandleFunc("/.well-known/jwks.json", srv.handleJWKS)

	return srv
}

// PublicKey returns the public keys of the signing key of this authorization server.
func (srv *AuthorizationServer) PublicKeys() []*ecdsa.PublicKey {
	var keys = []*ecdsa.PublicKey{}

	for _, k := range srv.signingKeys {
		keys = append(keys, &k.PublicKey)
	}

	return keys
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
		token  *oauth2.Token
		client *Client
	)

	// Retrieve the client
	client, err = srv.retrieveClient(r, false)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Basic")
		Error(w, ErrorInvalidClient, http.StatusUnauthorized)
		return
	}

	token, err = generateToken(client.ClientID, srv.signingKeys[0], 0, nil, 0)
	if err != nil {
		http.Error(w, "error while creating JWT", http.StatusInternalServerError)
		return
	}

	writeJSON(w, token)
}

// doAuthorizationCodeFlow implements the Authorization Code Grant
// flow (see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1).
func (srv *AuthorizationServer) doAuthorizationCodeFlow(w http.ResponseWriter, r *http.Request) {
	var (
		err      error
		code     string
		verifier string
		token    *oauth2.Token
		client   *Client
	)

	// Retrieve the client
	client, err = srv.retrieveClient(r, true)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Basic")
		Error(w, ErrorInvalidClient, http.StatusUnauthorized)
		return
	}

	// Retrieve the code verifier. It is REQUIRED for public clients
	verifier = r.FormValue("code_verifier")
	if client.ClientSecret == "" && verifier == "" {
		Error(w, ErrorInvalidRequest, http.StatusBadRequest)
		return
	}

	// Retrieve the code
	code = r.FormValue("code")
	if !srv.ValidateCode(verifier, code) {
		Error(w, ErrorInvalidGrant, http.StatusBadRequest)
		return
	}

	token, err = generateToken(client.ClientID, srv.signingKeys[0], 0, srv.signingKeys[0], 0)
	if err != nil {
		http.Error(w, "error while creating JWT", http.StatusInternalServerError)
		return
	}

	writeJSON(w, token)
}

func (srv *AuthorizationServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	var (
		keySet *JSONWebKeySet
	)

	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keySet = &JSONWebKeySet{Keys: []JSONWebKey{}}

	for kid, key := range srv.PublicKeys() {
		keySet.Keys = append(keySet.Keys,
			JSONWebKey{
				// Currently, our kid is simply a 0-based index value of our signing keys array
				Kid: fmt.Sprintf("%d", kid),
				Kty: "EC",
				X:   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
				Y:   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
			})
	}

	writeJSON(w, keySet)
}

// GetClient returns the client for the given ID or ErrClientNotFound.
func (srv *AuthorizationServer) GetClient(clientID string) (*Client, error) {
	// Look for a matching client
	for _, c := range srv.clients {
		if c.ClientID == clientID {
			return c, nil
		}
	}

	return nil, ErrClientNotFound
}

func (srv *AuthorizationServer) retrieveClient(r *http.Request, allowPublic bool) (*Client, error) {
	var (
		ok           bool
		clientID     string
		clientSecret string
	)

	clientID, clientSecret, ok = r.BasicAuth()
	if !ok {
		// We could still recover from this, if public clients are allowed.
		// We force PKCE later in the handler function.
		if allowPublic {
			// Check, if we have a client ID, this might allow us to identify a public client
			clientID = r.FormValue("client_id")

			return srv.GetClient(clientID)
		}

		return nil, ErrInvalidBasicAuthentication
	}

	// Look for a matching client
	for _, c := range srv.clients {
		if c.ClientID == clientID && c.ClientSecret == clientSecret {
			return c, nil
		}
	}

	return nil, ErrClientNotFound
}

// IssueCode implements CodeIssuer.
func (srv *AuthorizationServer) IssueCode(challenge string) (code string) {
	code = GenerateSecret()

	srv.codes[code] = &codeInfo{
		expiry:    time.Now().Add(10 * time.Minute),
		challenge: challenge,
	}

	return code
}

// ValidateCode implements CodeIssuer. It checks if the code exists and is
// not expired. If the code exists, it will be invalidated after this call.
func (srv *AuthorizationServer) ValidateCode(verifier string, code string) bool {
	var (
		ok   bool
		info *codeInfo
	)

	info, ok = srv.codes[code]
	if !ok {
		return false
	}

	if info.expiry.Before(time.Now()) {
		return false
	}

	var cmpChallenge = base64.URLEncoding.EncodeToString(sha256.New().Sum([]byte(verifier)))

	if subtle.ConstantTimeCompare([]byte(cmpChallenge), []byte(info.challenge)) == 0 {
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

func RedirectError(w http.ResponseWriter,
	r *http.Request,
	redirectURI string,
	error string,
	errorDescription string,
) {
	params := url.Values{}
	params.Add("error", error)
	params.Add("error_description", errorDescription)

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

// generateToken generates a Token (comprising at least an acesss token) for a specific client,
// as specified by its ID. A signingKey needs to be specified, otherwise an error is thrown.
// Optionally, if a refreshKey is specified, that key is used to also create a refresh token.
func generateToken(clientID string,
	signingKey *ecdsa.PrivateKey,
	signingKeyID int,
	refreshKey *ecdsa.PrivateKey,
	refreshKeyID int,
) (token *Token, err error) {
	var expiry = time.Now().Add(24 * time.Hour)

	token = new(oauth2.Token)

	token.TokenType = "Bearer"
	token.Expiry = expiry

	// Create a new JWT
	t := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Subject:   clientID,
		ExpiresAt: jwt.NewNumericDate(expiry),
	})
	t.Header["kid"] = fmt.Sprintf("%d", signingKeyID)

	if token.AccessToken, err = t.SignedString(signingKey); err != nil {
		return nil, err
	}

	// Create a refresh token, if we have a key for it
	if refreshKey != nil {
		t = jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
			Subject: clientID,
		})
		t.Header["kid"] = fmt.Sprintf("%d", refreshKeyID)

		if token.RefreshToken, err = t.SignedString(refreshKey); err != nil {
			return nil, err
		}
	}

	return
}
