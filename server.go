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
	"strconv"
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

	DefaultExpireIn = time.Hour * 24
	DefaultAddress  = "http://localhost:8000"
)

type codeInfo struct {
	expiry    time.Time
	challenge string
}

// AuthorizationServer is an OAuth 2.0 authorization server
type AuthorizationServer struct {
	http.Server

	// clients contains our clients
	clients []*Client

	// signingKeys contains our signing keys
	signingKeys map[int]*ecdsa.PrivateKey

	// codes contains our codes and their expiry time and challenge
	codes map[string]*codeInfo

	// allowedOrigin is the allowed CORS origin
	allowedOrigin string

	// publicURL is the public facing address of this server. This is used to
	// populate its metadata.
	publicURL string

	// metadata contains server metadata according to RFC 8414. This is
	// populated automatically.
	metadata *ServerMetadata
}

type AuthorizationServerOption func(srv *AuthorizationServer)

type signingKeysFunc func() (keys map[int]*ecdsa.PrivateKey)

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

func WithPublicURL(publicURL string) AuthorizationServerOption {
	return func(srv *AuthorizationServer) {
		srv.publicURL = publicURL
	}
}

func WithSigningKeysFunc(f signingKeysFunc) AuthorizationServerOption {
	return func(srv *AuthorizationServer) {
		srv.signingKeys = f()
	}
}

func WithAllowedOrigins(origin string) AuthorizationServerOption {
	return func(srv *AuthorizationServer) {
		srv.allowedOrigin = origin
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

	// Build metadata
	if srv.publicURL == "" {
		srv.publicURL = DefaultAddress
	}
	srv.metadata = buildMetadata(srv.publicURL)

	if srv.signingKeys == nil {
		srv.signingKeys = generateSigningKeys()
	}

	mux.HandleFunc("/token", srv.handleToken)
	mux.HandleFunc("/certs", srv.handleJWKS)
	mux.HandleFunc("/.well-known/oauth-authorization-server", srv.handleMetadata)
	mux.HandleFunc("/.well-known/openid-configuration", srv.handleMetadata)

	return srv
}

// PublicKey returns the public keys of the signing key of this authorization
// server in a map, indexed by its kid.
func (srv *AuthorizationServer) PublicKeys() map[int]*ecdsa.PublicKey {
	var keys = make(map[int]*ecdsa.PublicKey, len(srv.signingKeys))

	for kid, key := range srv.signingKeys {
		keys[kid] = &key.PublicKey
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
	case "refresh_token":
		srv.doRefreshTokenFlow(w, r)
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

	token, err = srv.GenerateToken(client.ClientID, 0, -1)
	if err != nil {
		http.Error(w, "error while creating JWT", http.StatusInternalServerError)
		return
	}

	srv.writeToken(w, token)
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
	if client.Public() && verifier == "" {
		Error(w, ErrorInvalidRequest, http.StatusBadRequest)
		return
	}

	// Retrieve the code
	code = r.FormValue("code")
	if !srv.ValidateCode(verifier, code) {
		Error(w, ErrorInvalidGrant, http.StatusBadRequest)
		return
	}

	token, err = srv.GenerateToken(client.ClientID, 0, 0)
	if err != nil {
		http.Error(w, "error while creating JWT", http.StatusInternalServerError)
		return
	}

	srv.writeToken(w, token)
}

// doRefreshTokenFlow implements refreshing an access token.
// See https://datatracker.ietf.org/doc/html/rfc6749#section-6).
func (srv *AuthorizationServer) doRefreshTokenFlow(w http.ResponseWriter, r *http.Request) {
	var (
		err          error
		refreshToken string
		claims       jwt.RegisteredClaims
		client       *Client
		token        *Token
	)

	// Retrieve the token first, as we need it to find out which client this is
	refreshToken = r.FormValue("refresh_token")
	if refreshToken == "" {
		Error(w, ErrorInvalidRequest, http.StatusBadRequest)
		return
	}

	// Try to parse it as a JWT
	_, err = jwt.ParseWithClaims(refreshToken, &claims, func(t *jwt.Token) (interface{}, error) {
		kid, _ := strconv.ParseInt(t.Header["kid"].(string), 10, 64)

		return srv.PublicKeys()[int(kid)], nil
	})
	if err != nil {
		fmt.Printf("%+v", err)
		Error(w, ErrorInvalidGrant, http.StatusBadRequest)
		return
	}

	// The subject contains our client ID.
	client, err = srv.GetClient(claims.Subject)
	if err != nil {
		Error(w, ErrorInvalidClient, http.StatusUnauthorized)
		return
	}

	// If this is a public client, we can issue a new token
	if client.ClientSecret == "" {
		goto issue
	}

	// Otherwise, we must check for authentication
	client, err = srv.retrieveClient(r, false)
	if err != nil {
		Error(w, ErrorInvalidClient, http.StatusUnauthorized)
		return
	}

issue:
	token, err = srv.GenerateToken(client.ClientID, 0, -1)
	if err != nil {
		http.Error(w, "error while creating JWT", http.StatusInternalServerError)
		return
	}

	srv.writeToken(w, token)
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
		if !c.Public() && c.ClientID == clientID && c.ClientSecret == clientSecret {
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

	var challenge = GenerateCodeChallenge(verifier)

	// Check, if we need to check for a challenge
	if info.challenge != "" && subtle.ConstantTimeCompare([]byte(challenge), []byte(info.challenge)) == 0 {
		return false
	}

	// Invalidate it
	delete(srv.codes, code)

	return true
}

// GenerateToken generates a Token (comprising at least an acesss token) for a specific client,
// as specified by its ID. A signingKey needs to be specified, otherwise an error is thrown.
// Optionally, if a refreshKey is specified, that key is used to also create a refresh token.
func (srv *AuthorizationServer) GenerateToken(clientID string, signingKeyID int, refreshKeyID int) (token *Token, err error) {
	var (
		expiry     = time.Now().Add(DefaultExpireIn)
		signingKey *ecdsa.PrivateKey
		refreshKey *ecdsa.PrivateKey
		ok         bool
	)

	token = new(oauth2.Token)

	token.TokenType = "Bearer"
	token.Expiry = expiry

	signingKey, ok = srv.signingKeys[signingKeyID]
	if !ok {
		return nil, errors.New("invalid key ID")
	}

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
	if refreshKeyID != -1 {
		refreshKey, ok = srv.signingKeys[refreshKeyID]
		if !ok {
			return nil, errors.New("invalid key ID")
		}

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

func (srv *AuthorizationServer) cors(w http.ResponseWriter) {
	if srv.allowedOrigin != "" {
		w.Header().Add("Access-Control-Allow-Origin", srv.allowedOrigin)
	}
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

func (srv *AuthorizationServer) writeToken(w http.ResponseWriter, token *oauth2.Token) {
	// We need to transform this into our own struct, otherwise
	// the expiry will be translated into a string representation,
	// while it should be represented as seconds.
	s := struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Expiry       int    `json:"expires_in"`
	}{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       int(time.Until(token.Expiry).Seconds()),
	}

	srv.writeJSON(w, s)
}

func (srv *AuthorizationServer) writeJSON(w http.ResponseWriter, value interface{}) {
	w.Header().Set("Content-Type", "application/json")

	srv.cors(w)

	if err := json.NewEncoder(w).Encode(value); err != nil {
		Error(w, "could not encode JSON", http.StatusInternalServerError)
		return
	}
}

func GenerateSecret() string {
	b := make([]byte, 32)

	rand.Read(b)

	return base64.RawURLEncoding.EncodeToString(b)
}

func GenerateCodeChallenge(verifier string) string {
	var digest = sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// generateSigningKeys generates a set of signing keys
func generateSigningKeys() map[int]*ecdsa.PrivateKey {
	var signingKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	return map[int]*ecdsa.PrivateKey{0: signingKey}
}
