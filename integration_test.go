package oauth2_test

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	oauth2 "github.com/oxisto/oauth2go"
	"github.com/oxisto/oauth2go/login"
	"github.com/oxisto/oauth2go/storage"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/html"
	"golang.org/x/oauth2/clientcredentials"
)

func TestIntegration(t *testing.T) {
	srv := oauth2.NewServer(
		":0",
		oauth2.WithClient("client", "secret", ""),
		oauth2.WithSigningKeysFunc(func() map[int]*ecdsa.PrivateKey {
			return storage.LoadSigningKeys("storage/testdata/ecdsa.pem", "changeme", false)
		}),
	)
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		t.Errorf("Error while listening key: %v", err)
	}

	port := ln.Addr().(*net.TCPAddr).Port

	go srv.Serve(ln)
	defer srv.Close()

	config := clientcredentials.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		TokenURL:     fmt.Sprintf("http://localhost:%d/token", port),
	}

	token, err := config.Token(context.Background())
	if err != nil {
		t.Errorf("Error while retrieving a token: %v", err)
	}

	log.Printf("Token: %s", token.AccessToken)

	jwtoken, err := jwt.ParseWithClaims(token.AccessToken, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		kid, _ := strconv.ParseInt(t.Header["kid"].(string), 10, 64)

		return srv.PublicKeys()[int(kid)], nil
	})
	if err != nil {
		t.Errorf("Error while retrieving a token: %v", err)
	}

	log.Printf("JWT: %+v", jwtoken)
}

func TestThreeLeggedFlowPublicClient(t *testing.T) {
	var (
		res       *http.Response
		req       *http.Request
		client    *http.Client
		form      url.Values
		session   *http.Cookie
		token     *oauth2.Token
		newToken  *oauth2.Token
		source    oauth2.TokenSource
		code      string
		challenge string
		verifier  string
	)

	srv := oauth2.NewServer(":0",
		oauth2.WithClient("public", "", "/test"),
		login.WithLoginPage(login.WithUser("admin", "admin")),
	)

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		t.Errorf("Error while listening key: %v", err)
	}

	port := ln.Addr().(*net.TCPAddr).Port

	go srv.Serve(ln)
	defer srv.Close()

	config := oauth2.Config{
		ClientID:     "public",
		ClientSecret: "",
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("http://localhost:%d/authorize", port),
			TokenURL: fmt.Sprintf("http://localhost:%d/token", port),
		},
		RedirectURL: "/test",
	}

	// create a challenge and verifier
	verifier = "012345678901234567890123456789012345678901234567890123456789"
	challenge = oauth2.GenerateCodeChallenge(verifier)

	// Let's pretend to be a browser
	res, err = http.Get(config.AuthCodeURL("some-state",
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	))
	if err != nil {
		t.Errorf("Error while POST /authorize: %v", err)
	}

	// We are interested in two things
	// - The session ID (or the cookie)
	// - The CSRF token
	for _, c := range res.Cookies() {
		if c.Name == "id" {
			session = c
			break
		}
	}

	if session == nil {
		t.Errorf("Error session is nil")
	}

	// Parse the HTML body to look for the csrf_token
	root, _ := html.Parse(res.Body)

	form = url.Values{}
	walker := func(node *html.Node) {
		if node.Type == html.ElementNode &&
			node.Data == "input" &&
			len(node.Attr) == 3 {
			form.Add(node.Attr[1].Val, node.Attr[2].Val)
		}
	}

	traverse(root, walker)

	form.Add("username", "admin")
	form.Add("password", "admin")

	req, _ = http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/login", port), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)

	// Let's POST our login
	client = &http.Client{}
	res, err = client.Do(req)
	if err != nil {
		t.Errorf("Error while POST /login: %v", err)
	}

	// Extract the code from the response
	code = res.Request.URL.Query().Get("code")

	token, err = config.Exchange(context.Background(),
		code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		t.Errorf("Error while Exchange: %v", err)
	}

	if token.AccessToken == "" {
		t.Error("Access token is empty")
	}

	if token.RefreshToken == "" {
		t.Error("Access token is empty")
	}

	// For some extra fun, let's use our refresh token by declaring our token expired
	token.Expiry = time.Now().Add(-5 * time.Minute)
	source = config.TokenSource(context.Background(), token)

	newToken, err = source.Token()
	if err != nil {
		t.Errorf("Error while fetching from token source: %v", err)
	}

	if newToken.AccessToken == "" {
		t.Error("Access token is empty")
	}

	// Access tokens should be different
	if newToken.AccessToken == token.AccessToken {
		t.Error("New token is not different")
	}

	// Refresh tokens should be the same
	if newToken.RefreshToken != token.RefreshToken {
		t.Error("Refresh token is different")
	}
}

func TestThreeLeggedFlowConfidentialClient(t *testing.T) {
	var (
		res     *http.Response
		req     *http.Request
		client  *http.Client
		form    url.Values
		session *http.Cookie
		token   *oauth2.Token
		code    string
	)

	srv := oauth2.NewServer(":0",
		oauth2.WithClient("client", "secret", "/test"),
		login.WithLoginPage(login.WithUser("admin", "admin")),
	)

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		t.Errorf("Error while listening key: %v", err)
	}

	port := ln.Addr().(*net.TCPAddr).Port

	go srv.Serve(ln)
	defer srv.Close()

	config := oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("http://localhost:%d/authorize", port),
			TokenURL: fmt.Sprintf("http://localhost:%d/token", port),
		},
		RedirectURL: "/test",
	}

	// Let's pretend to be a browser
	res, err = http.Get(config.AuthCodeURL("some-state"))
	if err != nil {
		t.Errorf("Error while POST /authorize: %v", err)
	}

	// We are interested in two things
	// - The session ID (or the cookie)
	// - The CSRF token
	for _, c := range res.Cookies() {
		if c.Name == "id" {
			session = c
			break
		}
	}

	if session == nil {
		t.Errorf("Error session is nil")
	}

	// Parse the HTML body to look for the csrf_token
	root, _ := html.Parse(res.Body)

	form = url.Values{}
	walker := func(node *html.Node) {
		if node.Type == html.ElementNode &&
			node.Data == "input" &&
			len(node.Attr) == 3 {
			form.Add(node.Attr[1].Val, node.Attr[2].Val)
		}
	}

	traverse(root, walker)

	form.Add("username", "admin")
	form.Add("password", "admin")

	req, _ = http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/login", port), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)

	// Let's POST our login
	client = &http.Client{}
	res, err = client.Do(req)
	if err != nil {
		t.Errorf("Error while POST /login: %v", err)
	}

	// Extract the code from the response
	code = res.Request.URL.Query().Get("code")

	token, err = config.Exchange(context.Background(),
		code,
	)
	if err != nil {
		t.Errorf("Error while Exchange: %v", err)
	}

	if token.AccessToken == "" {
		t.Error("Access token is empty", err)
	}

	if token.RefreshToken == "" {
		t.Error("Access token is empty", err)
	}
}

func traverse(root *html.Node, walker func(node *html.Node)) {
	var f func(*html.Node)

	f = func(n *html.Node) {
		walker(n)

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}

	f(root)
}
