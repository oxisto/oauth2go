// package login contains an optional "login" (authentication) server that can be used. It offers a simple
// (in the future customizable) login form that sends username / password via POST formdata
// to a /login endpoint. The authentication server then issues a cookie-based session.
//
// This package can be used to turn oauth2go in a more-or-less complete authentication service.
// If this package is not used, an external authentication page that establishes a web-session with the
// user is needed.
package login

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"time"

	oauth2 "github.com/oxisto/oauth2go"
)

//go:embed login.html
var files embed.FS

func WithLoginPage(opts ...handlerOption) oauth2.AuthorizationServerOption {
	h := NewHandler()

	for _, o := range opts {
		o(h)
	}

	return func(srv *oauth2.AuthorizationServer) {
		srv.Handler.(*http.ServeMux).Handle("/login", h)
	}
}

func WithUser(name string, password string) handlerOption {
	return func(srv *handler) {
		srv.users = append(srv.users, &User{
			name:     name,
			password: password,
		})
	}
}

type handlerOption func(*handler)

// session describes a currently active login session for a particular user
type session struct {
	User *User

	ExpireAt time.Time
}

func (s *session) Expired() bool {
	return s.ExpireAt.After(time.Now())
}

type handler struct {
	// sessions contains a map of (random) session IDs to a session object
	sessions map[string]*session

	// our users
	users []*User
}

type User struct {
	name     string
	password string
}

func NewHandler() *handler {
	return &handler{
		sessions: map[string]*session{},
		users:    []*User{},
	}
}

func init() {

}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		var tmpl, err = template.ParseFS(files, "login.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, map[string]interface{}{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	} else if r.Method == "POST" {
		h.doLoginPost(w, r)
	}
}

func (h *handler) newSession(user *User) {
	// Generate a new session ID
	var b = make([]byte, 32)
	rand.Read(b)

	id := base64.StdEncoding.EncodeToString(b)

	session := session{
		User:     user,
		ExpireAt: time.Now().Add(time.Minute * 24),
	}

	h.sessions[id] = &session
}

func (h *handler) doLoginPost(w http.ResponseWriter, r *http.Request) {
	c := http.Cookie{}

	fmt.Printf("need to issue cookie: %+v", c)

	// Start a new session
	h.newSession(h.users[0])

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
