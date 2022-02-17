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
	"html/template"
	"log"
	"net/http"
	"sync"
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
	ID string

	User *User

	ExpireAt time.Time
}

func (s *session) Expired() bool {
	return s.ExpireAt.Before(time.Now())
}

type handler struct {
	// sessions contains a map of (random) session IDs to a session object
	sessions map[string]*session

	// sm is a mutex for the session
	sm sync.RWMutex

	// our users
	users []*User

	log oauth2.Logger
}

type User struct {
	name     string
	password string
}

func NewHandler() *handler {
	h := &handler{
		sessions: map[string]*session{},
		users:    []*User{},
	}

	if h.log == nil {
		h.log = log.Default()
	}

	return h
}

func init() {

}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		h.doLoginGet(w, r)
	} else if r.Method == "POST" {
		h.doLoginPost(w, r)
	}
}

func (h *handler) newSession(user *User) *session {
	// Generate a new session ID
	var b = make([]byte, 32)
	rand.Read(b)

	id := base64.StdEncoding.EncodeToString(b)

	session := session{
		ID:       id,
		User:     user,
		ExpireAt: time.Now().Add(time.Minute * 24),
	}

	h.sm.Lock()
	defer h.sm.Unlock()

	h.sessions[id] = &session

	return &session
}

func (h *handler) removeSession(id string) {
	h.sm.Lock()
	defer h.sm.Unlock()

	delete(h.sessions, id)
}

func (h *handler) doLoginGet(w http.ResponseWriter, r *http.Request) {
	var (
		err     error
		ok      bool
		cookie  *http.Cookie
		session *session
	)

	// Check, if we have have a cookie
	cookie, err = r.Cookie("id")
	if err != nil {
		// Regardless of the error, we display the login page
		h.handleLoginPage(w, r)
		return
	}

	// Check, if the cookie points to a valid (not expired) session
	h.sm.RLock()
	session, ok = h.sessions[cookie.Value]
	h.sm.RUnlock()

	if !ok {
		// No session, so we display the login page
		h.handleLoginPage(w, r)
		return
	}

	if session.Expired() {
		// Session is expired, so we remove it from our list and also display the login page
		h.removeSession(session.ID)
		h.handleLoginPage(w, r)
		return
	}

	// Seems like we have a valid session. Woohoo. Nothing to do except redirecting
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *handler) handleLoginPage(w http.ResponseWriter, r *http.Request) {
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
}

func (h *handler) doLoginPost(w http.ResponseWriter, r *http.Request) {
	var err error
	if err = r.ParseForm(); err != nil {
		http.Error(w, "could not parse form data", http.StatusInternalServerError)
		return
	}

	user := h.user(r.FormValue("username"), r.FormValue("password"))
	if user == nil {
		// TODO(oxisto): Redirect back to login page?
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Start a new session
	session := h.newSession(user)

	c := http.Cookie{
		Name:    "id",
		Value:   session.ID,
		Path:    "/",
		Expires: session.ExpireAt,
	}

	http.SetCookie(w, &c)

	h.log.Printf("Generating new session with id %s", session.ID)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *handler) user(username string, password string) *User {
	// Look for username and password
	for _, u := range h.users {
		if u.name == username && u.password == password {
			return u
		}
	}

	return nil
}
