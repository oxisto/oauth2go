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
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	oauth2 "github.com/oxisto/oauth2go"
)

//go:embed login.html
var embedFS embed.FS

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

	// the base url of our authentication server
	baseURL string

	pwh PasswordHasher

	files fs.FS
}

// User represents a user in our authentication server. It has a unique name
// and potentially other meta-data.
type User struct {
	// The unique name of this user
	Name string

	// The (hashed) user password.
	PasswordHash string
}

func NewHandler() *handler {
	h := &handler{
		sessions: map[string]*session{},
		users:    []*User{},
		baseURL:  "/",
		pwh:      bcryptHasher{},
	}

	h.files = embedFS

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

// doLoginGet handles the /login endpoint if called with the GET method. It returns
// an HTML-based login form, if no session exists, a session is invalid or a previous
// failure was indicated.
//
// If successful, it redirects to the base url.
func (h *handler) doLoginGet(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		ok        bool
		returnURL string
		cookie    *http.Cookie
		session   *session
	)

	// Retrive an optional return URL. Will default to the handler's base URL
	returnURL = h.parseReturnURL(r)

	// Before any other checks, check if we have an indication that we were redirected
	// here because of a failure
	if r.URL.Query().Has("failed") {
		// We display the login page with an error message
		h.handleLoginPage(w, r, "Invalid credentials", returnURL)
		return
	}

	// Check, if we have have a cookie
	cookie, err = r.Cookie("id")
	if err != nil {
		// Regardless of the error, we display the login page
		h.handleLoginPage(w, r, "", returnURL)
		return
	}

	// Check, if the cookie points to a valid (not expired) session
	h.sm.RLock()
	session, ok = h.sessions[cookie.Value]
	h.sm.RUnlock()

	if !ok {
		// No session, so we display the login page
		h.handleLoginPage(w, r, "", returnURL)
		return
	}

	if session.Expired() {
		// Session is expired, so we remove it from our list and also display the login page
		h.removeSession(session.ID)
		h.handleLoginPage(w, r, "", returnURL)
		return
	}

	// Seems like we have a valid session. Woohoo. Nothing to do except redirecting
	http.Redirect(w, r, returnURL, http.StatusFound)
}

func (h *handler) handleLoginPage(w http.ResponseWriter, r *http.Request, error string, returnURL string) {
	var tmpl, err = template.ParseFS(h.files, "login.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, map[string]interface{}{
		"ErrorMessage": error,
		"ReturnURL":    returnURL,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *handler) doLoginPost(w http.ResponseWriter, r *http.Request) {
	var (
		returnURL string
		user      *User
	)

	// Parse the return URL
	returnURL = h.parseReturnURL(r)

	// Retrieve the user. Returns nil, if no user has been found with these credentials
	user = h.user(r.FormValue("username"), r.FormValue("password"))
	if user == nil {
		url := path.Join(h.baseURL, "/login?failed")

		// Redirect back to login page (but with an error message).
		// We are using http.StatusSeeOther because we are changing the method from POST to GET
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	// Start a new session
	session := h.newSession(user)

	c := http.Cookie{
		Name:     "id",
		Value:    session.ID,
		Path:     h.baseURL,
		Expires:  session.ExpireAt,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	}

	http.SetCookie(w, &c)

	h.log.Printf("Generating new session with id %s", session.ID)

	// Everything good, lets redirect to the return URL.
	http.Redirect(w, r, returnURL, http.StatusFound)
}

func (h *handler) user(username string, password string) *User {
	defer func() {
		password = ""
	}()

	// Look for username and password
	for _, u := range h.users {
		if u.Name == username && h.pwh.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil {
			return u
		}
	}

	return nil
}

func GeneratePassword() string {
	b := make([]byte, 32)

	rand.Read(b)

	return base64.StdEncoding.EncodeToString(b)
}

// parseReturnURL checks for the existence of a return URL in the HTTP request.
// It will return the handlers base URL, if the return URL is either missing or invalid.
// For security reasons, only relative URLs are allowed.
func (h *handler) parseReturnURL(r *http.Request) (returnURL string) {
	var (
		err error
		u   *url.URL
	)

	returnURL = r.FormValue("return_url")
	if u, err = url.Parse(returnURL); err != nil {
		// Revert back to the base URL
		returnURL = h.baseURL
		return
	}

	if u.IsAbs() {
		// Revert back to the base URL
		returnURL = h.baseURL
		return
	}

	return
}
