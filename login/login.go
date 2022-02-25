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
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	oauth2 "github.com/oxisto/oauth2go"
	"github.com/oxisto/oauth2go/login/csrf"
)

//go:embed login.html
var embedFS embed.FS

// session describes a currently active login session for a particular user
type session struct {
	ID string

	User *User

	ExpireAt time.Time

	CSRFToken string
}

func (s *session) Expired() bool {
	return s.ExpireAt.Before(time.Now())
}

func (s *session) Anonymous() bool {
	return s.User == nil
}

func (s *session) Cookie(path string) *http.Cookie {
	return &http.Cookie{
		Name:     "id",
		Value:    s.ID,
		Path:     path,
		Expires:  s.ExpireAt,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	}
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

func (h *handler) newSession(w http.ResponseWriter) *session {
	// Generate a new session ID
	var b = make([]byte, 32)
	rand.Read(b)

	id := base64.StdEncoding.EncodeToString(b)

	// Generate a CSRF token
	csrfToken := csrf.GenerateToken()

	// A new session is always anonymous at first
	session := session{
		ID:        id,
		User:      nil,
		ExpireAt:  time.Now().Add(time.Minute * 24),
		CSRFToken: csrfToken,
	}

	h.sm.Lock()
	defer h.sm.Unlock()

	h.sessions[id] = &session

	http.SetCookie(w, session.Cookie(h.baseURL))

	h.log.Printf("Generating new session with id %s", session.ID)

	return &session
}

func (h *handler) updateSession(w http.ResponseWriter, session *session, user *User) {
	h.sm.Lock()
	session.User = user
	h.sm.Unlock()

	http.SetCookie(w, session.Cookie(h.baseURL))

	h.log.Printf("Updating session with id %s to user %s", session.ID, user.Name)
}

// removeSession removes an (expired) session from the session storage
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
		returnURL string
		session   *session
		form      loginForm
	)

	// Retrieve an optional return URL. Will default to the handler's base URL
	returnURL = h.parseReturnURL(r)

	// Extract our session (or potentially start a new one)
	session = h.extractSession(w, r)

	// Prepare the login form
	form = loginForm{returnURL: returnURL, fs: h.files, csrfToken: session.CSRFToken}

	// Check, if we have an additional failure message
	if r.URL.Query().Has("failed") {
		// We display the login page with an error message
		form.errorMessage = "Invalid credentials"
	}

	// At this point, we either have a (new) anonymous session or an existing user session
	if session.Anonymous() {
		// Our session is not logged in, so we display the login page
		form.ServeHTTP(w, r)
	} else {
		// Seems like we have a valid user session. Woohoo. Nothing to do except redirecting
		http.Redirect(w, r, returnURL, http.StatusFound)
	}
}

func (h *handler) doLoginPost(w http.ResponseWriter, r *http.Request) {
	var (
		returnURL string
		csrfToken string
		user      *User
		session   *session
	)

	// Parse the return URL
	returnURL = h.parseReturnURL(r)

	// Retrieve our session.
	session = h.extractSession(w, r)

	// Retrieve our CSRF token
	csrfToken = r.FormValue("csrf_token")

	// We can only continue, if the token matches our stored CSRF token
	//
	// TODO: use masked token
	if csrfToken != session.CSRFToken {
		goto fail
	}

	// Retrieve the user with the supplied login data. Returns nil, if no user has been found with these credentials
	user = h.user(r.FormValue("username"), r.FormValue("password"))
	if user == nil {
		goto fail
	}

	// Associate the user with the session and
	h.updateSession(w, session, user)

	// Everything good, lets redirect to the return URL.
	http.Redirect(w, r, returnURL, http.StatusFound)
	return

fail:
	url := path.Join(h.baseURL, "/login?failed")

	// Redirect back to login page (but with an error message).
	// We are using http.StatusSeeOther because we are changing the method from POST to GET
	http.Redirect(w, r, url, http.StatusSeeOther)
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

// extractSession extracts a session from a HTTP request using a cookie or
// establishes a new (anonymous) session, if no cookie was found or if
// the session was invalid in some other way.
func (h *handler) extractSession(w http.ResponseWriter, r *http.Request) (session *session) {
	var (
		cookie *http.Cookie
		err    error
		ok     bool
	)

	// Check, if we have have a cookie
	cookie, err = r.Cookie("id")
	if err != nil {
		// No cookie was sent, so we start a new anonymous session
		session = h.newSession(w)
	} else {
		// Check, if the cookie points to a valid (not expired) session
		h.sm.RLock()
		session, ok = h.sessions[cookie.Value]
		h.sm.RUnlock()

		if !ok {
			// Start a new anonymous session
			session = h.newSession(w)
		}

		if session.Expired() {
			// Session is expired, so we remove it from our list
			h.removeSession(session.ID)

			// And start a new anonymous session
			session = h.newSession(w)
		}
	}

	// Make sure, to send the cookie with the session ID back to the client
	http.SetCookie(w, session.Cookie(h.baseURL))

	return session
}
