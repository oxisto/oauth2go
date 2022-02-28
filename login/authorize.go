package login

import (
	"fmt"
	"net/http"
	"net/url"

	oauth2 "github.com/oxisto/oauth2go"
)

// handleAuthorize implements the authorize endpoint (see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1).
func (h *handler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var (
		client      *oauth2.Client
		redirectURI string
		state       string
		challenge   string
		method      string
		err         error
		query       url.Values
		session     *session
	)

	query = r.URL.Query()

	client, err = h.srv.GetClient(query.Get("client_id"))
	if err != nil {
		http.Error(w, "Invalid client ID", http.StatusBadRequest)
		return
	}

	redirectURI = query.Get("redirect_uri")
	if redirectURI == "" || client.RedirectURI != redirectURI {
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	if query.Get("response_type") != "code" {
		oauth2.RedirectError(w, r, redirectURI, "invalid_request", "")
		return
	}

	challenge = query.Get("code_challenge")
	if challenge == "" {
		oauth2.RedirectError(w, r, redirectURI, "invalid_request", "Code challenge is required")
		return
	}

	method = query.Get("code_challenge_method")
	if method != "S256" {
		oauth2.RedirectError(w, r, redirectURI, "invalid_request", "Only transform algorithm S265 is supported")
		return
	}

	state = query.Get("state")

	// Check, if we already have a session
	session = h.extractSession(w, r)

	if session.Anonymous() {
		var params = url.Values{}
		params.Add("return_url", r.RequestURI)

		// Redirect to our login page
		http.Redirect(w, r, fmt.Sprintf("/login?%s", params.Encode()), http.StatusFound)
	} else {
		var params = url.Values{}
		params.Add("code", h.srv.IssueCode(challenge))
		params.Add("state", state)

		http.Redirect(w, r, fmt.Sprintf("%s?%s", redirectURI, params.Encode()), http.StatusFound)
	}
}
