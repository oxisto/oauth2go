package oauth2

import (
	"net/http"
)

// ServerMetadata is a struct that contains metadata according to RFC 8414.
//
// See https://datatracker.ietf.org/doc/rfc8414/.
type ServerMetadata struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	JWKSURI                string   `json:"jwks_uri"`
	SupportedScopes        []string `json:"scopes_supported"`
	SupportedResponseTypes []string `json:"response_types_supported"`
	SupportedGrantTypes    []string `json:"grant_types_supported"`
}

// buildMetadata builds a [ServerMetadata] based on the capabilities of this
// server and the public URL.
func buildMetadata(url string) *ServerMetadata {
	return &ServerMetadata{
		Issuer:                 url,
		AuthorizationEndpoint:  url + "/authorize",
		TokenEndpoint:          url + "/token",
		JWKSURI:                url + "/certs",
		SupportedScopes:        []string{"profile"},
		SupportedResponseTypes: []string{"code"},
		SupportedGrantTypes:    []string{"authorization_code", "client_credentials", "refresh_token"},
	}
}

func (srv *AuthorizationServer) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, srv.metadata)
}
