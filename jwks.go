package oauth2

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

// JSONWebKeySet is a JSON Web Key Set.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey is a JSON Web Key that only supports elliptic curve keys for now.
type JSONWebKey struct {
	Kid string `json:"kid"`

	Kty string `json:"kty"`

	Crv string `json:"crv"`

	X string `json:"x"`

	Y string `json:"y"`
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
				Crv: key.Params().Name,
				Kty: "EC",
				X:   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
				Y:   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
			})
	}

	srv.writeJSON(w, keySet)
}
