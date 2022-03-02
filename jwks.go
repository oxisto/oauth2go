package oauth2

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
