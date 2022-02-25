package csrf

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
)

var TokenSize = 18
var EncodedTokenSize = 24
var DoubleEncodedTokenSize = 32

var ErrInvalidLength = errors.New("invalid length")

// GenerateToken generates a new random token that can be used as a CSRF token. Ideally,
// a unique token for each session should be generated. On can use the masking technique
// to generate a unique token for each request, that can still be verified against a
// session-unique token.
func GenerateToken() string {
	var b []byte = make([]byte, TokenSize)

	rand.Read(b)

	return base64.StdEncoding.EncodeToString(b)
}

// Mask can be used to mask a session-wide token into a unique CSRF token for each request.
func Mask(sessionToken string) string {
	toMask := GenerateToken()

	return base64.StdEncoding.EncodeToString(xor([]byte(sessionToken), []byte(toMask))) + string(toMask)
}

func Unmask(token string) (string, error) {
	if len(token) != DoubleEncodedTokenSize+EncodedTokenSize {
		return "", ErrInvalidLength
	}

	mask := token[DoubleEncodedTokenSize:]

	masked, err := base64.StdEncoding.DecodeString(token[:DoubleEncodedTokenSize])
	if err != nil {
		return "", fmt.Errorf("could not decode: %w", err)
	}

	return string(xor([]byte(mask), masked)), nil
}

func xor(x []byte, y []byte) (result []byte) {
	var n = len(x)

	if len(y) < n {
		n = len(y)
	}

	result = make([]byte, n)

	for i := 0; i < n; i++ {
		result[i] = x[i] ^ y[i]
	}

	return
}
