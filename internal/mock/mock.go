// package mock contains several structs that are used in various unit tests
package mock

import (
	"net/http/httptest"
)

// ErrorResponseWriter extends httptest.ResponseRecorder with errors that can be returned by
// various functions.
type ErrorResponseRecorder struct {
	*httptest.ResponseRecorder

	// WriteError is an error that can be set to be returned by the Write method.
	WriteError error
}

func (e *ErrorResponseRecorder) Write(b []byte) (int, error) {
	if e.WriteError != nil {
		return 0, e.WriteError
	}

	return e.ResponseRecorder.Write(b)
}
