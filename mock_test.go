package oauth2

import "net/http"

type mockResponseWriter struct {
	http.Response

	WriteError error
}

func (mockResponseWriter) Header() http.Header {
	return http.Header{}
}

func (e *mockResponseWriter) Write([]byte) (int, error) {
	return 0, e.WriteError
}

func (e *mockResponseWriter) WriteHeader(statusCode int) {
	e.StatusCode = statusCode
}

func (m *mockResponseWriter) Result() *http.Response {
	return &m.Response
}
