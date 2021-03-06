package login

import (
	"net/http"

	oauth2 "github.com/oxisto/oauth2go"
)

func WithLoginPage(opts ...handlerOption) oauth2.AuthorizationServerOption {
	h := NewHandler()

	for _, o := range opts {
		o(h)
	}

	return func(srv *oauth2.AuthorizationServer) {
		h.srv = srv

		mux := srv.Handler.(*http.ServeMux)
		mux.Handle("/login", h)
		mux.HandleFunc("/authorize", h.handleAuthorize)
	}
}

func WithPassswordHasher(pwh PasswordHasher) handlerOption {
	return func(h *handler) {
		h.pwh = pwh
	}
}

func WithBaseURL(url string) handlerOption {
	return func(h *handler) {
		h.baseURL = url
	}
}

func WithUser(name string, password string) handlerOption {
	return func(srv *handler) {
		hash, err := srv.pwh.GenerateFromPassword([]byte(password))
		if err != nil {
			srv.log.Printf("Could not generate hash from password: %w. Not adding user", err)
			return
		}

		srv.users = append(srv.users, &User{
			Name:         name,
			PasswordHash: string(hash),
		})

		password = ""
	}
}

type handlerOption func(*handler)
