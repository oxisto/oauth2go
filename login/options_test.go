package login

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	oauth2 "github.com/oxisto/oauth2go"
)

func TestWithLoginPage(t *testing.T) {
	type args struct {
		opts []handlerOption
	}
	tests := []struct {
		name string
		args args
		want *handler
	}{
		{
			name: "could not generate password",
			args: args{
				opts: []handlerOption{
					WithPassswordHasher(&mockPasswordHasher{GenerateFromPasswordError: errors.New("some error")}),
					WithUser("admin", "admin"),
				},
			},
			want: &handler{
				sessions: make(map[string]*session),
				users:    []*User{},
				baseURL:  "/",
				log:      log.Default(),
				pwh:      &mockPasswordHasher{GenerateFromPasswordError: errors.New("some error")},
				files:    embedFS,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := oauth2.NewServer(":0", WithLoginPage(tt.args.opts...))
			h, _ := srv.Handler.(*http.ServeMux).Handler(&http.Request{URL: &url.URL{Path: "/login"}})
			got := h.(*handler)
			got.srv = nil

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithLoginPage() handler = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockPasswordHasher struct {
	GenerateFromPasswordError error
}

func (mockPasswordHasher) CompareHashAndPassword(hash []byte, password []byte) error {
	return nil
}

func (m *mockPasswordHasher) GenerateFromPassword(password []byte, opts ...interface{}) ([]byte, error) {
	return nil, m.GenerateFromPasswordError
}
