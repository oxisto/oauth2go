// package login contains an optional "login" (authentication) server that can be used. It offers a simple
// (in the future customizable) login form that sends username / password via POST formdata
// to a /login endpoint. The authentication server then issues a cookie-based session.
//
// This package can be used to turn oauth2go in a more-or-less complete authentication service.
// If this package is not used, an external authentication page that establishes a web-session with the
// user is needed.
package login

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	oauth2 "github.com/oxisto/oauth2go"
)

func Test_handler_doLoginGet(t *testing.T) {
	type fields struct {
		sessions map[string]*session
		users    []*User
		log      oauth2.Logger
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantCode int
		wantBody string
	}{
		{
			name: "No cookie",
			fields: fields{
				sessions: map[string]*session{},
			},
			args: args{
				r: &http.Request{
					URL: &url.URL{Host: "localhost:8080"},
				},
			},
			wantCode: http.StatusOK,
			wantBody: "form",
		},
		{
			name: "Not existing session",
			fields: fields{
				sessions: map[string]*session{},
			},
			args: args{
				r: &http.Request{
					Header: http.Header{
						"Cookie": []string{"id=mySession"},
					},
					URL: &url.URL{Host: "localhost:8080"},
				},
			},
			wantCode: http.StatusOK,
			wantBody: "form",
		},
		{
			name: "Existing but expired session",
			fields: fields{
				sessions: map[string]*session{
					"mySession": {
						ID: "mySession",
						User: &User{
							name: "MyUser",
						},
						ExpireAt: time.Time{},
					},
				},
			},
			args: args{
				r: &http.Request{
					Header: http.Header{
						"Cookie": []string{"id=mySession"},
					},
					URL: &url.URL{Host: "localhost:8080"},
				},
			},
			wantCode: http.StatusOK,
			wantBody: "form",
		},
		{
			name: "Existing not expired session",
			fields: fields{
				sessions: map[string]*session{
					"mySession": {
						ID: "mySession",
						User: &User{
							name: "MyUser",
						},
						ExpireAt: time.Now().Add(time.Minute * 10),
					},
				},
			},
			args: args{
				r: &http.Request{
					Header: http.Header{
						"Cookie": []string{"id=mySession"},
					},
					URL: &url.URL{Host: "localhost:8080"},
				},
			},
			wantCode: http.StatusSeeOther,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &handler{
				sessions: tt.fields.sessions,
				users:    tt.fields.users,
				log:      tt.fields.log,
			}

			rr := httptest.NewRecorder()
			h.doLoginGet(rr, tt.args.r)

			gotCode := rr.Code
			if gotCode != tt.wantCode {
				t.Errorf("handler.doLoginGet() = %v, want %v", gotCode, tt.wantCode)
			}

			gotBody := rr.Body.String()
			if tt.wantBody != "" && strings.Contains(gotBody, tt.wantBody) {
				if gotCode != tt.wantCode {
					t.Errorf("handler.doLoginGet() = %v, want %v", gotBody, tt.wantBody)
				}
			}
		})
	}
}
