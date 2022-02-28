package login

import (
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	oauth2 "github.com/oxisto/oauth2go"
)

func Test_handler_handleAuthorize(t *testing.T) {
	type fields struct {
		sessions map[string]*session
		users    []*User
		log      oauth2.Logger
		baseURL  string
		pwh      PasswordHasher
		files    fs.FS
		srv      *oauth2.AuthorizationServer
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name             string
		fields           fields
		args             args
		wantCode         int
		wantHeaderRegexp http.Header
	}{
		{
			name: "invalid client",
			fields: fields{
				sessions: map[string]*session{},
				users:    []*User{},
				log:      log.Default(),
				pwh:      bcryptHasher{},
				srv:      oauth2.NewServer(":0", oauth2.WithClient("client", "secret")),
			},
			args: args{
				r: &http.Request{
					URL: &url.URL{Path: "/authorize"},
				},
			},
			wantCode: http.StatusBadRequest,
			wantHeaderRegexp: http.Header{
				"Content-Type": []string{"text/plain; charset=utf-8"},
			},
		},
		{
			name: "invalid redirect URI",
			fields: fields{
				sessions: map[string]*session{},
				users:    []*User{},
				log:      log.Default(),
				pwh:      bcryptHasher{},
				srv:      oauth2.NewServer(":0", oauth2.WithClient("client", "secret")),
			},
			args: args{
				r: &http.Request{
					URL: &url.URL{
						Path:     "/authorize",
						RawQuery: "client_id=client",
					},
				},
			},
			wantCode: http.StatusBadRequest,
			wantHeaderRegexp: http.Header{
				"Content-Type": []string{"text/plain; charset=utf-8"},
			},
		},
		{
			name: "invalid response type",
			fields: fields{
				sessions: map[string]*session{},
				users:    []*User{},
				log:      log.Default(),
				pwh:      bcryptHasher{},
				srv:      oauth2.NewServer(":0", oauth2.WithClient("client", "secret")),
			},
			args: args{
				r: &http.Request{
					URL: &url.URL{
						Path:     "/authorize",
						RawQuery: "client_id=client&redirect_uri=/test",
					},
				},
			},
			wantCode: http.StatusFound,
			wantHeaderRegexp: http.Header{
				"Location": []string{"/test\\?error=invalid_request"},
			},
		},
		{
			name: "valid request, no session",
			fields: fields{
				sessions: map[string]*session{},
				users:    []*User{},
				log:      log.Default(),
				pwh:      bcryptHasher{},
				srv:      oauth2.NewServer(":0", oauth2.WithClient("client", "secret")),
			},
			args: args{
				r: httptest.NewRequest("GET", "/authorize?client_id=client&redirect_uri=/test&response_type=code", nil),
			},
			wantCode: http.StatusFound,
			wantHeaderRegexp: http.Header{
				// Should redirect to login page but with this authorize endpoint as return URL
				"Location": []string{"/login\\?return_url=%2Fauthorize%3Fclient_id%3Dclient%26redirect_uri%3D%2Ftest%26response_type%3Dcode"},
			},
		},
		{
			name: "valid request, existing session",
			fields: fields{
				sessions: map[string]*session{
					"mysession": {
						ID:       "mysession",
						User:     &User{Name: "admin"},
						ExpireAt: time.Now().Add(1 * time.Hour),
					},
				},
				users: []*User{},
				log:   log.Default(),
				pwh:   bcryptHasher{},
				srv: func() *oauth2.AuthorizationServer {
					srv := oauth2.NewServer(":0", oauth2.WithClient("client", "secret"))
					return srv
				}(),
			},
			args: args{
				r: func() *http.Request {
					r := httptest.NewRequest("GET", "/authorize?client_id=client&redirect_uri=/test&response_type=code", nil)
					r.AddCookie(&http.Cookie{
						Name:  "id",
						Value: "mysession",
					})

					return r
				}(),
			},
			wantCode: http.StatusFound,
			wantHeaderRegexp: http.Header{
				// Should redirect to redirect URI with the code in query param
				"Location": []string{"/test\\?code=(.*)&state="},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &handler{
				sessions: tt.fields.sessions,
				users:    tt.fields.users,
				log:      tt.fields.log,
				baseURL:  tt.fields.baseURL,
				pwh:      tt.fields.pwh,
				files:    tt.fields.files,
				srv:      tt.fields.srv,
			}

			rr := httptest.NewRecorder()
			h.handleAuthorize(rr, tt.args.r)

			gotCode := rr.Code
			if gotCode != tt.wantCode {
				t.Errorf("handle.handleAuthorize() code = %v, wantCode %v", gotCode, tt.wantCode)
			}

			gotHeader := rr.Header()
			var ok = true
			for wantKey := range tt.wantHeaderRegexp {
				wantValue := tt.wantHeaderRegexp.Get(wantKey)
				gotValue := gotHeader.Get(wantKey)
				match, _ := regexp.MatchString(wantValue, gotValue)
				if !match {
					ok = false
					break
				}
			}

			if !ok {
				t.Errorf("handle.handleAuthorize() header = %v, wantHeader %v", gotHeader, tt.wantHeaderRegexp)
			}
		})
	}
}
