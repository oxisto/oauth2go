// package login contains an optional "login" (authentication) server that can be used. It offers a simple
// (in the future customizable) login form that sends username / password via POST formdata
// to a /login endpoint. The authentication server then issues a cookie-based session.
//
// This package can be used to turn oauth2go in a more-or-less complete authentication service.
// If this package is not used, an external authentication page that establishes a web-session with the
// user is needed.
package login

import (
	"errors"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	oauth2 "github.com/oxisto/oauth2go"
	"github.com/oxisto/oauth2go/internal/mock"
	"golang.org/x/crypto/bcrypt"
)

func Test_handler_doLoginGet(t *testing.T) {
	type fields struct {
		sessions map[string]*session
		users    []*User
		log      oauth2.Logger
		files    fs.FS
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
			name: "Login failed",
			fields: fields{
				sessions: map[string]*session{},
				files:    embedFS,
			},
			args: args{
				r: &http.Request{
					URL: &url.URL{Host: "localhost:8080", Path: "/login", RawQuery: "failed"},
				},
			},
			wantCode: http.StatusOK,
			wantBody: "Invalid",
		},
		{
			name: "No cookie",
			fields: fields{
				sessions: map[string]*session{},
				files:    embedFS,
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
				files:    embedFS,
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
							Name: "MyUser",
						},
						ExpireAt: time.Time{},
					},
				},
				files: embedFS,
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
							Name: "MyUser",
						},
						ExpireAt: time.Now().Add(time.Minute * 10),
					},
				},
				files: embedFS,
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
				baseURL:  "/",
				files:    tt.fields.files,
			}

			rr := httptest.NewRecorder()
			h.doLoginGet(rr, tt.args.r)

			gotCode := rr.Code
			if gotCode != tt.wantCode {
				t.Errorf("handler.doLoginGet() code = %v, wantCode %v", gotCode, tt.wantCode)
			}

			gotBody := rr.Body.String()
			if tt.wantBody != "" && !strings.Contains(gotBody, tt.wantBody) {
				t.Errorf("handler.doLoginGet() body = %v, wantBody %v", gotBody, tt.wantBody)
			}
		})
	}
}

func Test_handler_doLoginPost(t *testing.T) {
	var hash, _ = bcryptHasher{}.GenerateFromPassword("admin", bcrypt.DefaultCost)

	type fields struct {
		sessions map[string]*session
		users    []*User
		log      oauth2.Logger
		pwh      PasswordHasher
		files    fs.FS
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantCode   int
		wantHeader http.Header
		wantCookie bool
	}{
		{
			name: "Existing user",
			fields: fields{
				sessions: make(map[string]*session),
				users: []*User{
					{Name: "admin", PasswordHash: string(hash)},
				},
				log: log.Default(),
				pwh: bcryptHasher{},
			},
			args: args{
				r: &http.Request{
					Method: "POST",
					URL:    &url.URL{Host: "localhost", Path: "/login"},
					PostForm: url.Values{
						"username": []string{"admin"},
						"password": []string{"admin"},
					},
				},
			},
			wantCode: http.StatusSeeOther,
			wantHeader: http.Header{
				http.CanonicalHeaderKey("Location"): []string{"/"},
			},
			wantCookie: true,
		},
		{
			name: "Invalid credentials",
			fields: fields{
				sessions: make(map[string]*session),
				users: []*User{
					{Name: "admin", PasswordHash: string(hash)},
				},
				log: log.Default(),
				pwh: bcryptHasher{},
			},
			args: args{
				r: &http.Request{
					Method: "POST",
					URL:    &url.URL{Host: "localhost", Path: "/login"},
					PostForm: url.Values{
						"username": []string{"notadmin"},
						"password": []string{"admin"},
					},
				},
			},
			wantCode: http.StatusSeeOther,
			wantHeader: http.Header{
				http.CanonicalHeaderKey("Location"): []string{"/login?failed"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &handler{
				sessions: tt.fields.sessions,
				users:    tt.fields.users,
				log:      tt.fields.log,
				pwh:      tt.fields.pwh,
				files:    tt.fields.files,
				baseURL:  "/",
			}

			rr := httptest.NewRecorder()
			h.doLoginPost(rr, tt.args.r)

			gotCode := rr.Code
			if gotCode != tt.wantCode {
				t.Errorf("handler.doLoginPost() code = %v, wantCode %v", gotCode, tt.wantCode)
			}

			gotHeader := rr.Header()
			_, ok := gotHeader["Set-Cookie"]

			if tt.wantCookie != ok {
				t.Errorf("handler.doLoginPost() ok = %v, wantCookie %v", ok, tt.wantCookie)
			}

			// We cannot compare the cookie, because it contains a random ID so we nil it out
			// and checked for its existence before
			delete(gotHeader, "Set-Cookie")

			if tt.wantHeader != nil && !reflect.DeepEqual(gotHeader, tt.wantHeader) {
				t.Errorf("handler.doLoginPost() header = %v, wantHeader %v", gotHeader, tt.wantHeader)
			}
		})
	}
}

func Test_handler_ServeHTTP(t *testing.T) {
	type fields struct {
		sessions map[string]*session
		users    []*User
		log      oauth2.Logger
		baseURL  string
		pwh      PasswordHasher
		files    fs.FS
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantCode int
	}{
		{
			name: "GET request",
			fields: fields{
				files: embedFS,
			},
			args: args{
				r: &http.Request{
					Method: "GET",
					URL:    &url.URL{Path: "/login"},
				},
			},
			wantCode: 200,
		},
		{
			name: "POST request",
			fields: fields{
				files: embedFS,
			},
			args: args{
				r: &http.Request{
					Method: "POST",
					URL:    &url.URL{Path: "/login"},
				},
			},
			wantCode: 500, // because this request is highly invalid
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
			}

			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, tt.args.r)

			gotCode := rr.Code
			if tt.wantCode != gotCode {
				t.Errorf("handler.doLoginPost() header = %v, wantHeader %v", gotCode, tt.wantCode)
			}
		})
	}
}

func Test_handler_handleLoginPage(t *testing.T) {
	type fields struct {
		sessions map[string]*session
		users    []*User
		log      oauth2.Logger
		baseURL  string
		pwh      PasswordHasher
		files    fs.FS
	}
	type args struct {
		w     http.ResponseWriter
		r     *http.Request
		error string
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantCode int
		wantBody string
	}{
		{
			name: "invalid fs",
			args: args{
				w: httptest.NewRecorder(),
			},
			fields: fields{
				files: &mockFS{OpenError: errors.New("some error")},
			},
			wantCode: http.StatusInternalServerError,
			wantBody: "template: pattern matches no files: `login.html`",
		},
		{
			name: "invalid template",
			args: args{
				w: httptest.NewRecorder(),
			},
			fields: fields{
				files: &mockFS{File: &mockFile{content: "{{"}}, // unclosed action
			},
			wantCode: http.StatusInternalServerError,
			wantBody: "template: login.html:1: unclosed action",
		},
		{
			name: "valid template without errors",
			args: args{
				w: &mock.MockResponseRecorder{
					ResponseRecorder: httptest.NewRecorder(),
				},
			},
			fields: fields{
				files: &mockFS{File: &mockFile{content: "test"}},
			},
			wantCode: http.StatusOK,
			wantBody: "test",
		},
		{
			name: "valid template with error while writing",
			args: args{
				w: &mock.MockResponseRecorder{
					ResponseRecorder: httptest.NewRecorder(),
					WriteError:       errors.New("some error"),
				},
			},
			fields: fields{
				files: &mockFS{File: &mockFile{content: "test"}},
			},
			wantCode: http.StatusInternalServerError,
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
			}

			h.handleLoginPage(tt.args.w, tt.args.r, tt.args.error)

			var rr *httptest.ResponseRecorder
			switch v := tt.args.w.(type) {
			case *httptest.ResponseRecorder:
				rr = v
			case *mock.MockResponseRecorder:
				rr = v.ResponseRecorder
			}

			gotCode := rr.Code
			if tt.wantCode != gotCode {
				t.Errorf("handler.handleLoginPage() header = %v, wantHeader %v", gotCode, tt.wantCode)
			}

			gotBody := rr.Body.String()
			if tt.wantBody != "" && !strings.Contains(gotBody, tt.wantBody) {
				t.Errorf("handler.handleLoginPage() body = %v, wantBody %v", gotBody, tt.wantBody)
			}
		})
	}
}
