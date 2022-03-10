package login

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oxisto/oauth2go/internal/mock"
)

func Test_loginForm_ServeHTTP(t *testing.T) {
	type fields struct {
		returnURL    string
		loginURL     string
		errorMessage string
		fs           fs.FS
	}
	type args struct {
		w http.ResponseWriter
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
			name: "invalid fs",
			args: args{
				w: httptest.NewRecorder(),
			},
			fields: fields{
				fs: &mockFS{OpenError: errors.New("some error")},
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
				fs: &mockFS{File: &mockFile{content: "{{"}}, // unclosed action
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
				fs:       &mockFS{File: &mockFile{content: "{{.LoginURL}}"}},
				loginURL: "/test",
			},
			wantCode: http.StatusOK,
			wantBody: "/test",
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
				fs: &mockFS{File: &mockFile{content: "test"}},
			},
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := loginForm{
				returnURL:    tt.fields.returnURL,
				loginURL:     tt.fields.loginURL,
				errorMessage: tt.fields.errorMessage,
				fs:           tt.fields.fs,
			}

			form.ServeHTTP(tt.args.w, tt.args.r)

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
