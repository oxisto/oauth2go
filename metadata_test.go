package oauth2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func Test_buildMetadata(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name string
		args args
		want *ServerMetadata
	}{
		{
			name: "Happy path",
			args: args{
				url: "http://localhost:8000",
			},
			want: &ServerMetadata{
				Issuer:                 "http://localhost:8000",
				AuthorizationEndpoint:  "http://localhost:8000/authorize",
				TokenEndpoint:          "http://localhost:8000/token",
				JWKSURI:                "http://localhost:8000/certs",
				SupportedScopes:        []string{"profile"},
				SupportedResponseTypes: []string{"code"},
				SupportedGrantTypes:    []string{"authorization_code", "client_credentials", "refresh_token"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildMetadata(tt.args.url); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("buildMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthorizationServer_handleMetadata(t *testing.T) {
	type fields struct {
		metadata *ServerMetadata
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		want     *ServerMetadata
		wantCode int
	}{
		{
			name:   "wrong method",
			fields: fields{},
			args: args{
				r: httptest.NewRequest("POST", "/.well-known/openid-configuration", nil),
			},
			want:     nil,
			wantCode: http.StatusMethodNotAllowed,
		},
		{
			name: "valid metadata",
			fields: fields{
				metadata: buildMetadata(DefaultAddress),
			},
			args: args{
				r: httptest.NewRequest("GET", "/.well-known/openid-configuration", nil),
			},
			want:     buildMetadata(DefaultAddress),
			wantCode: 200,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &AuthorizationServer{
				metadata: tt.fields.metadata,
			}

			rr := httptest.NewRecorder()
			srv.handleMetadata(rr, tt.args.r)

			gotCode := rr.Code
			if gotCode != tt.wantCode {
				t.Errorf("AuthorizationServer.handleMetadata() code = %v, wantCode %v", gotCode, tt.wantCode)
			}

			if rr.Code == http.StatusOK {
				var got ServerMetadata
				err := json.Unmarshal(rr.Body.Bytes(), &got)
				if err != nil {
					panic(err)
				}

				if !reflect.DeepEqual(&got, tt.want) {
					t.Errorf("AuthorizationServer.handleMetadata() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
