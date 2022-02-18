package oauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestAuthorizationServer_handleToken(t *testing.T) {
	type fields struct {
		Server     http.Server
		clients    []*Client
		signingKey *ecdsa.PrivateKey
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantBody string
	}{
		{
			name: "wrong method",
			args: args{
				r: &http.Request{
					Method: "GET",
				},
			},
		},
		{
			name: "unsupported grant",
			args: args{
				r: &http.Request{
					Method: "POST",
				},
			},
			wantBody: `{"error": "unsupported_grant_type"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()

			srv := &AuthorizationServer{
				Server:     tt.fields.Server,
				clients:    tt.fields.clients,
				signingKey: tt.fields.signingKey,
			}
			srv.handleToken(rr, tt.args.r)

			gotBody := strings.Trim(rr.Body.String(), "\n")
			if gotBody != tt.wantBody {
				t.Errorf("AuthorizationServer.handleToken() body = %v, wantBody %v", gotBody, tt.wantBody)
			}
		})
	}
}

func TestAuthorizationServer_retrieveClient(t *testing.T) {
	type fields struct {
		Server     http.Server
		clients    []*Client
		signingKey *ecdsa.PrivateKey
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Client
		wantErr bool
	}{
		{
			name: "Missing authorization",
			args: args{
				r: &http.Request{},
			},
			wantErr: true,
		},
		{
			name: "No base64 basic authorization",
			args: args{
				r: &http.Request{
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"Basic nothing"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Wrong basic authorization",
			args: args{
				r: &http.Request{
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"Basic bm90aGluZw=="},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid client credentials",
			args: args{
				r: &http.Request{
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"Basic Y2xpZW50Om5vdHNlY3JldA=="},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Valid client credentials",
			fields: fields{
				clients: []*Client{
					{
						clientID:     "client",
						clientSecret: "secret",
					},
				},
			},
			args: args{
				r: &http.Request{
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"Basic Y2xpZW50OnNlY3JldA=="},
					},
				},
			},
			want: &Client{
				clientID:     "client",
				clientSecret: "secret",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &AuthorizationServer{
				Server:     tt.fields.Server,
				clients:    tt.fields.clients,
				signingKey: tt.fields.signingKey,
			}
			got, err := srv.retrieveClient(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthorizationServer.retrieveClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AuthorizationServer.retrieveClient() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthorizationServer_handleJWKS(t *testing.T) {
	type fields struct {
		Server     http.Server
		clients    []*Client
		signingKey *ecdsa.PrivateKey
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		want     *JSONWebKeySet
		wantCode int
	}{
		{
			name: "retrieve JWKS with GET",
			fields: fields{
				signingKey: &ecdsa.PrivateKey{
					PublicKey: ecdsa.PublicKey{
						Curve: elliptic.P256(),
						X:     big.NewInt(1),
						Y:     big.NewInt(2),
					},
				},
			},
			args: args{
				r: httptest.NewRequest("GET", "/.well-known/jwks.json", nil),
			},
			want: &JSONWebKeySet{
				Keys: []JSONWebKey{{
					Kid: "1",
					Kty: "EC",
					X:   "AQ",
					Y:   "Ag",
				}},
			},
			wantCode: 200,
		},
		{
			name:   "retrieve JWKS with POST",
			fields: fields{},
			args: args{
				r: httptest.NewRequest("POST", "/.well-known/jwks.json", nil),
			},
			want:     nil,
			wantCode: 405,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &AuthorizationServer{
				Server:     tt.fields.Server,
				clients:    tt.fields.clients,
				signingKey: tt.fields.signingKey,
			}

			rr := httptest.NewRecorder()
			srv.handleJWKS(rr, tt.args.r)

			gotCode := rr.Code
			if gotCode != tt.wantCode {
				t.Errorf("handler.doLoginPost() code = %v, wantCode %v", gotCode, tt.wantCode)
			}

			if rr.Code == 200 {
				var got JSONWebKeySet
				err := json.Unmarshal(rr.Body.Bytes(), &got)
				if err != nil {
					panic(err)
				}

				if !reflect.DeepEqual(&got, tt.want) {
					t.Errorf("AuthorizationServer.handleJWKS() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func Test_writeJSON(t *testing.T) {
	type args struct {
		w     http.ResponseWriter
		value interface{}
	}
	tests := []struct {
		name string
		args args
		want func(t *testing.T, w http.ResponseWriter)
	}{
		{
			name: "stream error",
			args: args{
				w: &errorResponseWriter{},
			},
			want: func(t *testing.T, w http.ResponseWriter) {
				wantCode := 500
				gotCode := w.(*errorResponseWriter).Result().StatusCode
				if gotCode != wantCode {
					t.Errorf("handler.doLoginPost() code = %v, wantCode %v", gotCode, wantCode)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeJSON(tt.args.w, tt.args.value)

			tt.want(t, tt.args.w)
		})
	}
}

type errorResponseWriter struct {
	http.Response
}

func (errorResponseWriter) Header() http.Header {
	return http.Header{}
}

func (errorResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("some error")
}

func (m *errorResponseWriter) WriteHeader(statusCode int) {
	m.StatusCode = statusCode
}

func (m *errorResponseWriter) Result() *http.Response {
	return &m.Response
}
