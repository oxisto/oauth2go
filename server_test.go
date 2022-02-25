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

	"github.com/oxisto/oauth2go/internal/mock"
)

func TestAuthorizationServer_handleToken(t *testing.T) {
	type fields struct {
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
			name: "missing authorization",
			args: args{
				r: &http.Request{},
			},
			wantErr: true,
		},
		{
			name: "no base64 basic authorization",
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
			name: "wrong basic authorization",
			args: args{
				r: &http.Request{
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"Basic bm90aGluZw=="}, // nothing
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid client credentials",
			args: args{
				r: &http.Request{
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"Basic Y2xpZW50Om5vdHNlY3JldA=="}, // client:notsecret
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid client credentials",
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
						http.CanonicalHeaderKey("Authorization"): []string{"Basic Y2xpZW50OnNlY3JldA=="}, // client:secret
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
			wantCode: http.StatusOK,
		},
		{
			name:   "retrieve JWKS with POST",
			fields: fields{},
			args: args{
				r: httptest.NewRequest("POST", "/.well-known/jwks.json", nil),
			},
			want:     nil,
			wantCode: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &AuthorizationServer{
				clients:    tt.fields.clients,
				signingKey: tt.fields.signingKey,
			}

			rr := httptest.NewRecorder()
			srv.handleJWKS(rr, tt.args.r)

			gotCode := rr.Code
			if gotCode != tt.wantCode {
				t.Errorf("AuthorizationServer.doLoginPost() code = %v, wantCode %v", gotCode, tt.wantCode)
			}

			if rr.Code == http.StatusOK {
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
		name     string
		args     args
		wantCode int
	}{
		{
			name: "stream error",
			args: args{
				w: &mock.MockResponseRecorder{
					ResponseRecorder: httptest.NewRecorder(),
					WriteError:       errors.New("some error"),
				},
			},
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeJSON(tt.args.w, tt.args.value)

			var rr *httptest.ResponseRecorder
			switch v := tt.args.w.(type) {
			case *httptest.ResponseRecorder:
				rr = v
			case *mock.MockResponseRecorder:
				rr = v.ResponseRecorder
			}

			gotCode := rr.Code
			if gotCode != tt.wantCode {
				t.Errorf("AuthorizationServer.writeJSON() code = %v, wantCode %v", gotCode, tt.wantCode)
			}
		})
	}
}

func TestAuthorizationServer_doClientCredentialsFlow(t *testing.T) {
	type fields struct {
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
		wantCode int
		wantBody string
	}{
		{
			name: "missing or invalid authorization",
			args: args{
				r: &http.Request{
					Method: "POST",
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"notvalid"},
					},
				},
			},
			wantCode: http.StatusUnauthorized,
			wantBody: `{"error": "invalid_client"}`,
		},
		{
			name: "correct authorization but invalid signing key",
			fields: fields{
				clients: []*Client{
					{
						clientID:     "client",
						clientSecret: "secret",
					},
				},
				signingKey: &ecdsa.PrivateKey{
					D: big.NewInt(1),
					PublicKey: ecdsa.PublicKey{
						X: big.NewInt(1),
						Y: big.NewInt(1),
						Curve: func() elliptic.Curve {
							var c = elliptic.CurveParams{
								N:  elliptic.P224().Params().N,
								P:  elliptic.P224().Params().P,
								B:  elliptic.P224().Params().B,
								Gx: elliptic.P224().Params().Gx,
								Gy: elliptic.P224().Params().Gy,
							}
							// Adjust bit size to make it a corrupt key
							c.BitSize = 100
							return &c
						}(),
					},
				},
			},
			args: args{
				r: &http.Request{
					Method: "POST",
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"Basic Y2xpZW50OnNlY3JldA=="}, // client:secret
					},
				},
			},
			wantCode: 500,
			wantBody: "error while creating JWT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &AuthorizationServer{
				clients:    tt.fields.clients,
				signingKey: tt.fields.signingKey,
			}

			rr := httptest.NewRecorder()
			srv.doClientCredentialsFlow(rr, tt.args.r)

			gotCode := rr.Code
			if gotCode != tt.wantCode {
				t.Errorf("AuthorizationServer.doClientCredentialsFlow() code = %v, wantCode %v", gotCode, tt.wantCode)
			}

			gotBody := strings.Trim(rr.Body.String(), "\n")
			if gotBody != tt.wantBody {
				t.Errorf("AuthorizationServer.doClientCredentialsFlow() body = %v, wantBody %v", gotBody, tt.wantBody)
			}
		})
	}
}
