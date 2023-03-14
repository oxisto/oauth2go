package oauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestAuthorizationServer_handleJWKS(t *testing.T) {
	type fields struct {
		clients     []*Client
		signingKeys map[int]*ecdsa.PrivateKey
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
				signingKeys: map[int]*ecdsa.PrivateKey{
					0: {
						PublicKey: ecdsa.PublicKey{
							Curve: elliptic.P256(),
							X:     big.NewInt(1),
							Y:     big.NewInt(2),
						},
					},
				},
			},
			args: args{
				r: httptest.NewRequest("GET", "/certs", nil),
			},
			want: &JSONWebKeySet{
				Keys: []JSONWebKey{{
					Kid: "0",
					Kty: "EC",
					Crv: "P-256",
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
				r: httptest.NewRequest("POST", "/certs", nil),
			},
			want:     nil,
			wantCode: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &AuthorizationServer{
				clients:     tt.fields.clients,
				signingKeys: tt.fields.signingKeys,
			}

			rr := httptest.NewRecorder()
			srv.handleJWKS(rr, tt.args.r)

			gotCode := rr.Code
			if gotCode != tt.wantCode {
				t.Errorf("AuthorizationServer.handleJWKS() code = %v, wantCode %v", gotCode, tt.wantCode)
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
