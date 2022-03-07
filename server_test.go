package oauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/oxisto/oauth2go/internal/mock"
)

var badSigningKey = ecdsa.PrivateKey{
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
}

var testSigningKey *ecdsa.PrivateKey
var testVerifier = "012345678901234567890123456789012345678901234567890123456789"
var testChallenge = GenerateCodeChallenge(testVerifier)

// testRefreshTokenClientKID1MockSingingKey is a valid refresh token signed by mockSigningKey with the KID 1
var testRefreshTokenClientKID1MockSingingKey string

func init() {
	var (
		err error
		t   *jwt.Token
	)

	testSigningKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	t = jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Subject: "client",
	})
	t.Header["kid"] = fmt.Sprintf("%d", 1)

	testRefreshTokenClientKID1MockSingingKey, err = t.SignedString(testSigningKey)
	if err != nil {
		panic(err)
	}
}

func TestAuthorizationServer_handleToken(t *testing.T) {
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
				clients:     tt.fields.clients,
				signingKeys: tt.fields.signingKeys,
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
		clients     []*Client
		signingKeys map[int]*ecdsa.PrivateKey
	}
	type args struct {
		r           *http.Request
		allowPublic bool
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
						ClientID:     "client",
						ClientSecret: "secret",
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
				ClientID:     "client",
				ClientSecret: "secret",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &AuthorizationServer{
				clients:     tt.fields.clients,
				signingKeys: tt.fields.signingKeys,
			}
			got, err := srv.retrieveClient(tt.args.r, tt.args.allowPublic)
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
				r: httptest.NewRequest("GET", "/.well-known/jwks.json", nil),
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
				r: httptest.NewRequest("POST", "/.well-known/jwks.json", nil),
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
						ClientID:     "client",
						ClientSecret: "secret",
					},
				},
				signingKeys: map[int]*ecdsa.PrivateKey{
					0: &badSigningKey,
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
				clients:     tt.fields.clients,
				signingKeys: tt.fields.signingKeys,
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

func TestAuthorizationServer_doAuthorizationCodeFlow(t *testing.T) {
	type fields struct {
		clients     []*Client
		signingKeys map[int]*ecdsa.PrivateKey
		codes       map[string]*codeInfo
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
			name: "correct authorization of confidential client but invalid code",
			fields: fields{
				clients: []*Client{
					{
						ClientID:     "client",
						ClientSecret: "secret",
					},
				},
				codes: map[string]*codeInfo{
					"myCode": {
						expiry:    time.Now().Add(10 * time.Minute),
						challenge: testChallenge,
					},
				},
			},
			args: args{
				r: &http.Request{
					Method: "POST",
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"Basic Y2xpZW50OnNlY3JldA=="}, // client:secret
						http.CanonicalHeaderKey("Content-Type"):  []string{"application/x-www-form-urlencoded"},
					},
					Body: io.NopCloser(strings.NewReader("code=myOtherCode")),
				},
			},
			wantCode: http.StatusBadRequest,
			wantBody: `{"error": "invalid_grant"}`,
		},
		{
			name: "public client without challenge",
			fields: fields{
				clients: []*Client{
					{
						ClientID:     "client",
						ClientSecret: "",
					},
				},
				codes: map[string]*codeInfo{
					"myCode": {
						expiry:    time.Now().Add(10 * time.Minute),
						challenge: testChallenge,
					},
				},
			},
			args: args{
				r: &http.Request{
					Method: "POST",
					Header: http.Header{
						http.CanonicalHeaderKey("Content-Type"): []string{"application/x-www-form-urlencoded"},
					},
					Body: io.NopCloser(strings.NewReader("client_id=client&code=myCode")),
				},
			},
			wantCode: http.StatusBadRequest,
			wantBody: `{"error": "invalid_request"}`,
		},
		{
			name: "problem with JWT",
			fields: fields{
				clients: []*Client{
					{
						ClientID:     "client",
						ClientSecret: "secret",
					},
				},
				codes: map[string]*codeInfo{
					"myCode": {
						expiry:    time.Now().Add(10 * time.Minute),
						challenge: testChallenge,
					},
				},
				signingKeys: map[int]*ecdsa.PrivateKey{
					0: &badSigningKey,
				},
			},
			args: args{
				r: &http.Request{
					Method: "POST",
					Header: http.Header{
						http.CanonicalHeaderKey("Authorization"): []string{"Basic Y2xpZW50OnNlY3JldA=="}, // client:secret
						http.CanonicalHeaderKey("Content-Type"):  []string{"application/x-www-form-urlencoded"},
					},
					Body: io.NopCloser(strings.NewReader(fmt.Sprintf("code=myCode&code_verifier=%s", testVerifier))),
				},
			},
			wantCode: http.StatusInternalServerError,
			wantBody: `error while creating JWT`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &AuthorizationServer{
				clients:     tt.fields.clients,
				signingKeys: tt.fields.signingKeys,
				codes:       tt.fields.codes,
			}
			rr := httptest.NewRecorder()
			srv.doAuthorizationCodeFlow(rr, tt.args.r)

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

func TestAuthorizationServer_doRefreshTokenFlow(t *testing.T) {
	type fields struct {
		Server      http.Server
		clients     []*Client
		signingKeys map[int]*ecdsa.PrivateKey
		codes       map[string]*codeInfo
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
			name: "missing refresh token",
			args: args{
				r: &http.Request{
					Method: "POST",
					Header: http.Header{
						http.CanonicalHeaderKey("Content-Type"): []string{"application/x-www-form-urlencoded"},
					},
					Body: nil,
				},
			},
			wantCode: http.StatusBadRequest,
			wantBody: `{"error": "invalid_request"}`,
		},
		{
			name: "invalid refresh token",
			args: args{
				r: &http.Request{
					Method: "POST",
					Header: http.Header{
						http.CanonicalHeaderKey("Content-Type"): []string{"application/x-www-form-urlencoded"},
					},
					Body: io.NopCloser(strings.NewReader(fmt.Sprintf("refresh_token=%s", "notatoken"))),
				},
			},
			wantCode: http.StatusBadRequest,
			wantBody: `{"error": "invalid_grant"}`,
		},
		{
			name: "wrong client",
			fields: fields{
				clients: []*Client{
					{
						ClientID:     "notclient",
						ClientSecret: "secret",
					},
				},
				signingKeys: map[int]*ecdsa.PrivateKey{
					0: &badSigningKey,
					1: testSigningKey,
				},
			},
			args: args{
				r: &http.Request{
					Method: "POST",
					Header: http.Header{
						http.CanonicalHeaderKey("Content-Type"): []string{"application/x-www-form-urlencoded"},
					},
					Body: io.NopCloser(strings.NewReader(fmt.Sprintf("refresh_token=%s", testRefreshTokenClientKID1MockSingingKey))),
				},
			},
			wantCode: http.StatusUnauthorized,
			wantBody: `{"error": "invalid_client"}`,
		},
		{
			name: "missing authentication for confidential client",
			fields: fields{
				clients: []*Client{
					{
						ClientID:     "client",
						ClientSecret: "secret",
					},
				},
				signingKeys: map[int]*ecdsa.PrivateKey{
					0: &badSigningKey,
					1: testSigningKey,
				},
			},
			args: args{
				r: &http.Request{
					Method: "POST",
					Header: http.Header{
						http.CanonicalHeaderKey("Content-Type"): []string{"application/x-www-form-urlencoded"},
					},
					Body: io.NopCloser(strings.NewReader(fmt.Sprintf("refresh_token=%s", testRefreshTokenClientKID1MockSingingKey))),
				},
			},
			wantCode: http.StatusUnauthorized,
			wantBody: `{"error": "invalid_client"}`,
		},
		{
			name: "problem with JWT creation",
			fields: fields{
				clients: []*Client{
					{
						ClientID:     "client",
						ClientSecret: "",
					},
				},
				signingKeys: map[int]*ecdsa.PrivateKey{
					0: &badSigningKey,
					1: testSigningKey,
				},
			},
			args: args{
				r: &http.Request{
					Method: "POST",
					Header: http.Header{
						http.CanonicalHeaderKey("Content-Type"): []string{"application/x-www-form-urlencoded"},
					},
					Body: io.NopCloser(strings.NewReader(fmt.Sprintf("refresh_token=%s", testRefreshTokenClientKID1MockSingingKey))),
				},
			},
			wantCode: http.StatusInternalServerError,
			wantBody: `error while creating JWT`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &AuthorizationServer{
				Server:      tt.fields.Server,
				clients:     tt.fields.clients,
				signingKeys: tt.fields.signingKeys,
				codes:       tt.fields.codes,
			}

			rr := httptest.NewRecorder()
			srv.doRefreshTokenFlow(rr, tt.args.r)

			gotCode := rr.Code
			if gotCode != tt.wantCode {
				t.Errorf("AuthorizationServer.doRefreshTokenFlow() code = %v, wantCode %v", gotCode, tt.wantCode)
			}

			gotBody := strings.Trim(rr.Body.String(), "\n")
			if gotBody != tt.wantBody {
				t.Errorf("AuthorizationServer.doRefreshTokenFlow() body = %v, wantBody %v", gotBody, tt.wantBody)
			}
		})
	}
}

func TestAuthorizationServer_ValidateCode(t *testing.T) {
	type fields struct {
		clients     []*Client
		signingKeys map[int]*ecdsa.PrivateKey
		codes       map[string]*codeInfo
	}
	type args struct {
		verifier string
		code     string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "code is not existing",
			fields: fields{
				codes: map[string]*codeInfo{
					"myCode": {
						expiry:    time.Now().Add(10 * time.Minute),
						challenge: testChallenge,
					},
				},
			},
			args: args{
				code: "myOtherCode",
			},
			want: false,
		},
		{
			name: "code is expired",
			fields: fields{
				codes: map[string]*codeInfo{
					"myCode": {
						expiry:    time.Now().Add(-10 * time.Minute),
						challenge: testChallenge,
					},
				},
			},
			args: args{
				code: "myCode",
			},
			want: false,
		},
		{
			name: "code is not expired",
			fields: fields{
				codes: map[string]*codeInfo{
					"myCode": {
						expiry:    time.Now().Add(10 * time.Minute),
						challenge: testChallenge,
					},
				},
			},
			args: args{
				code: "myCode",
			},
			want: false,
		},
		{
			name: "code is ok",
			fields: fields{
				codes: map[string]*codeInfo{
					"myCode": {
						expiry:    time.Now().Add(10 * time.Minute),
						challenge: testChallenge,
					},
				},
			},
			args: args{
				verifier: testVerifier,
				code:     "myCode",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &AuthorizationServer{
				clients:     tt.fields.clients,
				signingKeys: tt.fields.signingKeys,
				codes:       tt.fields.codes,
			}
			if got := srv.ValidateCode(tt.args.verifier, tt.args.code); got != tt.want {
				t.Errorf("AuthorizationServer.ValidateCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthorizationServer_GenerateToken(t *testing.T) {
	type fields struct {
		clients     []*Client
		signingKeys map[int]*ecdsa.PrivateKey
		codes       map[string]*codeInfo
	}
	type args struct {
		clientID     string
		signingKeyID int
		refreshKeyID int
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantToken *Token
		wantErr   bool
	}{
		{
			name: "bad signing key",
			fields: fields{
				signingKeys: map[int]*ecdsa.PrivateKey{
					0: &badSigningKey,
				},
			},
			args: args{
				clientID:     "client",
				signingKeyID: 0,
			},
			wantToken: nil,
			wantErr:   true,
		},
		{
			name: "invalid key ID",
			fields: fields{
				signingKeys: map[int]*ecdsa.PrivateKey{
					0: testSigningKey,
				},
			},
			args: args{
				clientID:     "client",
				signingKeyID: 1,
			},
			wantToken: nil,
			wantErr:   true,
		},
		{
			name: "bad refresh key",
			fields: fields{
				signingKeys: map[int]*ecdsa.PrivateKey{
					0: testSigningKey,
					1: &badSigningKey,
				},
			},
			args: args{
				clientID:     "client",
				signingKeyID: 0,
				refreshKeyID: 1,
			},
			wantToken: nil,
			wantErr:   true,
		},
		{
			name: "invalid refresh key ID",
			fields: fields{
				signingKeys: map[int]*ecdsa.PrivateKey{
					0: testSigningKey,
				},
			},
			args: args{
				clientID:     "client",
				signingKeyID: 0,
				refreshKeyID: 1,
			},
			wantToken: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &AuthorizationServer{
				clients:     tt.fields.clients,
				signingKeys: tt.fields.signingKeys,
				codes:       tt.fields.codes,
			}

			gotToken, err := srv.GenerateToken(tt.args.clientID, tt.args.signingKeyID, tt.args.refreshKeyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthorizationServer.GenerateToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(gotToken, tt.wantToken) {
				t.Errorf("AuthorizationServer.GenerateToken() = %v, want %v", gotToken, tt.wantToken)
			}
		})
	}
}

func TestNewServer(t *testing.T) {
	type args struct {
		addr string
		opts []AuthorizationServerOption
	}
	tests := []struct {
		name string
		args args
		want *AuthorizationServer
	}{
		{
			name: "with signing keys func",
			args: args{
				opts: []AuthorizationServerOption{
					WithSigningKeysFunc(func() (keys map[int]*ecdsa.PrivateKey) {
						return map[int]*ecdsa.PrivateKey{
							0: testSigningKey,
						}
					})},
			},
			want: &AuthorizationServer{
				clients: []*Client{},
				codes:   map[string]*codeInfo{},
				signingKeys: map[int]*ecdsa.PrivateKey{
					0: testSigningKey,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewServer(tt.args.addr, tt.args.opts...)

			// Ignore Server.Handler in comparison because we create a new ServeMux
			got.Handler = nil
			tt.want.Handler = nil

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewServer() = %v, want %v", got, tt.want)
			}
		})
	}
}
