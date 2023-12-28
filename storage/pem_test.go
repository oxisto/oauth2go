package storage

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"reflect"
	"testing"
	"testing/iotest"
)

func TestParseECPrivateKeyFromPEMWithPassword(t *testing.T) {
	type args struct {
		data     []byte
		password []byte
	}
	tests := []struct {
		name    string
		args    args
		wantKey func(*testing.T, *ecdsa.PrivateKey)
		wantErr bool
	}{
		{
			name: "Private key with password",
			args: args{
				data: []byte(
					`-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAgTz/KWaEQ7xwICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEEoMbQeGZBq+RJGRyY2N8PwEgZAY
U36vBRn5HB8zNSic75MfpGXWRVXki1qm29G/DU+E68hksvfbJlqqpL12fQ5mbOz0
v8wNrNmehUyxEOQZlRPRdmgJJHObuOZ3Z49iWRJh26uvQLRYj0EdV9KkEKmSzxaF
1ZEAdLc369AgQGD33Ce9WGTtnROB6IIfFZULO5/wj/Ps32+T+jzZLIoGk+M/sng=
-----END ENCRYPTED PRIVATE KEY-----`),
				password: []byte("test"),
			},
			wantErr: false,
			wantKey: func(tt *testing.T, got *ecdsa.PrivateKey) {
				if got == nil {
					tt.Error("ParseECPrivateKeyFromPEMWithPassword() is nil")
				}
			},
		},
		{
			name: "Private key wrong password",
			args: args{
				data: []byte(
					`-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAgTz/KWaEQ7xwICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEEoMbQeGZBq+RJGRyY2N8PwEgZAY
U36vBRn5HB8zNSic75MfpGXWRVXki1qm29G/DU+E68hksvfbJlqqpL12fQ5mbOz0
v8wNrNmehUyxEOQZlRPRdmgJJHObuOZ3Z49iWRJh26uvQLRYj0EdV9KkEKmSzxaF
1ZEAdLc369AgQGD33Ce9WGTtnROB6IIfFZULO5/wj/Ps32+T+jzZLIoGk+M/sng=
-----END ENCRYPTED PRIVATE KEY-----`),
				password: []byte("nottest"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := ParseECPrivateKeyFromPEMWithPassword(tt.args.data, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseECPrivateKeyFromPEMWithPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantKey != nil {
				tt.wantKey(t, gotKey)
			}
		})
	}
}

func TestMarshalECPrivateKeyWithPassword(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		key      *ecdsa.PrivateKey
		password []byte
	}
	tests := []struct {
		name     string
		args     args
		wantData func(*testing.T, []byte)
		wantErr  bool
	}{
		{
			name: "Marshal EC key",
			args: args{
				key:      pk,
				password: []byte("test"),
			},
			wantData: func(tt *testing.T, data []byte) {
				if len(data) == 0 {
					tt.Error("ParseECPrivateKeyFromPEMWithPassword() is empty")
				}
			},
		},
		{
			name: "Error while marshalling EC key",
			args: args{
				key:      &ecdsa.PrivateKey{},
				password: []byte("test"),
			},
			wantErr:  true,
			wantData: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotData, err := MarshalECPrivateKeyWithPassword(tt.args.key, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalECPrivateKeyWithPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantData != nil {
				tt.wantData(t, gotData)
			}
		})
	}
}

func TestDecryptPEMBlock(t *testing.T) {
	type args struct {
		block    *pem.Block
		password []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "wrong type",
			args: args{
				block: &pem.Block{
					Type: "SOMETYPE",
				},
			},
			wantErr: true,
		},
		{
			name: "not ASN1",
			args: args{
				block: &pem.Block{
					Type:  "ENCRYPTED PRIVATE KEY",
					Bytes: []byte{1, 2, 3},
				},
			},
			wantErr: true,
		},
		{
			name: "wrong encryption algorithm",
			args: args{
				block: &pem.Block{
					Type: "ENCRYPTED PRIVATE KEY",
					Bytes: func() []byte {
						b, err := asn1.Marshal(EncryptedPrivateKeyInfo{
							EncryptionAlgorithm: EncryptionAlgorithmIdentifier{
								Algorithm: asn1.ObjectIdentifier{0, 0},
								Params: PBES2Params{
									KeyDerivationFunc: KeyDerivationFunc{
										Algorithm: oidPBKDF2,
									},
									EncryptionScheme: EncryptionScheme{
										EncryptionAlgorithm: oidAESCBC,
									},
								},
							},
						})
						if err != nil {
							t.Fatal(err)
						}
						return b
					}(),
				},
			},
			wantErr: true,
		},
		{
			name: "wrong key derivation algorithm",
			args: args{
				block: &pem.Block{
					Type: "ENCRYPTED PRIVATE KEY",
					Bytes: func() []byte {
						b, err := asn1.Marshal(EncryptedPrivateKeyInfo{
							EncryptionAlgorithm: EncryptionAlgorithmIdentifier{
								Algorithm: oidPBES2,
								Params: PBES2Params{
									KeyDerivationFunc: KeyDerivationFunc{
										Algorithm: asn1.ObjectIdentifier{0, 0},
									},
									EncryptionScheme: EncryptionScheme{
										EncryptionAlgorithm: oidAESCBC,
									},
								},
							},
						})
						if err != nil {
							t.Fatal(err)
						}
						return b
					}(),
				},
			},
			wantErr: true,
		},
		{
			name: "wrong PRF",
			args: args{
				block: &pem.Block{
					Type: "ENCRYPTED PRIVATE KEY",
					Bytes: func() []byte {
						b, err := asn1.Marshal(EncryptedPrivateKeyInfo{
							EncryptionAlgorithm: EncryptionAlgorithmIdentifier{
								Algorithm: oidPBES2,
								Params: PBES2Params{
									KeyDerivationFunc: KeyDerivationFunc{
										Algorithm: oidPBKDF2,
										PBKDF2Params: PBKDF2Params{
											PRF: asn1.ObjectIdentifier{0, 0},
										},
									},
									EncryptionScheme: EncryptionScheme{
										EncryptionAlgorithm: oidAESCBC,
									},
								},
							},
						})
						if err != nil {
							t.Fatal(err)
						}
						return b
					}(),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecryptPEMBlock(tt.args.block, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptPEMBlock() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecryptPEMBlock() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncryptPEMBlock(t *testing.T) {
	// manipulate OID to provoke an error
	oidPBKDF2 = asn1.ObjectIdentifier{0}

	type args struct {
		rand     io.Reader
		data     []byte
		password []byte
	}
	tests := []struct {
		name      string
		args      args
		wantBlock *pem.Block
		wantErr   bool
	}{
		{
			name: "invalid rand",
			args: args{
				rand: iotest.ErrReader(io.EOF),
			},
			wantErr: true,
		},
		{
			name: "invalid rand",
			args: args{
				rand: bytes.NewReader(make([]byte, 8)),
			},
			wantErr: true,
		},
		{
			name: "invalid",
			args: args{
				rand: bytes.NewReader(make([]byte, 16)),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBlock, err := EncryptPEMBlock(tt.args.rand, tt.args.data, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptPEMBlock() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotBlock, tt.wantBlock) {
				t.Errorf("EncryptPEMBlock() = %v, want %v", gotBlock, tt.wantBlock)
			}
		})
	}
}
