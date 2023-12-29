package pkcs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"reflect"
	"testing"
	"testing/iotest"
)

func TestParsePKCS8PrivateKeyWithPassword(t *testing.T) {
	type args struct {
		data     []byte
		password []byte
	}
	tests := []struct {
		name    string
		args    args
		wantKey func(*testing.T, crypto.PrivateKey)
		wantErr bool
	}{
		{
			name: "private key with password",
			args: args{
				data: []byte(
					`-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHqMFUGCSqGSIb3DQEFDTBIMCcGCSqGSIb3DQEFDDAaBAg/ry1F70gEOwICJxAw
CgYIKoZIhvcNAgkwHQYJYIZIAWUDBAECBBAssuVSH48KsMJ6RPl/mG9qBIGQii4G
54TH7t/WrIHgE9xB82RojLdQ8b2WAvjWFepY4RsunHNnDcljEKyFySnqe4f57cRy
3lfGKes6U5ubV5Bi/ffsb5/fApUD93GfIrHSW4yxb4oUKOa30ODwPbwx10sji8Vk
zpW8KFxMcSEgVROGQJFAKVHwbA8dOlOPmewQuh2DXiRqYucncbvxey1flMln
-----END ENCRYPTED PRIVATE KEY-----`),
				password: []byte("changeme"),
			},
			wantErr: false,
			wantKey: func(tt *testing.T, got crypto.PrivateKey) {
				if got == nil {
					tt.Error("ParseECPrivateKeyFromPEMWithPassword() is nil")
				}
			},
		},
		{
			name: "private key wrong password",
			args: args{
				data: []byte(
					`-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHqMFUGCSqGSIb3DQEFDTBIMCcGCSqGSIb3DQEFDDAaBAg/ry1F70gEOwICJxAw
CgYIKoZIhvcNAgkwHQYJYIZIAWUDBAECBBAssuVSH48KsMJ6RPl/mG9qBIGQii4G
54TH7t/WrIHgE9xB82RojLdQ8b2WAvjWFepY4RsunHNnDcljEKyFySnqe4f57cRy
3lfGKes6U5ubV5Bi/ffsb5/fApUD93GfIrHSW4yxb4oUKOa30ODwPbwx10sji8Vk
zpW8KFxMcSEgVROGQJFAKVHwbA8dOlOPmewQuh2DXiRqYucncbvxey1flMln
-----END ENCRYPTED PRIVATE KEY-----`),
				password: []byte("nottest"),
			},
			wantErr: true,
		},
		{
			name: "not a private key",
			args: args{
				data: []byte(
					`-----BEGIN ENCRYPTED PRIVATE KEY-----
THIS IS NOT A PRIVATE KEY
-----END ENCRYPTED PRIVATE KEY-----`),
				password: []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "not PEM",
			args: args{
				data: []byte(
					`NOTPEM`),
				password: []byte("test"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := ParsePKCS5PrivateKeyWithPassword(tt.args.data, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePKCS5PrivateKeyWithPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantKey != nil {
				tt.wantKey(t, gotKey)
			}
		})
	}
}

func TestMarshalPKCS5PrivateKeyWithPassword(t *testing.T) {
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
					tt.Error("MarshalPKCS5PrivateKeyWithPassword() is empty")
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
		{
			name: "Empty password",
			args: args{
				key:      pk,
				password: []byte{},
			},
			wantErr:  true,
			wantData: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotData, err := MarshalPKCS5PrivateKeyWithPassword(tt.args.key, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalPKCS5PrivateKeyWithPassword() error = %v, wantErr %v", err, tt.wantErr)
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
										EncryptionAlgorithm: oidAES128CBC,
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
										EncryptionAlgorithm: oidAES128CBC,
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
											PRF: pkix.AlgorithmIdentifier{
												Algorithm: asn1.ObjectIdentifier{0, 0},
											},
										},
									},
									EncryptionScheme: EncryptionScheme{
										EncryptionAlgorithm: oidAES128CBC,
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
				rand:     iotest.ErrReader(io.EOF),
				password: []byte{1},
			},
			wantErr: true,
		},
		{
			name: "invalid rand",
			args: args{
				rand:     bytes.NewReader(make([]byte, 8)),
				password: []byte{1},
			},
			wantErr: true,
		},
		{
			name: "invalid",
			args: args{
				rand:     bytes.NewReader(make([]byte, 16)),
				password: []byte{1},
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
