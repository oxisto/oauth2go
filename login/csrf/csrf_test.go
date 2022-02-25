package csrf

import (
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
)

func TestGenerateToken(t *testing.T) {
	got := GenerateToken()
	gotLength := len(got)
	wantLength := EncodedTokenSize

	if gotLength != wantLength {
		t.Errorf("GenerateToken() length = %v, want %v", gotLength, wantLength)
	}
}

func TestMask(t *testing.T) {
	type args struct {
		sessionToken string
	}
	tests := []struct {
		name       string
		args       args
		wantLength int
	}{
		{
			name: "session token",
			args: args{
				sessionToken: GenerateToken(),
			},
			wantLength: DoubleEncodedTokenSize + EncodedTokenSize,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Mask(tt.args.sessionToken); len(got) != tt.wantLength {
				t.Errorf("Mask() = %v, want %v", len(got), tt.wantLength)
			}
		})
	}
}

func TestUnmask(t *testing.T) {
	var token = GenerateToken()
	var mask = Mask(token)

	type args struct {
		token string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr error
	}{
		{
			name: "illegal base64",
			args: args{
				token: ",aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			wantErr: base64.CorruptInputError(0),
		},
		{
			name: "successful unmask",
			args: args{
				token: mask,
			},
			want: token,
		},
		{
			name: "invalid length",
			args: args{
				token: "aaaaa",
			},
			want:    "",
			wantErr: ErrInvalidLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := Unmask(tt.args.token)

			if !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("Unmask() error = %v, want %v", gotErr, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("Unmask() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_xor(t *testing.T) {
	type args struct {
		x []byte
		y []byte
	}
	tests := []struct {
		name       string
		args       args
		wantResult []byte
	}{
		{
			name: "xor same length",
			args: args{
				x: []byte{0, 1, 2, 3, 4},
				y: []byte{1, 1, 1, 1, 1},
			},
			wantResult: []byte{1, 0, 3, 2, 5},
		},
		{
			name: "xor smaller y",
			args: args{
				x: []byte{0, 1, 2, 3, 4},
				y: []byte{1, 1, 1, 1},
			},
			wantResult: []byte{1, 0, 3, 2},
		},
		{
			name: "xor larger y",
			args: args{
				x: []byte{0, 1, 2, 3, 4},
				y: []byte{1, 1, 1, 1, 1, 1},
			},
			wantResult: []byte{1, 0, 3, 2, 5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotResult := xor(tt.args.x, tt.args.y); !reflect.DeepEqual(gotResult, tt.wantResult) {
				t.Errorf("xor() = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}
