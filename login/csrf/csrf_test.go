package csrf

import (
	"errors"
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
			name: "successful unmask",
			args: args{
				token: mask,
			},
			want: token,
		},
		{
			name: "invalid length",
			args: args{
				token: "mytoken",
			},
			want:    "",
			wantErr: ErrInvalidLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := Unmask(tt.args.token)

			if gotErr != nil && !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("Unmask() error = %v, want %v", gotErr, tt.wantErr)
			}

			if got != tt.want {
				t.Errorf("Unmask() = %v, want %v", got, tt.want)
			}
		})
	}
}
