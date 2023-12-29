package storage

import (
	"crypto/ecdsa"
	"io"
	"os"
	"reflect"
	"testing"
)

func Test_keyLoader_recoverFromLoadKeyError(t *testing.T) {
	var tmpFile, _ = os.CreateTemp("", "private.key")
	// Close it immediately , since we want to write to it
	tmpFile.Close()

	defer func() {
		os.Remove(tmpFile.Name())
	}()

	type fields struct {
		path         string
		password     string
		saveOnCreate bool
	}
	type args struct {
		err         error
		defaultPath bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantKey func(*testing.T, *ecdsa.PrivateKey)
	}{
		{
			name: "Could not load key from custom path",
			fields: fields{
				saveOnCreate: false,
				path:         "doesnotexist",
				password:     "test",
			},
			args: args{
				err:         os.ErrNotExist,
				defaultPath: false,
			},
			wantKey: func(tt *testing.T, got *ecdsa.PrivateKey) {
				if got == nil {
					tt.Error("keyLoader.recoverFromLoadKeyError() is nil")
				}
			},
		},
		{
			name: "Could not load key from default path and save it",
			fields: fields{
				saveOnCreate: true,
				path:         tmpFile.Name(),
				password:     "test",
			},
			args: args{
				err:         os.ErrNotExist,
				defaultPath: true,
			},
			wantKey: func(tt *testing.T, got *ecdsa.PrivateKey) {
				if got == nil {
					tt.Error("keyLoader.recoverFromLoadKeyError() is nil")
				}

				f, _ := os.OpenFile(tmpFile.Name(), os.O_RDONLY, 0600)
				// Our tmp file should also contain something now
				data, _ := io.ReadAll(f)

				if len(data) == 0 {
					tt.Error("keyLoader.recoverFromLoadKeyError() did not write key on file")
				}
			},
		},
		{
			name: "error while recovering",
			fields: fields{
				saveOnCreate: true,
				path:         "/youwillnotcreatethis/file",
				password:     "test",
			},
			args: args{
				err: os.ErrNotExist,
			},
			wantKey: func(tt *testing.T, got *ecdsa.PrivateKey) {
				if got == nil {
					tt.Error("keyLoader.recoverFromLoadKeyError() is nil")
				}
			},
		},
		{
			name: "error while recovering",
			fields: fields{
				saveOnCreate: true,
				path:         "/youwillnotcreatethis",
				password:     "test",
			},
			args: args{
				err: os.ErrNotExist,
			},
			wantKey: func(tt *testing.T, got *ecdsa.PrivateKey) {
				if got == nil {
					tt.Error("keyLoader.recoverFromLoadKeyError() is nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &keyLoader{
				path:         tt.fields.path,
				password:     tt.fields.password,
				saveOnCreate: tt.fields.saveOnCreate,
			}
			gotKey := l.recoverFromLoadKeyError(tt.args.err)

			if tt.wantKey != nil {
				tt.wantKey(t, gotKey)
			}
		})
	}
}

func Test_keyLoader_LoadKey(t *testing.T) {
	type fields struct {
		path         string
		password     string
		saveOnCreate bool
		homeDirFunc  func() (string, error)
	}
	tests := []struct {
		name    string
		fields  fields
		wantKey func(*testing.T, *ecdsa.PrivateKey)
	}{
		{
			name: "happy path",
			fields: fields{
				path:        "testdata/ecdsa.pem",
				password:    "changeme",
				homeDirFunc: os.UserHomeDir,
			},
			wantKey: func(tt *testing.T, pk *ecdsa.PrivateKey) {
				if pk == nil {
					tt.Fatal("keyLoader.LoadKey() is nil")
				}
				if pk.X == nil {
					tt.Fatal("keyLoader.LoadKey(): X is nil")
				}
				if pk.X.String() != "32873710959934374119280106587483362391001994064365430366486752885578316099732" {
					tt.Fatal("keyLoader.LoadKey(): X is wrong")
				}
			},
		},
		{
			name: "recovered path",
			fields: fields{
				homeDirFunc: os.UserHomeDir,
			},
			wantKey: func(tt *testing.T, pk *ecdsa.PrivateKey) {
				if pk == nil {
					tt.Error("keyLoader.LoadKey() is nil")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &keyLoader{
				path:         tt.fields.path,
				password:     tt.fields.password,
				saveOnCreate: tt.fields.saveOnCreate,
			}
			gotKey := l.LoadKey()
			tt.wantKey(t, gotKey)
		})
	}
}

func TestLoadSigningKeys(t *testing.T) {
	type args struct {
		path         string
		password     string
		saveOnCreate bool
	}
	tests := []struct {
		name string
		args args
		want func(*testing.T, map[int]*ecdsa.PrivateKey)
	}{
		{
			name: "happy path",
			args: args{
				path:     "testdata/ecdsa.pem",
				password: "changeme",
			},
			want: func(tt *testing.T, m map[int]*ecdsa.PrivateKey) {
				if m[0].X == nil {
					tt.Fatal("keyLoader.LoadKey(): X is nil")
				}
				if m[0].X.String() != "32873710959934374119280106587483362391001994064365430366486752885578316099732" {
					tt.Fatal("keyLoader.LoadKey(): X is wrong")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LoadSigningKeys(tt.args.path, tt.args.password, tt.args.saveOnCreate)

			tt.want(t, got)
		})
	}
}

func Test_keyLoader_ensureFolderExistence(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "mkdir fail",
			args: args{
				path: "/thisshouldnotwork/file",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ensureFolderExistence(tt.args.path); (err != nil) != tt.wantErr {
				t.Errorf("keyLoader.ensureFolderExistence() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_loadKeyFromFile(t *testing.T) {
	type args struct {
		path     string
		password []byte
	}
	tests := []struct {
		name    string
		args    args
		wantKey *ecdsa.PrivateKey
		wantErr bool
	}{
		{
			name: "not a PEM file",
			args: args{
				path: "testdata/test.notkey",
			},
			wantErr: true,
		},
		{
			name: "not an ECDSA key",
			args: args{
				path:     "testdata/rsa.pem",
				password: []byte("changeme"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := loadKeyFromFile(tt.args.path, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadKeyFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotKey, tt.wantKey) {
				t.Errorf("loadKeyFromFile() = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}

func Test_saveKeyToFile(t *testing.T) {
	var tmpFile, _ = os.CreateTemp("", "private.key")
	// Close it immediately , since we want to write to it
	tmpFile.Close()

	defer func() {
		os.Remove(tmpFile.Name())
	}()

	type args struct {
		key      *ecdsa.PrivateKey
		path     string
		password string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "not a valid key",
			args: args{
				path: tmpFile.Name(),
				key:  &ecdsa.PrivateKey{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := saveKeyToFile(tt.args.key, tt.args.path, tt.args.password); (err != nil) != tt.wantErr {
				t.Errorf("saveKeyToFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
