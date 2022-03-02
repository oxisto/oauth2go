package main

import (
	"context"
	"flag"
	"net"
	"sync"
	"testing"
)

func Test_main(t *testing.T) {
	var (
		wg  sync.WaitGroup
		err error
	)

	tests := []struct {
		name     string
		flagPrep func(t *testing.T)
		want     func(t *testing.T)
	}{
		{
			name: "empty user password",
			flagPrep: func(t *testing.T) {
				err = flag.Set("user-password", "")
				if err != nil {
					t.Errorf("Error while setting flag: %v", err)
				}
			},
			want: func(t *testing.T) {
				if len(*userPassword) == 0 {
					t.Errorf("user password should not be empty")
				}
			},
		},
		{
			name: "empty client secret",
			flagPrep: func(t *testing.T) {
				err = flag.Set("client-secret", "")
				if err != nil {
					t.Errorf("Error while setting flag: %v", err)
				}
			},
			want: func(t *testing.T) {
				if len(*clientSecret) == 0 {
					t.Errorf("client secret should not be empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wg.Add(1)

			tt.flagPrep(t)

			// Make sure, our port is random
			err = flag.Set("port", "0")
			if err != nil {
				t.Errorf("Error while setting flag: %v", err)
			}

			ctx = func(net.Listener) context.Context {
				wg.Done()
				return context.Background()
			}

			go main()

			wg.Wait()
		})
	}
}
