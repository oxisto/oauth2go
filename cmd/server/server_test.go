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
	wg.Add(1)

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
}
