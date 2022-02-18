package main

import (
	"context"
	"flag"
	"net"
	"sync"
	"testing"
)

func Test_main(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)

	flag.Set("port", "0")

	ctx = func(net.Listener) context.Context {
		wg.Done()
		return context.Background()
	}

	go main()

	wg.Wait()
}
