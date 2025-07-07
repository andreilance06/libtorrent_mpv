package main

import (
	"fmt"
	"io"
	"log"

	"github.com/hashicorp/mdns"
)

func main() {
	entriesCh := make(chan *mdns.ServiceEntry, 4)
	go func() {
		entry := <-entriesCh
		fmt.Printf("%s:%d", entry.AddrV4, entry.Port)
	}()

	logger := log.Default()
	logger.SetOutput(io.Discard)

	params := mdns.DefaultParams("_libtorrentmpv._tcp")
	params.Logger = logger
	params.Entries = entriesCh

	mdns.Query(params)

	close(entriesCh)
}
