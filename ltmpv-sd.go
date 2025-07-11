package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/grandcat/zeroconf"
)

func findService() {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatalln("Failed to initialize resolver:", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		entry := <-results
		fmt.Printf("%s:%d", entry.AddrIPv4[0], entry.Port)
	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = resolver.Browse(ctx, "_libtorrentmpv._tcp", "local.", entries)
	if err != nil {
		log.Fatalln("Failed to browse:", err)
	}

	<-ctx.Done()
}

func registerService(port int) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "ltmpv-sd"
	}
	server, err := zeroconf.Register(hostname, "_libtorrentmpv._tcp", "local.", port, nil, nil)
	if err != nil {
		log.Fatalf("Failed to register service: %v\n", err)
	}
	defer server.Shutdown()
	server.TTL(120)

	// Wait for exit signal or timeout
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	<-sig
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ltmpv-sd <find|register> [--port <port>]")
		os.Exit(1)
	}

	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	port := fs.Int("port", 0, "Port number to register service (required for register)")

	_ = fs.Parse(os.Args[2:])

	switch cmd {
	case "find":
		findService()
	case "register":
		if *port == 0 {
			fmt.Println("Error: --port is required for register")
			fs.Usage()
			os.Exit(1)
		}
		registerService(*port)
	default:
		fmt.Println("Unknown command:", cmd)
		fmt.Println("Usage: ltmpv-sd <find|register> [--port <port>]")
		os.Exit(1)
	}
}
