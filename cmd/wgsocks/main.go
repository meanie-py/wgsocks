package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/meanie-py/wgsocks/internal/server"
	"github.com/meanie-py/wgsocks/internal/wireguard"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: wgsocks <config.conf> [config2.conf ...]\n")
		os.Exit(1)
	}

	var configs []*wireguard.Config
	for _, path := range os.Args[1:] {
		cfg, err := wireguard.ParseConfigFile(path)
		if err != nil {
			log.Fatalf("Failed to parse %s: %v", path, err)
		}
		configs = append(configs, cfg)
	}

	listenAddr := envOr("LISTEN_ADDR", ":1080")
	maxTunnels := envInt("MAX_TUNNELS", 5)
	maxFailover := envInt("MAX_FAILOVER", 3)

	log.Printf("Loaded %d WireGuard configs", len(configs))

	srv := server.NewServer(listenAddr, configs, maxTunnels, maxFailover)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down...")
		_ = srv.Close()
		os.Exit(0)
	}()

	if err := srv.Run(); err != nil {
		_ = srv.Close()
		log.Fatalf("Server error: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("Invalid %s: %v", key, err)
	}
	return n
}
