package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor/internal/api"
)

func main() {
	config, err := api.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	server, err := api.NewServer(config)
	if err != nil {
		log.Fatalf("build server: %v", err)
	}
	defer func() {
		if closeErr := server.Close(); closeErr != nil {
			log.Printf("close server resources: %v", closeErr)
		}
	}()

	httpServer := &http.Server{
		Addr:              config.ServerAddr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("Ignyte Anchor API listening on %s", config.ServerAddr)
		if serveErr := httpServer.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Fatalf("listen and serve: %v", serveErr)
		}
	}()

	signalContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-signalContext.Done()

	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if shutdownErr := httpServer.Shutdown(shutdownContext); shutdownErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "shutdown failed: %v\n", shutdownErr)
		os.Exit(1)
	}
}
