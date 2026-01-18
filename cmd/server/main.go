// Package main is the entry point for the FileEZ server.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/awnumar/memguard"

	"github.com/fileez/fileez/internal/api"
	"github.com/fileez/fileez/internal/config"
	"github.com/fileez/fileez/internal/secure"
	"github.com/fileez/fileez/internal/store"
)

func main() {
	// Initialize memguard (must be called before any other memguard operations)
	memguard.CatchInterrupt()

	// Ensure secure cleanup on exit
	defer memguard.Purge()

	// Load configuration
	cfg := config.LoadFromEnv()

	log.Printf("FileEZ Server starting...")
	log.Printf("  Port: %d", cfg.Port)
	log.Printf("  Max file size: %d MB", cfg.MaxFileSize/(1024*1024))
	log.Printf("  Max memory: %d MB", cfg.MaxMemory/(1024*1024))
	log.Printf("  File expiry: %s", cfg.FileExpiry)
	log.Printf("  Clipboard expiry: %s", cfg.ClipboardExpiry)

	// Initialize decoy pool (creates noise in memory to confuse forensics)
	// 100 decoys ranging from 1KB to 512KB (~25MB average total)
	secure.InitDecoyPool(100, 1024, 512*1024)
	defer func() {
		if dp := secure.GlobalDecoyPool(); dp != nil {
			dp.Destroy()
		}
	}()
	log.Printf("  Decoy pool initialized (100 buffers)")

	// Start tripwire monitoring (detects debugger attachment on Linux)
	tripwire := secure.GlobalTripwire()
	defer tripwire.Stop()
	log.Printf("  Tripwire monitoring started")

	// Initialize memory tracker
	memory, err := secure.NewMemoryTracker(cfg.MaxMemory)
	if err != nil {
		log.Fatalf("Failed to create memory tracker: %v", err)
	}

	// Initialize session manager
	session := store.NewSessionManager()

	// Initialize stores
	files := store.NewFileStore(session, memory, cfg.MaxFileSize, cfg.FileExpiry)
	clipboard := store.NewClipboardStore(session, memory, cfg.ClipboardExpiry)

	// Register global intrusion callback - shred all data if debugger detected
	tripwire.RegisterCallback(func() {
		log.Println("[SECURITY] Intrusion detected - shredding all data")
		files.ShredAll()
		clipboard.ShredAll()
		session.Destroy()
		os.Exit(1)
	})

	// Create API server
	server := &api.Server{
		Config:    cfg,
		Session:   session,
		Files:     files,
		Clipboard: clipboard,
		Memory:    memory,
	}

	// Create router
	router := api.NewRouter(server)

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         cfg.Addr(),
		Handler:      router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  2 * time.Minute,
	}

	// Channel for shutdown signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		log.Printf("Server listening on %s", cfg.Addr())
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	sig := <-shutdown
	log.Printf("Received signal %v, initiating graceful shutdown...", sig)

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	// Shutdown HTTP server (stop accepting new requests)
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	// Secure cleanup
	log.Printf("Securely shredding all data...")

	// Shred all files
	fileCount := files.ShredAll()
	log.Printf("  Shredded %d files", fileCount)

	// Shred clipboard
	clipboard.ShredAll()
	log.Printf("  Shredded clipboard data")

	// Destroy session
	session.Destroy()
	log.Printf("  Destroyed session")

	// Final memguard cleanup
	memguard.Purge()

	log.Printf("Shutdown complete")
}
