package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/google/certificate-transparency/go/gossip"
)

var dbPath = flag.String("database", "/tmp/gossip.sq3", "Path to database.")
var listenAddress = flag.String("listen", ":8080", "Listen address:port for HTTP server.")

func main() {
	flag.Parse()
	log.Print("Starting gossip server.")

	storage := gossip.Storage{}
	if err := storage.Open(*dbPath); err != nil {
		log.Fatalf("Failed to open storage: %v", err)
	}
	defer storage.Close()

	handler := gossip.NewHandler(&storage)
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/.well-known/ct/v1/sct-feedback", handler.HandleSCTFeedback)
	serveMux.HandleFunc("/.well-known/ct/v1/sth-pollination", handler.HandleSTHPollination)
	server := &http.Server{
		Addr:    *listenAddress,
		Handler: serveMux,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Error serving: %v", err)
	}
}
