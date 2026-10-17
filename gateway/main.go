package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// Connection note: one JSON object per line. Field names are agreed with D; do not change.
type Note struct {
	Time        string   `json:"time"`
	Client      string   `json:"client"`
	ClientID    string   `json:"client_id"`
	TLSVersion  string   `json:"tls_version"`
	Cipher      string   `json:"cipher"`
	KeysOffered []string `json:"keys_offered"`
	KeyChosen   string   `json:"key_chosen"`
	Strength    string   `json:"strength"` // "strong" or "weak"
}

var (
	logMu   sync.Mutex
	logFile *os.File
)

func writeNote(n Note) {
	logMu.Lock()
	defer logMu.Unlock()
	b, _ := json.Marshal(n)
	logFile.Write(append(b, '\n'))
}

func handle(client net.Conn, backendAddr string) {
	defer client.Close()
	backend, err := net.Dial("tcp", backendAddr)
	if err != nil {
		log.Printf("backend dial failed: %v", err)
		return
	}
	defer backend.Close()

	// Placeholder security fields until hybrid TLS is added.
	writeNote(Note{
		Time:        time.Now().UTC().Format(time.RFC3339),
		Client:      client.RemoteAddr().String(),
		ClientID:    "unknown",
		TLSVersion:  "none",
		Cipher:      "none",
		KeysOffered: []string{},
		KeyChosen:   "none",
		Strength:    "weak",
	})

	done := make(chan struct{}, 2)
	go func() { io.Copy(backend, client); done <- struct{}{} }()
	go func() { io.Copy(client, backend); done <- struct{}{} }()
	<-done
}

func main() {
	listen := flag.String("listen", ":8443", "address the gateway listens on")
	backend := flag.String("backend", "127.0.0.1:9000", "legacy service address")
	notes := flag.String("notes", "connections.log", "connection-note file")
	flag.Parse()

	var err error
	logFile, err = os.OpenFile(*notes, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("gateway on %s -> %s, notes in %s", *listen, *backend, *notes)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go handle(c, *backend)
	}
}
