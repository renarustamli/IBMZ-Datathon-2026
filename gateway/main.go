package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
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

func curveName(id tls.CurveID) string {
	switch id {
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	}
	return "other-" + strconv.Itoa(int(id))
}

func handle(raw net.Conn, base *tls.Config, backendAddr string) {
	defer raw.Close()

	offered := []string{}
	clientID := "unknown"
	cfg := base.Clone()
	cfg.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		for _, c := range h.SupportedCurves {
			offered = append(offered, curveName(c))
		}
		if h.ServerName != "" {
			clientID = h.ServerName // client id is sent as the TLS server name (SNI)
		}
		return nil, nil
	}

	conn := tls.Server(raw, cfg)
	err := conn.Handshake()

	note := Note{
		Time:        time.Now().UTC().Format(time.RFC3339),
		Client:      raw.RemoteAddr().String(),
		ClientID:    clientID,
		KeysOffered: offered,
	}

	if err != nil {
		note.TLSVersion = "none"
		note.Cipher = "none"
		note.KeyChosen = "rejected"
		note.Strength = "weak"
		writeNote(note)
		log.Printf("handshake rejected from %s (%s): %v", raw.RemoteAddr(), clientID, err)
		return
	}
	defer conn.Close()

	st := conn.ConnectionState()
	note.TLSVersion = tls.VersionName(st.Version)
	note.Cipher = tls.CipherSuiteName(st.CipherSuite)
	note.KeyChosen = curveName(st.CurveID)
	if st.CurveID == tls.X25519MLKEM768 {
		note.Strength = "strong"
	} else {
		note.Strength = "weak"
	}
	writeNote(note)

	backend, err := net.Dial("tcp", backendAddr)
	if err != nil {
		log.Printf("backend dial failed: %v", err)
		return
	}
	defer backend.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(backend, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, backend); done <- struct{}{} }()
	<-done
}

func main() {
	listen := flag.String("listen", ":8443", "address the gateway listens on")
	backend := flag.String("backend", "127.0.0.1:9000", "legacy service address")
	notes := flag.String("notes", "logs/connections.jsonl", "connection-note file")
	mode := flag.String("mode", "strict", "strict = hybrid post-quantum only; legacy = also accept classical X25519")
	certFile := flag.String("cert", "cert.pem", "TLS certificate")
	keyFile := flag.String("key", "key.pem", "TLS private key")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}
	base := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if *mode == "strict" {
		base.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	} else {
		base.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519}
	}

	os.MkdirAll(filepath.Dir(*notes), 0o755)
	logFile, err = os.OpenFile(*notes, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("gateway (%s mode) on %s -> %s, notes in %s", *mode, *listen, *backend, *notes)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go handle(c, base, *backend)
	}
}
